"""Deterministic policy engine. No AI is involved in these decisions.

Every drafted payment or conversion is checked here, and checked again at
execution time. The outcome is one of:
  allow   - can run after the user taps Confirm
  step_up - needs Confirm plus the user's PIN
  deny    - cannot run; the reasons say why
"""

from __future__ import annotations

import sqlite3
import statistics
from dataclasses import asdict, dataclass
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import yaml

from .compliance import Documents
from .fx import RateFeed
from .ledger import Ledger
from .money import ZERO, D, fmt, q
from .payees import PayeeError, Payees, name_similarity
from .users import Users
from .util import Clock, loads, parse_dt

ALLOW, STEP_UP, DENY, PASS = "allow", "step_up", "deny", "pass"
DATA_DIR = Path(__file__).parent / "data"


@dataclass
class RuleResult:
    rule: str
    outcome: str  # pass | step_up | deny
    message: str


@dataclass
class Decision:
    outcome: str
    results: list[RuleResult]

    @property
    def reasons(self) -> list[RuleResult]:
        return [r for r in self.results if r.outcome != PASS]

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "reasons": [asdict(r) for r in self.reasons],
            "passed": [asdict(r) for r in self.results if r.outcome == PASS],
        }


def load_config(path: str | Path | None = None) -> dict:
    return yaml.safe_load(Path(path or DATA_DIR / "policy.yaml").read_text(encoding="utf-8"))


def beneficiary_student(user_id: str, payee: dict | None) -> str:
    """Whose student file covers this payment: the linked student, else the sender."""
    if payee and payee.get("linked_user_id"):
        return payee["linked_user_id"]
    return user_id


class PolicyEngine:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, users: Users, ledger: Ledger, payees: Payees,
                 documents: Documents, feed: RateFeed, config: dict, sanctions: list[str]):
        self.conn = conn
        self.clock = clock
        self.users = users
        self.ledger = ledger
        self.payees = payees
        self.documents = documents
        self.feed = feed
        self.config = config
        self.sanctions = sanctions

    # helpers
    def _executed_payments(self, user_id: str | None = None) -> list[dict]:
        sql = "SELECT payload, resolved_at FROM actions WHERE kind = 'payment' AND status = 'executed'"
        args: tuple = ()
        if user_id:
            sql += " AND user_id = ?"
            args = (user_id,)
        out = []
        for r in self.conn.execute(sql, args):
            p = loads(r["payload"])
            p["_executed_at"] = parse_dt(r["resolved_at"])
            out.append(p)
        return out

    def evaluate(self, action: dict) -> Decision:
        payee = None
        if action["kind"] == "payment":
            try:
                payee = self.payees.get(action["user_id"], action["payee_id"], full=True)
            except PayeeError:
                payee = None
        ctx = {"payee": payee, "history": self._executed_payments(action["user_id"])}
        rules = [
            self._kyc, self._quote_fresh, self._balance, self._payee_verified, self._cooling_off,
            self._first_payment, self._purpose, self._corridor_documents, self._limits, self._velocity,
            self._anomaly, self._sanctions, self._untrusted_origin,
        ]
        results = [r for rule in rules if (r := rule(action, ctx)) is not None]
        if any(r.outcome == DENY for r in results):
            outcome = DENY
        elif any(r.outcome == STEP_UP for r in results):
            outcome = STEP_UP
        else:
            outcome = ALLOW
        return Decision(outcome, results)

    # rules
    def _kyc(self, a, ctx):
        user = self.users.get(a["user_id"])
        if user["kyc_status"] == "verified":
            return RuleResult("kyc", PASS, "Identity verified (KYC)")
        return RuleResult("kyc", DENY, "Identity isn't verified yet, so money can't leave the wallet.")

    def _quote_fresh(self, a, ctx):
        expires = parse_dt(a["quote_expires_at"])
        if self.clock.now() <= expires:
            return RuleResult("quote_fresh", PASS, f"Quote valid until {expires.strftime('%H:%M')} UTC")
        return RuleResult("quote_fresh", DENY, "The quote has expired. Get a fresh quote.")

    def _balance(self, a, ctx):
        bal = self.ledger.balance(self.ledger.wallet(a["user_id"], a["from_currency"]))
        need = D(a["total_debit"])
        if bal >= need:
            return RuleResult("balance", PASS, f"Balance covers {fmt(need, a['from_currency'])}")
        return RuleResult("balance", DENY, f"Not enough {a['from_currency']}: need {fmt(need, a['from_currency'])}, "
                                           f"have {fmt(bal, a['from_currency'])}.")

    def _payee_verified(self, a, ctx):
        if a["kind"] != "payment":
            return None
        payee = ctx["payee"]
        if payee is None:
            return RuleResult("payee_verified", DENY, "Unknown payee.")
        if payee["verified"]:
            return RuleResult("payee_verified", PASS, f"Payee verified ({payee['display_name']})")
        flags = payee.get("flags") or []
        if "account_does_not_match_registry" in flags:
            return RuleResult("payee_verified", DENY,
                              "This account does NOT match the institution's verified account. Possible fraud.")
        return RuleResult("payee_verified", DENY, "Payee isn't verified. Verify it in the app first.")

    def _cooling_off(self, a, ctx):
        payee = ctx["payee"]
        if a["kind"] != "payment" or not payee or not payee["verified"] or payee["payee_type"] == "institution":
            return None
        hours = self.config["new_payee"]["cooling_off_hours"]
        opens = parse_dt(payee["verified_at"]) + timedelta(hours=hours)
        if self.clock.now() < opens:
            return RuleResult("cooling_off", DENY,
                              f"New payee: payments open {opens.strftime('%d %b %H:%M')} UTC ({hours}h cooling-off).")
        return RuleResult("cooling_off", PASS, "Payee past cooling-off period")

    def _first_payment(self, a, ctx):
        if a["kind"] != "payment":
            return None
        if any(p.get("payee_id") == a["payee_id"] for p in ctx["history"]):
            return RuleResult("first_payment", PASS, "Paid this payee before")
        return RuleResult("first_payment", STEP_UP, "First payment to this payee: confirm with your PIN.")

    def _purpose(self, a, ctx):
        if a["kind"] != "payment":
            return None
        allowed = self.config["purposes"]
        if a.get("purpose") in allowed:
            return RuleResult("purpose", PASS, f"Purpose: {a['purpose']}")
        return RuleResult("purpose", DENY, f"A payment purpose is required: one of {', '.join(allowed)}.")

    def _corridor_documents(self, a, ctx):
        if a["kind"] != "payment" or a["from_currency"] == a["to_currency"]:
            return None
        payee = ctx["payee"]
        for rule in self.config.get("corridor_rules", []):
            if a["from_currency"] != rule["from_currency"] or a.get("purpose") not in rule["purposes"]:
                continue
            student = beneficiary_student(a["user_id"], payee)
            institution = payee.get("institution_id") if (payee and a["purpose"] == "tuition") else None
            doc = self.documents.student_file(student, institution)
            if doc is None:
                need = "for this institution " if institution else ""
                return RuleResult("student_file", DENY,
                                  f"{rule['label']}: an active student file {need}is required before this payment.")
            estimate = D(doc["data"]["annual_estimate"].get(a["purpose"], "0"))
            file_ccy = doc["data"]["currency"]
            start = parse_dt(doc["valid_from"]) if doc["valid_from"] else None
            used = ZERO
            for p in self._executed_payments():
                if p.get("student_user_id") != student or p.get("purpose") != a["purpose"]:
                    continue
                if start and p["_executed_at"] < start:
                    continue
                used += D(p["receive_amount"]) * self.feed.mid(p["to_currency"], file_ccy)
            this = D(a["receive_amount"]) * self.feed.mid(a["to_currency"], file_ccy)
            used, this = q(used, file_ccy), q(this, file_ccy)
            if used + this > estimate:
                return RuleResult("student_file", DENY,
                                  f"Exceeds the student file's approved {a['purpose']} estimate: "
                                  f"{fmt(used, file_ccy)} used + {fmt(this, file_ccy)} > {fmt(estimate, file_ccy)}.")
            return RuleResult("student_file", PASS,
                              f"Student file {doc['data'].get('file_no', '')} active: "
                              f"{fmt(used + this, file_ccy)} of {fmt(estimate, file_ccy)} {a['purpose']} estimate")
        return None

    def _limits(self, a, ctx):
        lim = {k: fmt(v, "USD") for k, v in self.config["limits_usd"].items()}
        cap = {k: D(v) for k, v in self.config["limits_usd"].items()}
        usd = D(a["usd_equivalent"])
        if a["kind"] == "conversion":
            if usd > cap["conversion_per_transaction"]:
                return RuleResult("limits", STEP_UP, f"Conversion above {lim['conversion_per_transaction']}: "
                                                     "confirm with your PIN.")
            return RuleResult("limits", PASS, "Within conversion limit")
        if usd > cap["hard_max_per_transaction"]:
            return RuleResult("limits", DENY, f"Above the maximum single payment ({lim['hard_max_per_transaction']}).")
        now = self.clock.now()
        today = sum((D(p["usd_equivalent"]) for p in ctx["history"] if p["_executed_at"].date() == now.date()), ZERO)
        month = sum((D(p["usd_equivalent"]) for p in ctx["history"]
                     if (p["_executed_at"].year, p["_executed_at"].month) == (now.year, now.month)), ZERO)
        if today + usd > cap["daily"]:
            return RuleResult("limits", DENY, f"Would pass today's limit: {fmt(today + usd, 'USD')} of "
                                              f"{lim['daily']}.")
        if month + usd > cap["monthly"]:
            return RuleResult("limits", DENY, f"Would pass this month's limit: {fmt(month + usd, 'USD')} of "
                                              f"{lim['monthly']}.")
        if usd > cap["per_transaction"]:
            return RuleResult("limits", STEP_UP, f"Above your per-payment limit of {lim['per_transaction']}: "
                                                 "confirm with your PIN.")
        return RuleResult("limits", PASS, f"Within limits (today {fmt(today + usd, 'USD')} of {lim['daily']})")

    def _velocity(self, a, ctx):
        if a["kind"] != "payment":
            return None
        cfg = self.config["velocity"]
        since = self.clock.now() - timedelta(minutes=cfg["window_minutes"])
        recent = sum(1 for p in ctx["history"] if p["_executed_at"] >= since)
        if recent >= cfg["max_payments"]:
            return RuleResult("velocity", STEP_UP, f"{recent} payments in the last {cfg['window_minutes']} minutes: "
                                                   "confirm with your PIN.")
        return RuleResult("velocity", PASS, "Normal payment frequency")

    def _anomaly(self, a, ctx):
        if a["kind"] != "payment":
            return None
        cfg = self.config["anomaly"]
        past = [D(p["usd_equivalent"]) for p in ctx["history"]]
        if len(past) < cfg["min_history"]:
            return None
        median = statistics.median(past)
        usd = D(a["usd_equivalent"])
        # Earlier payments to the same payee in the window count too, so splitting a payment doesn't dodge this.
        hours = cfg.get("split_window_hours", 24)
        since = self.clock.now() - timedelta(hours=hours)
        earlier = sum((D(p["usd_equivalent"]) for p in ctx["history"]
                       if p.get("payee_id") == a.get("payee_id") and p["_executed_at"] >= since), ZERO)
        threshold = median * Decimal(str(cfg["multiplier"]))
        if median > 0 and usd + earlier > threshold:
            ratio = ((usd + earlier) / median).quantize(Decimal("0.1"))
            if usd > threshold:
                return RuleResult("anomaly", STEP_UP, f"About {ratio}x your usual payment: confirm with your PIN.")
            return RuleResult("anomaly", STEP_UP, f"Together with your other payments to this payee in the last "
                                                  f"{hours} hours, about {ratio}x your usual payment: confirm with "
                                                  "your PIN.")
        return RuleResult("anomaly", PASS, "Amount is typical for you")

    def _sanctions(self, a, ctx):
        if a["kind"] != "payment" or not ctx["payee"]:
            return None
        name = ctx["payee"]["display_name"]
        threshold = self.config["sanctions"]["match_threshold"]
        hit = max(self.sanctions, key=lambda s: name_similarity(name, s), default=None)
        if hit and name_similarity(name, hit) >= threshold:
            return RuleResult("sanctions", DENY, "Payee name matches a sanctions watchlist entry. Payment blocked.")
        return RuleResult("sanctions", PASS, "Screened against the sanctions watchlist")

    def _untrusted_origin(self, a, ctx):
        """Drafts made after the chat saw forwarded content: always PIN; quarantine after a high-risk message.

        In quarantine only registry-verified institutions can still be paid, since paying the real
        university can't benefit a scammer.
        """
        if a.get("origin") != "document":
            return None
        score = int(a.get("risk_score") or 0)
        payee = ctx["payee"]
        registry_payee = bool(payee and payee["payee_type"] == "institution" and payee["verified"])
        if a["kind"] == "payment" and score >= self.config["scam"]["deny_at"] and not registry_payee:
            return RuleResult("untrusted_origin", DENY,
                              f"This chat included a message with scam risk {score}/100, so from here it can only "
                              "pay registry-verified universities. Start a new chat for other payments.")
        return RuleResult("untrusted_origin", STEP_UP,
                          "Prepared after reading a forwarded message: confirm with your PIN.")
