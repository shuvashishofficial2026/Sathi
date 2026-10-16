"""The sandbox: wires every service together and seeds the demo world.

Two demo users:
  nusrat - a CUET graduate doing a master's in Shenzhen (English), PIN 2468
  abbu   - her father in Chattogram who sends her allowance (Bangla), PIN 1357

Methods are split into two groups. "Agent-safe" methods only read or prepare
drafts (tiers 0 and 1); the agent's tools are built on these alone. "App-only"
methods confirm, verify, sign or move the sandbox clock; only the UI calls them.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from datetime import timedelta
from pathlib import Path

from . import db
from .actions import Actions, ConfirmationAuthority, action_card
from .audit import AuditLog
from .budget import Budget
from .compliance import Documents
from .drafts import Drafts
from .executor import Executor
from .fx import QuoteEngine, RateFeed, load_providers
from .ledger import Ledger
from .mandates import MandateEngine
from .money import ZERO, D, currency, q
from .payees import Payees
from .policy import PolicyEngine, beneficiary_student, load_config
from .scam import ScamShield
from .users import Users
from .util import Clock, dumps, iso

DATA = Path(__file__).parent / "data"
PIN_LIKE = re.compile(r"(?<!\d)\d{4,6}(?!\d)")


class SandboxError(Exception):
    pass


class Sandbox:
    def __init__(self, db_path: str = ":memory:", clock: Clock | None = None, seed: bool = True,
                 rng_seed: int | None = 7, secret: bytes | None = None, config: dict | None = None):
        self.lock = threading.RLock()
        self.clock = clock or Clock()
        self.conn = db.connect(db_path)
        self.config = config or load_config()
        self.audit = AuditLog(self.conn, self.clock)
        self.users = Users(self.conn, self.clock, self.audit)
        self.ledger = Ledger(self.conn, self.clock)
        self.feed = RateFeed.from_file(DATA / "fx_snapshot.json", seed=rng_seed)
        self.quotes = QuoteEngine(self.conn, self.feed, load_providers(DATA / "providers.json"), self.clock,
                                  ttl_minutes=self.config["quotes"]["ttl_minutes"])
        registry = json.loads((DATA / "institutions.json").read_text(encoding="utf-8"))["institutions"]
        sanctions = json.loads((DATA / "sanctions.json").read_text(encoding="utf-8"))["names"]
        self.payees = Payees(self.conn, self.clock, registry)
        self.documents = Documents(self.conn, self.clock)
        self.policy = PolicyEngine(self.conn, self.clock, self.users, self.ledger, self.payees, self.documents,
                                   self.feed, self.config, sanctions)
        self.actions = Actions(self.conn, self.clock, self.audit)
        self.drafts = Drafts(self.clock, self.audit, self.quotes, self.payees, self.policy, self.actions)
        self.authority = ConfirmationAuthority(secret or secrets.token_bytes(32))
        self.executor = Executor(self.conn, self.clock, self.audit, self.ledger, self.actions, self.policy,
                                 self.users, self.payees, self.authority)
        self.mandates = MandateEngine(self.conn, self.clock, self.audit, self.feed, self.quotes, self.ledger,
                                      self.users, self.drafts, self.executor, self.config)
        self.budget = Budget(self.conn, self.clock, self.ledger, self.feed)
        self.scam = ScamShield(self.payees)
        if seed:
            seed_demo(self)

    # ---------- agent-safe: read (tier 0) ----------
    def profile(self, user_id: str) -> dict:
        return self.users.get(user_id)

    def balances(self, user_id: str) -> dict:
        user = self.users.get(user_id)
        bals = self.ledger.balances(user_id)
        usd = sum((self.feed.to_usd(v, c) for c, v in bals.items()), ZERO)
        return {
            "balances": {c: str(v) for c, v in bals.items()},
            "total_usd": str(q(usd, "USD")),
            f"total_{user['home_currency']}": str(q(usd * self.feed.mid("USD", user["home_currency"]),
                                                    user["home_currency"])),
            "rates_as_of": self.feed.as_of,
        }

    def rates(self, base: str, quote: str) -> dict:
        return {"base": currency(base), "quote": currency(quote), "mid_rate": str(self.feed.mid(base, quote)),
                "inverse": str(self.feed.mid(quote, base)), "as_of": self.feed.as_of, "source": self.feed.source}

    def get_quotes(self, user_id: str, from_ccy: str, to_ccy: str, amount, amount_type: str = "send",
                   purpose: str | None = None, payee_id: str | None = None, mode: str = "payment") -> dict:
        payee_type = None
        if payee_id:
            payee = self.payees.get(user_id, payee_id)
            payee_type = payee["payee_type"]
            if currency(to_ccy) != payee["currency"]:
                raise SandboxError(f"{payee['display_name']} receives {payee['currency']}, not {currency(to_ccy)}.")
        return self.quotes.quote(user_id, from_ccy, to_ccy, amount, amount_type, purpose, payee_type, mode)

    def list_payees(self, user_id: str) -> list[dict]:
        return self.payees.list(user_id)

    def history(self, user_id: str, limit: int = 15) -> list[dict]:
        return self.ledger.history(user_id, limit)

    def documents_on_record(self, user_id: str) -> list[dict]:
        return self.documents.list(user_id)

    def pending(self, user_id: str) -> list[dict]:
        return [{**a, "card": action_card(a)} for a in self.actions.list(user_id, ("awaiting_confirmation",))]

    def recent_actions(self, user_id: str, limit: int = 10) -> list[dict]:
        return [{**a, "card": action_card(a)} for a in self.actions.list(user_id, limit=limit)]

    def list_mandates(self, user_id: str) -> list[dict]:
        return self.mandates.list(user_id)

    def budget_summary(self, user_id: str) -> dict:
        return self.budget.summary(user_id)

    def runway(self, user_id: str) -> dict:
        return self.budget.runway(user_id)

    def deadlines(self, user_id: str) -> list[dict]:
        return self.budget.deadlines(user_id)

    # ---------- agent-safe: prepare (tier 1) ----------
    def draft_payment(self, user_id: str, quote_id: str, payee_id: str, purpose: str, reference: str = "",
                      origin: str = "chat", risk_score: int = 0) -> dict:
        with self.lock:
            return self.drafts.payment(user_id, quote_id, payee_id, purpose, reference, origin, risk_score)

    def draft_conversion(self, user_id: str, quote_id: str, origin: str = "chat") -> dict:
        with self.lock:
            return self.drafts.conversion(user_id, quote_id, origin)

    def add_payee(self, user_id: str, display_name: str, payee_type: str, currency_code: str, account_number: str,
                  bank_name: str | None = None, country: str | None = None, source: str = "agent") -> dict:
        payee = self.payees.add(user_id, display_name, payee_type, currency_code, account_number, bank_name,
                                country, source)
        self.audit.record("agent" if source == "agent" else "user", "payee.added",
                          {"payee_id": payee["id"], "name": payee["display_name"], "type": payee_type,
                           "verified": payee["verified"], "flags": payee["flags"],
                           "account_number": payee["account_number"]}, user_id)
        return payee

    def propose_mandate(self, user_id: str, from_ccy: str, to_ccy: str, max_amount, min_rate,
                        days_valid: int = 14, note: str = "") -> dict:
        return self.mandates.propose(user_id, from_ccy, to_ccy, max_amount, min_rate, days_valid, note)

    def analyze_message(self, user_id: str, text: str) -> dict:
        report = self.scam.analyze(text)
        self.audit.record("agent", "scam.analyzed", {"risk_score": report["risk_score"],
                                                     "flags": [f["id"] for f in report["flags"]]}, user_id)
        return report

    def redact_pin(self, user_id: str, text: str, audit: bool = True) -> tuple[str, bool]:
        """Remove the user's own PIN if they typed it into chat, before the AI or the logs see it."""
        found = False

        def scrub(m: re.Match) -> str:
            nonlocal found
            if self.users.matches_pin(user_id, m.group()):
                found = True
                return "[PIN removed]"
            return m.group()

        candidates = PIN_LIKE.findall(text or "")
        if not candidates or len(candidates) > 10:
            return text, False
        cleaned = PIN_LIKE.sub(scrub, text)
        if found and audit:
            self.audit.record("system", "pin.redacted", {"where": "chat"}, user_id)
        return cleaned, found

    def set_budget(self, user_id: str, category: str, monthly_limit, ccy: str) -> dict:
        return self.budget.set_budget(user_id, category, monthly_limit, ccy)

    def add_deadline(self, user_id: str, title: str, due_date: str, amount, ccy: str,
                     payee_id: str | None = None, purpose: str | None = None) -> dict:
        return self.budget.add_deadline(user_id, title, due_date, amount, ccy, payee_id, purpose)

    # ---------- app-only (UI): approve, verify, sign, demo controls ----------
    def confirm(self, user_id: str, action_id: str, pin: str | None = None) -> dict:
        """The user tapped Confirm in the app. Issues the one-time token and executes."""
        with self.lock:
            action = self.actions.get(action_id)
            receipt = self.executor.confirm(user_id, action_id, self.authority.token_for(action), pin)
            settled = self.budget.settle_deadline(user_id, action["payload"])
            if settled:
                self.audit.record("system", "deadline.paid", {"deadline_id": settled["id"], "title": settled["title"],
                                                              "action_id": action_id}, user_id)
                receipt["deadline_paid"] = settled["title"]
            return receipt

    def reject(self, user_id: str, action_id: str) -> dict:
        with self.lock:
            return self.executor.reject(user_id, action_id)

    def verify_payee(self, user_id: str, payee_id: str, pin: str) -> dict:
        if not self.users.check_pin(user_id, pin):
            raise SandboxError("Wrong PIN.")
        payee = self.payees.verify(user_id, payee_id)
        self.audit.record("user", "payee.verified", {"payee_id": payee_id, "name": payee["display_name"]}, user_id)
        return payee

    def sign_mandate(self, user_id: str, mandate_id: str, pin: str) -> dict:
        return self.mandates.sign(user_id, mandate_id, pin)

    def revoke_mandate(self, user_id: str, mandate_id: str) -> dict:
        return self.mandates.revoke(user_id, mandate_id)

    def market_tick(self, volatility="0.004") -> dict:
        """Demo: move the market a little, then let mandates react."""
        with self.lock:
            snap = self.feed.tick(volatility, as_of=iso(self.clock.now()))
            self.audit.record("system", "market.tick", {"usd_rates": snap["usd_rates"]})
            return {"rates": snap, "mandate_events": self.mandates.run()}

    def set_rate(self, ccy: str, units_per_usd) -> dict:
        """Demo: set one rate directly (e.g. to show a mandate firing), then let mandates react."""
        with self.lock:
            self.feed.set_usd_rate(ccy, units_per_usd, as_of=iso(self.clock.now()))
            self.audit.record("system", "market.set_rate", {"currency": ccy, "units_per_usd": str(units_per_usd)})
            return {"rates": self.feed.snapshot(), "mandate_events": self.mandates.run()}

    def advance_time(self, days: float = 0, hours: float = 0, minutes: float = 0) -> str:
        """Demo: move the sandbox clock forward (cooling-off periods, expiry)."""
        now = self.clock.advance(days=days, hours=hours, minutes=minutes)
        self.audit.record("system", "clock.advanced", {"days": days, "hours": hours, "minutes": minutes})
        return iso(now)


# ---------------------------------------------------------------- demo world

NUSRAT_SPENDING = [  # (days ago, category, CNY, memo)
    (92, "food", "210.50", "Canteen + groceries"), (90, "transport", "45.00", "Metro card top-up"),
    (85, "food", "238.00", "Groceries"), (84, "phone", "59.00", "Mobile plan"),
    (78, "food", "246.20", "Canteen + groceries"), (75, "transport", "40.00", "Metro card top-up"),
    (71, "books", "128.00", "Textbooks"), (64, "food", "265.80", "Groceries"),
    (57, "food", "231.40", "Canteen"), (54, "phone", "59.00", "Mobile plan"),
    (50, "transport", "45.00", "Metro card top-up"), (43, "food", "252.10", "Groceries"),
    (36, "food", "244.60", "Canteen + groceries"), (29, "transport", "40.00", "Metro card top-up"),
    (24, "phone", "59.00", "Mobile plan"), (22, "food", "271.30", "Groceries"),
    (15, "food", "236.90", "Canteen"), (12, "books", "86.00", "Lab notebook + printing"),
    (8, "food", "258.40", "Groceries"), (6, "transport", "45.00", "Metro card top-up"),
    (3, "food", "119.70", "Canteen"),
]


def _seed_payment(sb: Sandbox, user_id: str, payee: dict, provider_id: str, from_ccy: str, amount: str,
                  purpose: str, days_ago: int, amount_type: str = "send") -> None:
    """Insert a past, already-executed payment (bypasses approval: seeding only)."""
    when = sb.clock.now() - timedelta(days=days_ago)
    priced, _ = sb.quotes._price(sb.quotes.provider(provider_id), from_ccy, payee["currency"], D(amount), amount_type)
    provider = sb.quotes.provider(provider_id)
    payload = {
        "kind": "payment", "user_id": user_id, "quote_id": "seed",
        **{k: priced[k] for k in ("provider_id", "provider_name", "from_currency", "to_currency", "send_amount",
                                  "fee", "total_debit", "receive_amount", "mid_rate", "offered_rate", "total_cost",
                                  "total_cost_pct", "eta_hours", "usd_equivalent")},
        "arrives_by": iso(when + timedelta(hours=provider.eta_hours)), "quote_expires_at": iso(when),
        "payee_id": payee["id"], "payee_name": payee["display_name"], "payee_type": payee["payee_type"],
        "institution_id": payee["institution_id"], "student_user_id": beneficiary_student(user_id, payee),
        "purpose": purpose, "reference": "", "origin": "chat", "risk_score": 0,
    }
    payload = json.loads(dumps(payload))
    action_id = f"act_seed{secrets.token_hex(4)}"
    sb.conn.execute(
        "INSERT INTO actions(id, user_id, kind, status, origin, payload, action_hash, decision, created_at, "
        "expires_at, resolved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (action_id, user_id, "payment", "executed", "chat", dumps(payload), "seed",
         dumps({"outcome": "allow", "reasons": [], "passed": []}), iso(when), iso(when), iso(when)),
    )
    journal_id = sb.ledger.post(kind="payment", user_id=user_id, legs=sb.executor._legs(payload),
                                idempotency_key=action_id, memo=f"{purpose}: {payee['display_name']}",
                                category=purpose, meta={"action_id": action_id, "seed": True}, ts=when)
    sb.conn.execute("UPDATE actions SET journal_id = ? WHERE id = ?", (journal_id, action_id))


def seed_demo(sb: Sandbox) -> None:
    now = sb.clock.now()
    L = sb.ledger
    sb.users.create("nusrat", "Nusrat Jahan", "BDT", "CN", pin="2468", language="en")
    sb.users.create("abbu", "Abdul Karim (Abbu)", "BDT", "BD", pin="1357", language="bn")

    start = now - timedelta(days=95)
    for user_id, ccy, amount in [("nusrat", "BDT", "480000"), ("nusrat", "CNY", "2000"), ("nusrat", "USD", "450"),
                                 ("abbu", "BDT", "1100000")]:
        L.post(kind="opening", user_id=user_id, legs=[(L.account("funding", "seed", ccy), -D(amount)),
                                                      (L.wallet(user_id, ccy), D(amount))],
               memo="Opening balance", ts=start)

    shu = sb.payees.add("nusrat", "Shenzhen Harbour University", "institution", "CNY", "6222020200112233445",
                        source="registry")
    landlord = sb.payees.add("nusrat", "Li Wei (landlord)", "person", "CNY", "6217 8899 0011 2345",
                             bank_name="Demo Bank of Shenzhen", country="CN", source="user",
                             verified_at=now - timedelta(days=120))
    sb.payees.add("nusrat", "Tanvir Ahmed (classmate)", "person", "CNY", "6230 5566 7788 9900",
                  bank_name="Demo Bank of Shenzhen", country="CN", source="user")
    daughter = sb.payees.add("abbu", "Nusrat (daughter)", "person", "CNY", "6213 4455 6677 8812",
                             bank_name="Demo Bank of Shenzhen", country="CN", source="user",
                             linked_user_id="nusrat", verified_at=now - timedelta(days=200))

    sb.documents.add("nusrat", "student_file", institution_id="shu", valid_from=now - timedelta(days=40),
                     valid_until=now + timedelta(days=325), data={
                         "file_no": "SF-2026-0417", "bank": "Demo Bank Chattogram (authorized dealer, simulated)",
                         "currency": "CNY",
                         "annual_estimate": {"tuition": "26000.00", "living_expenses": "36000.00"},
                     })
    sb.documents.add("nusrat", "admission_letter", institution_id="shu", status="verified",
                     data={"programme": "MSc Computer Science", "intake": "September 2026"})

    for days_ago in (88, 58, 28):
        _seed_payment(sb, "abbu", daughter, "digisend", "BDT", "50000", "living_expenses", days_ago)
    for days_ago in (85, 55, 25):
        _seed_payment(sb, "nusrat", landlord, "localpay", "CNY", "2000", "rent", days_ago)
    for days_ago, category, amount, memo in NUSRAT_SPENDING:
        L.post(kind="spend", user_id="nusrat",
               legs=[(L.wallet("nusrat", "CNY"), -D(amount)), (L.account("external", f"merchant_{category}", "CNY"),
                                                               D(amount))],
               memo=memo, category=category, ts=now - timedelta(days=days_ago))

    for category, limit in [("food", "1200"), ("transport", "200"), ("rent", "2000"), ("phone", "80"),
                            ("books", "150")]:
        sb.budget.set_budget("nusrat", category, limit, "CNY")
    sb.budget.add_deadline("nusrat", "Spring semester tuition", (now + timedelta(days=140)).strftime("%Y-%m-%d"),
                           "13000", "CNY", payee_id=shu["id"], purpose="tuition")
    sb.audit.record("system", "sandbox.seeded", {"users": ["nusrat", "abbu"]})
