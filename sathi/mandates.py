"""Mandates: bounded autonomy.

The user signs a standing instruction once (with their PIN), e.g. "convert up
to USD 300 to CNY whenever I get at least 7.15 CNY per USD, for 14 days". The
mandate engine then acts on its own inside those caps. It still goes through
the policy engine, and anything needing a PIN is left for the user instead.
"""

from __future__ import annotations

import sqlite3
from datetime import timedelta

from .audit import AuditLog
from .drafts import Drafts
from .executor import ExecutionError, Executor
from .fx import QuoteEngine, RateFeed
from .ledger import Ledger
from .money import D, currency, fmt, q, rate
from .users import Users
from .util import Clock, iso, new_id, parse_dt


class MandateError(Exception):
    pass


class MandateEngine:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, audit: AuditLog, feed: RateFeed, quotes: QuoteEngine,
                 ledger: Ledger, users: Users, drafts: Drafts, executor: Executor, config: dict):
        self.conn = conn
        self.clock = clock
        self.audit = audit
        self.feed = feed
        self.quotes = quotes
        self.ledger = ledger
        self.users = users
        self.drafts = drafts
        self.executor = executor
        self.config = config["mandates"]

    def propose(self, user_id: str, from_ccy: str, to_ccy: str, max_amount, min_rate, days_valid: int = 14,
                note: str = "") -> dict:
        """Tier 1: the agent may propose; nothing runs until the user signs."""
        from_ccy, to_ccy = currency(from_ccy), currency(to_ccy)
        if from_ccy == to_ccy:
            raise MandateError("A mandate converts between two different currencies.")
        max_amount, min_rate = q(max_amount, from_ccy), rate(min_rate)
        if max_amount <= 0 or min_rate <= 0:
            raise MandateError("Amount and rate must be positive.")
        if not 1 <= int(days_valid) <= self.config["max_days"]:
            raise MandateError(f"A mandate can last 1 to {self.config['max_days']} days.")
        usd = self.feed.to_usd(max_amount, from_ccy)
        if usd > D(self.config["max_usd"]):
            raise MandateError(f"Mandates are capped at about USD {self.config['max_usd']}.")
        mandate_id = new_id("md")
        now = self.clock.now()
        self.conn.execute(
            "INSERT INTO mandates(id, user_id, from_currency, to_currency, max_amount, min_rate, status, created_at, "
            "expires_at, note) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (mandate_id, user_id, from_ccy, to_ccy, str(max_amount), str(min_rate), "proposed", iso(now),
             iso(now + timedelta(days=int(days_valid))), note[:140]),
        )
        m = self.get(mandate_id)
        self.audit.record("agent", "mandate.proposed", {"mandate_id": mandate_id, "describe": m["description"]},
                          user_id)
        return m

    def sign(self, user_id: str, mandate_id: str, pin: str) -> dict:
        """User-only: activates a proposed mandate after a PIN check."""
        m = self.get(mandate_id)
        if m["user_id"] != user_id or m["status"] != "proposed":
            raise MandateError("Only a proposed mandate of yours can be signed.")
        if not self.users.check_pin(user_id, pin):
            raise MandateError("Wrong PIN.")
        self.conn.execute("UPDATE mandates SET status = 'active', signed_at = ? WHERE id = ?",
                          (iso(self.clock.now()), mandate_id))
        self.audit.record("user", "mandate.signed", {"mandate_id": mandate_id, "describe": describe(m)}, user_id)
        return self.get(mandate_id)

    def revoke(self, user_id: str, mandate_id: str) -> dict:
        m = self.get(mandate_id)
        if m["user_id"] != user_id or m["status"] not in ("proposed", "active"):
            raise MandateError("Nothing to revoke.")
        self._set_status(mandate_id, "revoked")
        self.audit.record("user", "mandate.revoked", {"mandate_id": mandate_id}, user_id)
        return self.get(mandate_id)

    def get(self, mandate_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM mandates WHERE id = ?", (mandate_id,)).fetchone()
        if not row:
            raise MandateError(f"unknown mandate {mandate_id}")
        m = dict(row)
        m["remaining"] = str(q(D(m["max_amount"]) - D(m["used_amount"]), m["from_currency"]))
        m["description"] = describe(m)
        return m

    def list(self, user_id: str) -> list[dict]:
        rows = self.conn.execute("SELECT id FROM mandates WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        return [self.get(r["id"]) for r in rows]

    def _set_status(self, mandate_id: str, status: str) -> None:
        self.conn.execute("UPDATE mandates SET status = ? WHERE id = ?", (status, mandate_id))

    def run(self) -> list[dict]:
        """Check every active mandate against current rates and act where the condition is met."""
        events = []
        now = self.clock.now()
        for row in self.conn.execute("SELECT id FROM mandates WHERE status = 'active'").fetchall():
            m = self.get(row["id"])
            uid = m["user_id"]
            if now > parse_dt(m["expires_at"]):
                self._set_status(m["id"], "expired")
                self.audit.record("mandate", "mandate.expired", {"mandate_id": m["id"]}, uid)
                events.append({"mandate_id": m["id"], "user_id": uid, "event": "expired"})
                continue
            remaining = D(m["remaining"])
            if remaining <= 0:
                self._set_status(m["id"], "completed")
                continue
            balance = self.ledger.balance(self.ledger.wallet(uid, m["from_currency"]))
            amount = min(remaining, balance)
            if amount <= 0:
                events.append({"mandate_id": m["id"], "user_id": uid, "event": "no_balance"})
                continue
            result = self.quotes.quote(uid, m["from_currency"], m["to_currency"], amount, "send", mode="conversion")
            if not result["quotes"]:
                continue
            best = result["quotes"][0]
            if D(best["total_debit"]) > balance:
                fee_ratio = D(best["total_debit"]) / D(best["send_amount"])
                amount = q(balance / fee_ratio, m["from_currency"]) - D("0.01")
                result = self.quotes.quote(uid, m["from_currency"], m["to_currency"], amount, "send",
                                           mode="conversion")
                best = result["quotes"][0]
            if D(best["offered_rate"]) < D(m["min_rate"]):
                events.append({"mandate_id": m["id"], "user_id": uid, "event": "waiting",
                               "rate": best["offered_rate"], "target": m["min_rate"]})
                continue
            action = self.drafts.conversion(uid, best["id"], origin="mandate", mandate_id=m["id"])
            if action["status"] == "blocked":
                events.append({"mandate_id": m["id"], "user_id": uid, "event": "blocked",
                               "reasons": action["card"]["reasons"]})
                continue
            try:
                receipt = self.executor.execute_mandated(action["id"], m)
            except ExecutionError as exc:
                events.append({"mandate_id": m["id"], "user_id": uid, "event": exc.code,
                               "reasons": exc.reasons or [exc.message], "action_id": action["id"]})
                continue
            used = q(D(m["used_amount"]) + D(best["send_amount"]), m["from_currency"])
            self.conn.execute("UPDATE mandates SET used_amount = ? WHERE id = ?", (str(used), m["id"]))
            if used >= D(m["max_amount"]):
                self._set_status(m["id"], "completed")
            self.audit.record("mandate", "mandate.executed", {
                "mandate_id": m["id"], "action_id": action["id"], "summary": receipt["summary"],
                "rate": best["offered_rate"], "min_rate": m["min_rate"]}, uid)
            events.append({"mandate_id": m["id"], "user_id": uid, "event": "executed",
                           "summary": receipt["summary"], "action_id": action["id"]})
        return events


def describe(m: dict) -> str:
    return (f"Convert up to {fmt(m['max_amount'], m['from_currency'])} to {m['to_currency']} when the rate is at "
            f"least {D(m['min_rate']).normalize():f} {m['to_currency']} per {m['from_currency']}, until "
            f"{parse_dt(m['expires_at']).strftime('%d %b %Y')}")
