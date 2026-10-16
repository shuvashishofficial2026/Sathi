"""Budgets, spending, deadlines and runway across currencies."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from .fx import RateFeed
from .ledger import Ledger
from .money import ZERO, D, currency, q
from .util import Clock, new_id

SPEND_KINDS = ("payment", "spend")
ONE_OFF_CATEGORIES = ("tuition",)


class Budget:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, ledger: Ledger, feed: RateFeed):
        self.conn = conn
        self.clock = clock
        self.ledger = ledger
        self.feed = feed

    def _convert(self, amount, from_ccy: str, to_ccy: str) -> Decimal:
        return D(amount) * self.feed.mid(from_ccy, to_ccy) if from_ccy != to_ccy else D(amount)

    # budgets
    def set_budget(self, user_id: str, category: str, monthly_limit, ccy: str) -> dict:
        ccy = currency(ccy)
        limit = q(monthly_limit, ccy)
        if limit <= 0:
            raise ValueError("monthly limit must be positive")
        category = category.strip().lower()
        self.conn.execute(
            "INSERT INTO budgets(user_id, category, currency, monthly_limit) VALUES (?,?,?,?) "
            "ON CONFLICT(user_id, category) DO UPDATE SET currency = excluded.currency, "
            "monthly_limit = excluded.monthly_limit",
            (user_id, category, ccy, str(limit)),
        )
        return {"category": category, "currency": ccy, "monthly_limit": str(limit)}

    def spending(self, user_id: str, since: datetime) -> dict[str, dict[str, Decimal]]:
        """Outflows by category and currency since a date (payments and card spending)."""
        out: dict[str, dict[str, Decimal]] = defaultdict(lambda: defaultdict(lambda: ZERO))
        for j in self.ledger.history(user_id, limit=10_000, since=since):
            if j["kind"] not in SPEND_KINDS or not j["category"]:
                continue
            for ccy, amt in j["amounts"].items():
                if D(amt) < 0:
                    out[j["category"]][ccy] += -D(amt)
        return out

    def income(self, user_id: str, since: datetime) -> dict[str, Decimal]:
        out: dict[str, Decimal] = defaultdict(lambda: ZERO)
        for j in self.ledger.history(user_id, limit=10_000, since=since):
            if j["kind"] not in ("payment", "income"):
                continue
            for ccy, amt in j["amounts"].items():
                if D(amt) > 0:
                    out[ccy] += D(amt)
        return out

    def summary(self, user_id: str) -> dict:
        now = self.clock.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        spent = self.spending(user_id, month_start)
        rows = self.conn.execute("SELECT * FROM budgets WHERE user_id = ? ORDER BY category", (user_id,)).fetchall()
        categories = []
        for r in rows:
            ccy = r["currency"]
            total = sum((self._convert(v, c, ccy) for c, v in spent.get(r["category"], {}).items()), ZERO)
            limit = D(r["monthly_limit"])
            pct = int(total / limit * 100) if limit else 0
            categories.append({
                "category": r["category"], "currency": ccy, "limit": str(q(limit, ccy)),
                "spent": str(q(total, ccy)), "remaining": str(q(limit - total, ccy)), "pct_used": pct,
                "status": "over" if total > limit else "near" if pct >= 80 else "ok",
            })
        budgeted = {r["category"] for r in rows}
        unbudgeted = {cat: {c: str(q(v, c)) for c, v in by_ccy.items()}
                      for cat, by_ccy in spent.items() if cat not in budgeted}
        return {"month": month_start.strftime("%B %Y"), "categories": categories, "unbudgeted": unbudgeted}

    # deadlines
    def add_deadline(self, user_id: str, title: str, due_date: str, amount, ccy: str, payee_id: str | None = None,
                     purpose: str | None = None) -> dict:
        ccy = currency(ccy)
        due = datetime.strptime(due_date, "%Y-%m-%d").date()
        deadline_id = new_id("dl")
        self.conn.execute(
            "INSERT INTO deadlines(id, user_id, title, due_date, amount, currency, payee_id, purpose) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (deadline_id, user_id, title[:80], due.isoformat(), str(q(amount, ccy)), ccy, payee_id, purpose),
        )
        return dict(self.conn.execute("SELECT * FROM deadlines WHERE id = ?", (deadline_id,)).fetchone())

    def deadlines(self, user_id: str, within_days: int | None = None) -> list[dict]:
        rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM deadlines WHERE user_id = ? AND status = 'open' ORDER BY due_date", (user_id,))]
        today = self.clock.now().date()
        out = []
        for r in rows:
            days = (datetime.strptime(r["due_date"], "%Y-%m-%d").date() - today).days
            if within_days is not None and days > within_days:
                continue
            out.append({**r, "days_left": days})
        return out

    def settle_deadline(self, user_id: str, payment: dict) -> dict | None:
        """Close the earliest open deadline that an executed payment covers (same payee, currency, purpose)."""
        if payment.get("kind") != "payment":
            return None
        rows = self.conn.execute(
            "SELECT * FROM deadlines WHERE user_id = ? AND status = 'open' AND payee_id = ? AND currency = ? "
            "ORDER BY due_date", (user_id, payment["payee_id"], payment["to_currency"])).fetchall()
        for r in rows:
            if D(r["amount"]) <= D(payment["receive_amount"]) and r["purpose"] in (None, payment.get("purpose")):
                self.conn.execute("UPDATE deadlines SET status = 'paid' WHERE id = ?", (r["id"],))
                return dict(r)
        return None

    # runway
    def runway(self, user_id: str) -> dict:
        """How long the money lasts, after setting aside upcoming deadlines."""
        home = self.conn.execute("SELECT home_currency FROM users WHERE id = ?", (user_id,)).fetchone()[0]
        now = self.clock.now()
        since = now - timedelta(days=90)
        liquid = sum((self.feed.to_usd(v, c) for c, v in self.ledger.balances(user_id).items()), ZERO)
        spend_usd = ZERO
        for cat, by_ccy in self.spending(user_id, since).items():
            if cat in ONE_OFF_CATEGORIES:
                continue
            spend_usd += sum((self.feed.to_usd(v, c) for c, v in by_ccy.items()), ZERO)
        income_usd = sum((self.feed.to_usd(v, c) for c, v in self.income(user_id, since).items()), ZERO)
        monthly_spend, monthly_income = spend_usd / 3, income_usd / 3
        upcoming = self.deadlines(user_id, within_days=180)
        reserved = sum((self.feed.to_usd(d["amount"], d["currency"]) for d in upcoming), ZERO)
        free = liquid - reserved
        burn = monthly_spend - monthly_income

        def months(x):
            return str(q(x, "USD")) if x is not None else None

        to_home = self.feed.mid("USD", home)
        return {
            "home_currency": home,
            "liquid": str(q(liquid * to_home, home)),
            "reserved_for_deadlines": str(q(reserved * to_home, home)),
            "free_after_deadlines": str(q(free * to_home, home)),
            "avg_monthly_spending": str(q(monthly_spend * to_home, home)),
            "avg_monthly_income": str(q(monthly_income * to_home, home)),
            "months_if_income_stops": months(free / monthly_spend) if monthly_spend > 0 else None,
            "months_at_current_pace": months(free / burn) if burn > 0 else None,
            "running_down": burn > 0,
            "covers_upcoming_deadlines": free >= 0,
            "upcoming_deadlines": [{"title": d["title"], "due_date": d["due_date"], "days_left": d["days_left"],
                                    "amount": d["amount"], "currency": d["currency"]} for d in upcoming],
            "as_of": now.astimezone(UTC).strftime("%d %b %Y"),
        }
