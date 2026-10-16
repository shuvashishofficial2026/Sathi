"""Double-entry ledger.

Every journal's postings sum to zero per currency, wallets can never go
negative, and an idempotency key stops the same request posting twice.
Account ids look like "wallet:nusrat:CNY" (kind:owner:currency).
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import datetime
from decimal import Decimal

from .db import transaction
from .money import ZERO, D, currency, q
from .util import Clock, dumps, iso, loads, new_id


class LedgerError(Exception):
    pass


class InsufficientFunds(LedgerError):
    def __init__(self, account_id: str):
        super().__init__(f"insufficient funds in {account_id}")
        self.account_id = account_id


class DuplicateRequest(LedgerError):
    def __init__(self, journal_id: str):
        super().__init__(f"already processed as journal {journal_id}")
        self.journal_id = journal_id


class Ledger:
    def __init__(self, conn: sqlite3.Connection, clock: Clock):
        self.conn = conn
        self.clock = clock

    # accounts
    def account(self, kind: str, owner: str, ccy: str) -> str:
        ccy = currency(ccy)
        account_id = f"{kind}:{owner}:{ccy}"
        self.conn.execute(
            "INSERT OR IGNORE INTO accounts(id, owner, currency, kind) VALUES (?,?,?,?)",
            (account_id, owner, ccy, kind),
        )
        return account_id

    def wallet(self, user_id: str, ccy: str) -> str:
        return self.account("wallet", user_id, ccy)

    def balance(self, account_id: str) -> Decimal:
        rows = self.conn.execute("SELECT amount FROM postings WHERE account_id = ?", (account_id,))
        return sum((D(r["amount"]) for r in rows), ZERO)

    def balances(self, user_id: str) -> dict[str, Decimal]:
        rows = self.conn.execute(
            "SELECT a.currency, p.amount FROM accounts a LEFT JOIN postings p ON p.account_id = a.id "
            "WHERE a.owner = ? AND a.kind = 'wallet' ORDER BY a.currency",
            (user_id,),
        )
        out: dict[str, Decimal] = {}
        for r in rows:
            out.setdefault(r["currency"], ZERO)
            if r["amount"] is not None:
                out[r["currency"]] += D(r["amount"])
        return {c: q(v, c) for c, v in out.items()}

    # posting
    def post(
        self,
        *,
        kind: str,
        user_id: str | None,
        legs: list[tuple[str, Decimal]],
        idempotency_key: str | None = None,
        memo: str = "",
        category: str | None = None,
        meta: dict | None = None,
        ts: datetime | None = None,
    ) -> str:
        """Post a balanced journal. legs = [(account_id, signed amount), ...]."""
        totals: dict[str, Decimal] = defaultdict(lambda: ZERO)
        clean: list[tuple[str, str, Decimal]] = []
        for account_id, amount in legs:
            ccy = account_id.split(":")[2]
            amt = q(amount, ccy)
            if amt == 0:
                continue
            totals[ccy] += amt
            clean.append((account_id, ccy, amt))
        if not clean:
            raise LedgerError("journal has no non-zero legs")
        unbalanced = {c: v for c, v in totals.items() if v != 0}
        if unbalanced:
            raise LedgerError(f"journal does not balance: {unbalanced}")

        journal_id = new_id("jr")
        with transaction(self.conn):
            if idempotency_key:
                row = self.conn.execute(
                    "SELECT id FROM journals WHERE idempotency_key = ?", (idempotency_key,)
                ).fetchone()
                if row:
                    raise DuplicateRequest(row["id"])
            self.conn.execute(
                "INSERT INTO journals(id, ts, kind, user_id, idempotency_key, memo, category, meta) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (journal_id, iso(ts or self.clock.now()), kind, user_id, idempotency_key, memo, category,
                 dumps(meta or {})),
            )
            for account_id, ccy, amt in clean:
                k, owner, _ = account_id.split(":")
                self.account(k, owner, ccy)
                self.conn.execute(
                    "INSERT INTO postings(journal_id, account_id, currency, amount) VALUES (?,?,?,?)",
                    (journal_id, account_id, ccy, str(amt)),
                )
            for account_id, _, amt in clean:
                if account_id.startswith("wallet:") and amt < 0 and self.balance(account_id) < 0:
                    raise InsufficientFunds(account_id)
        return journal_id

    def history(self, user_id: str, limit: int = 20, since: datetime | None = None) -> list[dict]:
        """Journals touching the user's wallets, newest first, with the user's net per currency."""
        sql = (
            "SELECT j.id, j.ts, j.kind, j.memo, j.category, j.meta, p.currency, p.amount "
            "FROM journals j JOIN postings p ON p.journal_id = j.id "
            "WHERE p.account_id IN (SELECT id FROM accounts WHERE owner = ? AND kind = 'wallet')"
        )
        args: list = [user_id]
        if since:
            sql += " AND j.ts >= ?"
            args.append(iso(since))
        sql += " ORDER BY j.ts DESC, j.id"
        grouped: dict[str, dict] = {}
        for r in self.conn.execute(sql, args):
            j = grouped.setdefault(
                r["id"],
                {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "memo": r["memo"],
                 "category": r["category"], "meta": loads(r["meta"]), "amounts": defaultdict(lambda: ZERO)},
            )
            j["amounts"][r["currency"]] += D(r["amount"])
        out = []
        for j in grouped.values():
            j["amounts"] = {c: str(q(v, c)) for c, v in j["amounts"].items() if v != 0}
            out.append(j)
        out.sort(key=lambda j: j["ts"], reverse=True)
        return out[:limit]
