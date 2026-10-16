"""Payees and the verified-institution registry.

An institution payee is verified only when its account number exactly matches
the registry entry for that institution. A person or business payee starts
unverified; only the user can verify it in the app (with their PIN), and a
cooling-off period applies after that. The agent can add payees but never
verify them.
"""

from __future__ import annotations

import difflib
import re
import sqlite3

from .audit import mask_account
from .money import currency
from .util import Clock, dumps, iso, loads, new_id

PAYEE_TYPES = ("institution", "person", "business")


def normalize_name(name: str) -> str:
    name = re.sub(r"\(demo\)", "", (name or "").lower())
    return " ".join(re.sub(r"[^a-z0-9ঀ-৿ ]+", " ", name).split())


def digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def name_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, normalize_name(a), normalize_name(b)).ratio()


class PayeeError(Exception):
    pass


class Payees:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, registry: list[dict]):
        self.conn = conn
        self.clock = clock
        self.registry = registry

    # registry
    def registry_lookup(self, name: str, threshold: float = 0.85) -> dict | None:
        """Find an institution by name or alias."""
        best, best_score = None, 0.0
        for entry in self.registry:
            for candidate in [entry["name"], *entry.get("aliases", [])]:
                score = name_similarity(name, candidate)
                if score > best_score:
                    best, best_score = entry, score
        return best if best_score >= threshold else None

    def registry_mentions(self, text: str) -> list[dict]:
        """Institutions whose name or alias appears in free text."""
        norm = f" {normalize_name(text)} "
        found = []
        for entry in self.registry:
            for candidate in [entry["name"], *entry.get("aliases", [])]:
                if f" {normalize_name(candidate)} " in norm:
                    found.append(entry)
                    break
        return found

    # payees
    def add(self, owner: str, display_name: str, payee_type: str, currency_code: str, account_number: str,
            bank_name: str | None = None, country: str | None = None, source: str = "user",
            linked_user_id: str | None = None, verified_at=None) -> dict:
        if payee_type not in PAYEE_TYPES:
            raise PayeeError(f"payee_type must be one of {PAYEE_TYPES}")
        ccy = currency(currency_code)
        if len(digits(account_number)) < 6:
            raise PayeeError("account number looks too short")
        flags: list[str] = []
        institution_id = None
        verified = False
        if payee_type == "institution":
            entry = self.registry_lookup(display_name)
            if entry is None:
                flags.append("institution_not_in_registry")
            elif digits(entry["account_number"]) != digits(account_number):
                institution_id = entry["id"]
                flags.append("account_does_not_match_registry")
            elif entry["currency"] != ccy:
                institution_id = entry["id"]
                flags.append("currency_does_not_match_registry")
            else:
                institution_id = entry["id"]
                display_name = entry["name"]
                bank_name = entry["bank_name"]
                country = entry["country"]
                verified = True
        if verified_at is not None:  # seeding only
            verified = True
        payee_id = new_id("py")
        now = self.clock.now()
        self.conn.execute(
            "INSERT INTO payees(id, owner, display_name, payee_type, country, currency, bank_name, account_number, "
            "institution_id, linked_user_id, verified, verified_at, source, flags, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (payee_id, owner, display_name, payee_type, country, ccy, bank_name, account_number, institution_id,
             linked_user_id, int(verified), iso(verified_at or now) if verified else None, source, dumps(flags),
             iso(now)),
        )
        return self.get(owner, payee_id)

    def verify(self, owner: str, payee_id: str) -> dict:
        """User-only action (the app checks the PIN first). Starts the cooling-off clock."""
        payee = self.get(owner, payee_id, full=True)
        if payee["payee_type"] == "institution":
            raise PayeeError("institutions are verified against the registry, not manually")
        self.conn.execute(
            "UPDATE payees SET verified = 1, verified_at = ? WHERE id = ? AND owner = ?",
            (iso(self.clock.now()), payee_id, owner),
        )
        return self.get(owner, payee_id)

    def get(self, owner: str, payee_id: str, full: bool = False) -> dict:
        row = self.conn.execute("SELECT * FROM payees WHERE id = ? AND owner = ?", (payee_id, owner)).fetchone()
        if not row:
            raise PayeeError(f"no payee {payee_id} for this user")
        return self._out(row, full)

    def list(self, owner: str) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM payees WHERE owner = ? ORDER BY display_name", (owner,))
        return [self._out(r, False) for r in rows]

    @staticmethod
    def _out(row, full: bool) -> dict:
        d = dict(row)
        d["verified"] = bool(d["verified"])
        d["flags"] = loads(d["flags"]) or []
        if not full:
            d["account_number"] = mask_account(d["account_number"])
        return d
