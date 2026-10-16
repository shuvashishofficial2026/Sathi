"""Sandbox users, simulated KYC status and PIN checks (used for step-up approval)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3

from .audit import AuditLog
from .money import currency
from .util import Clock, iso

MAX_PIN_FAILURES = 3


class PinLocked(Exception):
    pass


def hash_pin(pin: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", str(pin).encode(), salt.encode(), 100_000)
    return f"{salt}${digest.hex()}"


class Users:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, audit: AuditLog):
        self.conn = conn
        self.clock = clock
        self.audit = audit

    def create(self, user_id: str, name: str, home_currency: str, country: str, pin: str,
               language: str = "en", kyc_status: str = "verified") -> dict:
        self.conn.execute(
            "INSERT INTO users(id, name, home_currency, country, language, kyc_status, pin_hash, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (user_id, name, currency(home_currency), country, language, kyc_status, hash_pin(pin),
             iso(self.clock.now())),
        )
        return self.get(user_id)

    def get(self, user_id: str) -> dict:
        row = self.conn.execute(
            "SELECT id, name, home_currency, country, language, kyc_status, pin_failures FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            raise KeyError(f"unknown user {user_id}")
        return dict(row)

    def list(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT id, name, language FROM users ORDER BY id")]

    def matches_pin(self, user_id: str, candidate: str) -> bool:
        """Is this the user's PIN? Used only to scrub a PIN typed into chat, so it doesn't count failures."""
        row = self.conn.execute("SELECT pin_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return False
        salt = row["pin_hash"].split("$", 1)[0]
        return hmac.compare_digest(hash_pin(str(candidate), salt), row["pin_hash"])

    def check_pin(self, user_id: str, pin: str | None) -> bool:
        """True if the PIN is right. Three wrong attempts lock step-up approval."""
        row = self.conn.execute("SELECT pin_hash, pin_failures FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown user {user_id}")
        if row["pin_failures"] >= MAX_PIN_FAILURES:
            raise PinLocked("PIN locked after too many wrong attempts")
        salt = row["pin_hash"].split("$", 1)[0]
        ok = pin is not None and hmac.compare_digest(hash_pin(str(pin), salt), row["pin_hash"])
        if ok:
            self.conn.execute("UPDATE users SET pin_failures = 0 WHERE id = ?", (user_id,))
        else:
            self.conn.execute("UPDATE users SET pin_failures = pin_failures + 1 WHERE id = ?", (user_id,))
            self.audit.record("user", "pin.failed", {"failures": row["pin_failures"] + 1}, user_id)
        return ok
