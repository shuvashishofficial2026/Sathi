"""Tamper-evident audit log.

Every entry stores the hash of the entry before it, so changing or deleting any
past entry breaks the chain and verify_chain() reports where. SQLite triggers
also refuse UPDATE and DELETE on the table. Sensitive values are masked before
they are written.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3

from .db import transaction
from .util import Clock, dumps, iso, loads

GENESIS = "0" * 64
SECRET_KEYS = {"pin", "token", "confirmation_token", "secret", "pin_hash"}
_DIGIT_RUN = re.compile(r"\+?\d[\d -]{7,}\d")


def mask_account(value: str) -> str:
    if (value or "").startswith("••••"):
        return value
    digits = re.sub(r"\D", "", value or "")
    return "•••• " + digits[-4:] if len(digits) > 4 else "••••"


def redact(obj):
    """Mask account numbers, phone-like digit runs and secrets."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in SECRET_KEYS:
                out[k] = "[redacted]"
            elif k == "account_number" and isinstance(v, str):
                out[k] = mask_account(v)
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return _DIGIT_RUN.sub(
            lambda m: mask_account(m.group()) if len(re.sub(r"\D", "", m.group())) >= 9 else m.group(), obj
        )
    return obj


def _entry_hash(seq: int, ts: str, actor: str, user_id: str | None, event: str, data: str, prev: str) -> str:
    material = f"{seq}|{ts}|{actor}|{user_id or ''}|{event}|{data}|{prev}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, conn: sqlite3.Connection, clock: Clock):
        self.conn = conn
        self.clock = clock

    def record(self, actor: str, event: str, data: dict | None = None, user_id: str | None = None) -> dict:
        """Append one entry. actor is one of: user, agent, system, mandate, policy."""
        data_json = dumps(redact(data or {}))
        with transaction(self.conn):
            last = self.conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq = last["seq"] + 1 if last else 1
            prev = last["hash"] if last else GENESIS
            ts = iso(self.clock.now())
            h = _entry_hash(seq, ts, actor, user_id, event, data_json, prev)
            self.conn.execute(
                "INSERT INTO audit(seq, ts, actor, user_id, event, data, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                (seq, ts, actor, user_id, event, data_json, prev, h),
            )
        return {"seq": seq, "ts": ts, "actor": actor, "user_id": user_id, "event": event, "hash": h}

    def verify_chain(self) -> dict:
        """Recompute every hash. Returns {"ok": bool, "entries": n, "first_bad_seq": int | None}."""
        prev = GENESIS
        n = 0
        for row in self.conn.execute("SELECT * FROM audit ORDER BY seq"):
            n += 1
            expected = _entry_hash(
                row["seq"], row["ts"], row["actor"], row["user_id"], row["event"], row["data"], prev
            )
            if row["prev_hash"] != prev or row["hash"] != expected or row["seq"] != n:
                return {"ok": False, "entries": n, "first_bad_seq": row["seq"]}
            prev = row["hash"]
        return {"ok": True, "entries": n, "first_bad_seq": None}

    def entries(self, user_id: str | None = None, limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM audit"
        args: tuple = ()
        if user_id:
            sql += " WHERE user_id = ? OR user_id IS NULL"
            args = (user_id,)
        sql += " ORDER BY seq DESC LIMIT ?"
        rows = self.conn.execute(sql, args + (limit,)).fetchall()
        return [{**dict(r), "data": loads(r["data"])} for r in rows]

    def export_jsonl(self, path: str) -> int:
        rows = self.conn.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(dumps({**dict(r), "data": loads(r["data"])}) + "\n")
        return len(rows)
