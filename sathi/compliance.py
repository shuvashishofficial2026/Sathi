"""Compliance documents on record (simulated), e.g. a Bangladeshi student file.

Bangladeshi students paying tuition and living costs abroad do it through a
"student file" at an authorized dealer bank, opened with the admission letter
and the institution's cost estimate. Here the file is a record with a validity
window and an annual estimate per purpose, which the policy engine enforces.
"""

from __future__ import annotations

import sqlite3

from .util import Clock, dumps, iso, loads, new_id, parse_dt


class Documents:
    def __init__(self, conn: sqlite3.Connection, clock: Clock):
        self.conn = conn
        self.clock = clock

    def add(self, user_id: str, kind: str, status: str = "active", institution_id: str | None = None,
            valid_from=None, valid_until=None, data: dict | None = None) -> dict:
        doc_id = new_id("doc")
        self.conn.execute(
            "INSERT INTO documents(id, user_id, kind, institution_id, status, valid_from, valid_until, data) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (doc_id, user_id, kind, institution_id, status, iso(valid_from) if valid_from else None,
             iso(valid_until) if valid_until else None, dumps(data or {})),
        )
        return self.get(doc_id)

    def get(self, doc_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not row:
            raise KeyError(doc_id)
        return {**dict(row), "data": loads(row["data"])}

    def list(self, user_id: str) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM documents WHERE user_id = ? ORDER BY kind", (user_id,))
        return [{**dict(r), "data": loads(r["data"])} for r in rows]

    def student_file(self, student_user_id: str, institution_id: str | None = None) -> dict | None:
        """The student's active, in-date student file (for that institution, if given)."""
        now = self.clock.now()
        for doc in self.list(student_user_id):
            if doc["kind"] != "student_file" or doc["status"] != "active":
                continue
            if doc["valid_from"] and parse_dt(doc["valid_from"]) > now:
                continue
            if doc["valid_until"] and parse_dt(doc["valid_until"]) < now:
                continue
            if institution_id and doc["institution_id"] != institution_id:
                continue
            return doc
        return None
