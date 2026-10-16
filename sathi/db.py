"""SQLite storage for the sandbox. Ledger postings and the audit log are append-only."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, home_currency TEXT NOT NULL, country TEXT NOT NULL,
  language TEXT NOT NULL DEFAULT 'en', kyc_status TEXT NOT NULL, pin_hash TEXT NOT NULL,
  pin_failures INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, currency TEXT NOT NULL, kind TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS journals (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL, user_id TEXT,
  idempotency_key TEXT UNIQUE, memo TEXT, category TEXT, meta TEXT NOT NULL DEFAULT '{}');

CREATE TABLE IF NOT EXISTS postings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  journal_id TEXT NOT NULL REFERENCES journals(id),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  currency TEXT NOT NULL, amount TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS postings_account ON postings(account_id);

CREATE TABLE IF NOT EXISTS payees (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, display_name TEXT NOT NULL, payee_type TEXT NOT NULL,
  country TEXT, currency TEXT NOT NULL, bank_name TEXT, account_number TEXT NOT NULL,
  institution_id TEXT, linked_user_id TEXT, verified INTEGER NOT NULL DEFAULT 0, verified_at TEXT,
  source TEXT NOT NULL, flags TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, institution_id TEXT,
  status TEXT NOT NULL, valid_from TEXT, valid_until TEXT, data TEXT NOT NULL DEFAULT '{}');

CREATE TABLE IF NOT EXISTS quotes (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, data TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
  origin TEXT NOT NULL, payload TEXT NOT NULL, action_hash TEXT NOT NULL, decision TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, resolved_at TEXT, journal_id TEXT,
  mandate_id TEXT);

CREATE TABLE IF NOT EXISTS mandates (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, from_currency TEXT NOT NULL, to_currency TEXT NOT NULL,
  max_amount TEXT NOT NULL, used_amount TEXT NOT NULL DEFAULT '0', min_rate TEXT NOT NULL,
  status TEXT NOT NULL, created_at TEXT NOT NULL, signed_at TEXT, expires_at TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS budgets (
  user_id TEXT NOT NULL, category TEXT NOT NULL, currency TEXT NOT NULL, monthly_limit TEXT NOT NULL,
  PRIMARY KEY (user_id, category));

CREATE TABLE IF NOT EXISTS deadlines (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL, due_date TEXT NOT NULL,
  amount TEXT NOT NULL, currency TEXT NOT NULL, payee_id TEXT, purpose TEXT,
  status TEXT NOT NULL DEFAULT 'open');

CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, user_id TEXT, event TEXT NOT NULL,
  data TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS postings_no_update BEFORE UPDATE ON postings
  BEGIN SELECT RAISE(ABORT, 'ledger postings are immutable'); END;
CREATE TRIGGER IF NOT EXISTS postings_no_delete BEFORE DELETE ON postings
  BEGIN SELECT RAISE(ABORT, 'ledger postings are immutable'); END;
"""


def connect(path: str = ":memory:") -> sqlite3.Connection:
    # Autocommit mode; transactions are opened explicitly with transaction().
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Atomic block. Nested calls join the outer transaction."""
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
