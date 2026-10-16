import sqlite3
from decimal import Decimal

import pytest

from sathi.audit import redact
from sathi.ledger import DuplicateRequest, InsufficientFunds, LedgerError
from sathi.money import D, q
from tests.conftest import pay


def test_money_parsing_and_rounding():
    assert D("13,000") == Decimal("13000")
    assert D(12.5) == Decimal("12.5")
    assert q("1.005", "USD") == Decimal("1.01")
    for bad in ("abc", None, True):
        with pytest.raises(ValueError):
            D(bad)


def test_unbalanced_journal_is_rejected(sb):
    L = sb.ledger
    with pytest.raises(LedgerError):
        L.post(kind="test", user_id="nusrat", legs=[(L.wallet("nusrat", "USD"), D("-10")),
                                                    (L.account("external", "x", "USD"), D("9"))])


def test_overdraft_is_rejected_and_rolled_back(sb):
    L = sb.ledger
    before = L.balances("nusrat")["USD"]
    count = sb.conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0]
    with pytest.raises(InsufficientFunds):
        L.post(kind="test", user_id="nusrat", legs=[(L.wallet("nusrat", "USD"), D("-5000")),
                                                    (L.account("external", "x", "USD"), D("5000"))])
    assert L.balances("nusrat")["USD"] == before
    assert sb.conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0] == count


def test_idempotency_key_prevents_double_posting(sb):
    L = sb.ledger
    legs = [(L.wallet("nusrat", "USD"), D("-10")), (L.account("external", "x", "USD"), D("10"))]
    L.post(kind="test", user_id="nusrat", legs=legs, idempotency_key="same-request")
    with pytest.raises(DuplicateRequest):
        L.post(kind="test", user_id="nusrat", legs=legs, idempotency_key="same-request")
    assert L.balances("nusrat")["USD"] == Decimal("440.00")


def test_postings_are_immutable(sb):
    with pytest.raises(sqlite3.DatabaseError):
        sb.conn.execute("UPDATE postings SET amount = '999999' WHERE id = 1")
    with pytest.raises(sqlite3.DatabaseError):
        sb.conn.execute("DELETE FROM postings WHERE id = 1")


def test_every_journal_balances_per_currency(sb):
    pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    rows = sb.conn.execute("SELECT journal_id, currency, amount FROM postings").fetchall()
    totals = {}
    for r in rows:
        key = (r["journal_id"], r["currency"])
        totals[key] = totals.get(key, Decimal(0)) + Decimal(r["amount"])
    assert all(v == 0 for v in totals.values())


def test_audit_chain_verifies_and_is_append_only(sb):
    a = pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    sb.confirm("abbu", a["id"])
    assert sb.audit.verify_chain()["ok"]
    with pytest.raises(sqlite3.DatabaseError):
        sb.conn.execute("UPDATE audit SET data = '{}' WHERE seq = 1")
    with pytest.raises(sqlite3.DatabaseError):
        sb.conn.execute("DELETE FROM audit WHERE seq = 1")


def test_audit_detects_tampering_even_without_triggers(sb):
    a = pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    sb.confirm("abbu", a["id"])
    # An attacker with raw database access drops the protection and edits history.
    sb.conn.execute("DROP TRIGGER audit_no_update")
    sb.conn.execute("""UPDATE audit SET data = '{"summary":"nothing happened"}' WHERE event = 'action.executed'""")
    result = sb.audit.verify_chain()
    seq = sb.conn.execute("SELECT seq FROM audit WHERE event = 'action.executed'").fetchone()[0]
    assert result == {"ok": False, "entries": seq, "first_bad_seq": seq}


def test_audit_masks_account_numbers_and_secrets(sb):
    sb.add_payee("nusrat", "Some Shop", "business", "CNY", "6222 1111 2222 3333 444")
    entry = sb.audit.entries(limit=1)[0]
    assert entry["event"] == "payee.added"
    assert entry["data"]["account_number"] == "•••• 3444"
    assert "6222 1111" not in str(entry)
    assert redact({"pin": "2468", "note": "call +880 1712 345678"}) == {
        "pin": "[redacted]", "note": "call •••• 5678"}
