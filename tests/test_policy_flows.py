from decimal import Decimal

import pytest

from sathi.actions import action_card
from sathi.executor import ExecutionError
from sathi.sandbox import SandboxError
from tests.conftest import ABBU_PIN, NUSRAT_PIN, best_quote, pay, payee


def reasons(action):
    return " | ".join(action["card"]["reasons"])


# ---------- T1: tuition ----------

def test_tuition_payment_end_to_end_with_step_up(sb):
    a = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "13000", "tuition", amount_type="receive",
            reference="MSc CS spring 2027")
    assert a["status"] == "awaiting_confirmation"
    assert a["card"]["needs_pin"] is True
    assert "First payment to this payee" in reasons(a)
    assert any("Student file SF-2026-0417" in c for c in a["card"]["checks_passed"])

    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", a["id"])
    assert e.value.code == "step_up_required"
    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", a["id"], pin="0000")
    assert e.value.code == "wrong_pin"

    receipt = sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN)
    shu = payee(sb, "nusrat", "Shenzhen Harbour")
    assert sb.ledger.balance(f"external:{shu['id']}:CNY") == Decimal("13000.00")
    assert sb.actions.get(a["id"])["status"] == "executed"
    assert receipt["journal_id"]

    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN)
    assert e.value.code == "not_pending"


def test_forged_confirmation_token_is_refused(sb):
    a = pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    with pytest.raises(ExecutionError) as e:
        sb.executor.confirm("abbu", a["id"], token="0" * 64)
    assert e.value.code == "bad_token"
    assert sb.actions.get(a["id"])["status"] == "awaiting_confirmation"


def test_another_users_action_cannot_be_confirmed(sb):
    a = pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", a["id"])
    assert e.value.code == "not_found"


def test_pin_locks_after_three_wrong_attempts(sb):
    a = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "13000", "tuition", amount_type="receive")
    for _ in range(3):
        with pytest.raises(ExecutionError):
            sb.confirm("nusrat", a["id"], pin="1111")
    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN)
    assert e.value.code == "pin_locked"


def test_tuition_beyond_the_student_file_estimate_is_denied(sb):
    first = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "13000", "tuition", amount_type="receive")
    sb.confirm("nusrat", first["id"], pin=NUSRAT_PIN)
    second = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "14000", "tuition", amount_type="receive")
    assert second["status"] == "blocked"
    assert "Exceeds the student file's approved tuition estimate" in reasons(second)


def test_tuition_to_an_institution_without_a_student_file_is_denied(sb):
    kllu = sb.add_payee("nusrat", "KL Lakeside University", "institution", "MYR", "5140 1234 5678 90")
    assert kllu["verified"] is True  # matches the registry
    q = best_quote(sb, "nusrat", "BDT", "MYR", "5000", "receive", "tuition", kllu["id"])
    a = sb.draft_payment("nusrat", q["id"], kllu["id"], "tuition")
    assert a["status"] == "blocked"
    assert "active student file for this institution" in reasons(a)


# ---------- T2: allowance from Abbu ----------

def test_allowance_from_father_needs_only_a_tap_and_reaches_daughter(sb):
    before = sb.ledger.balances("nusrat")["CNY"]
    a = pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    assert a["status"] == "awaiting_confirmation"
    assert a["card"]["needs_pin"] is False
    assert a["payload"]["provider_id"] == "digisend"
    sb.confirm("abbu", a["id"])
    after = sb.ledger.balances("nusrat")["CNY"]
    assert after - before == Decimal(a["payload"]["receive_amount"])


# ---------- payee safety ----------

def test_unverified_payee_is_blocked_then_cooling_off_then_allowed(sb):
    a = pay(sb, "nusrat", "Tanvir", "CNY", "200", "personal")
    assert a["status"] == "blocked"
    assert "isn't verified" in reasons(a)

    tanvir = payee(sb, "nusrat", "Tanvir")
    sb.verify_payee("nusrat", tanvir["id"], NUSRAT_PIN)
    a = pay(sb, "nusrat", "Tanvir", "CNY", "200", "personal")
    assert a["status"] == "blocked"
    assert "cooling-off" in reasons(a)

    sb.advance_time(hours=25)
    a = pay(sb, "nusrat", "Tanvir", "CNY", "200", "personal")
    assert a["status"] == "awaiting_confirmation"
    sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN)  # first payment to Tanvir -> PIN


def test_swapped_university_bank_details_are_flagged_as_fraud(sb):
    fake = sb.add_payee("nusrat", "Shenzhen Harbour University", "institution", "CNY", "6222 9999 8888 7777 666")
    assert fake["verified"] is False
    assert "account_does_not_match_registry" in fake["flags"]
    q = best_quote(sb, "nusrat", "BDT", "CNY", "13000", "receive", "tuition", fake["id"])
    a = sb.draft_payment("nusrat", q["id"], fake["id"], "tuition")
    assert a["status"] == "blocked"
    assert "does NOT match the institution's verified account" in reasons(a)


def test_agent_cannot_verify_a_payee_without_the_pin(sb):
    tanvir = payee(sb, "nusrat", "Tanvir")
    with pytest.raises(SandboxError, match="Wrong PIN"):
        sb.verify_payee("nusrat", tanvir["id"], "9999")
    assert payee(sb, "nusrat", "Tanvir")["verified"] is False


def test_sanctioned_payee_is_blocked(sb):
    p = sb.add_payee("nusrat", "Viktor Sanctionov", "person", "CNY", "6200 1234 5678 9012")
    sb.verify_payee("nusrat", p["id"], NUSRAT_PIN)
    sb.advance_time(hours=25)
    q = best_quote(sb, "nusrat", "CNY", "CNY", "100", "send", "personal", p["id"])
    a = sb.draft_payment("nusrat", q["id"], p["id"], "personal")
    assert a["status"] == "blocked"
    assert "sanctions watchlist" in reasons(a)


# ---------- limits and patterns ----------

def test_daily_limit_stops_the_third_large_payment(sb):
    for _ in range(2):
        a = pay(sb, "abbu", "Nusrat", "BDT", "290000", "family_support")
        assert a["card"]["needs_pin"]  # far above his usual allowance
        sb.confirm("abbu", a["id"], pin=ABBU_PIN)
    a = pay(sb, "abbu", "Nusrat", "BDT", "290000", "family_support")
    assert a["status"] == "blocked"
    assert "today's limit" in reasons(a)


def test_above_per_payment_limit_needs_pin_and_hard_max_is_denied(sb):
    a = pay(sb, "abbu", "Nusrat", "BDT", "320000", "family_support")
    assert "per-payment limit" in reasons(a)
    assert a["card"]["needs_pin"]
    sb.ledger.post(kind="opening", user_id="abbu", legs=[
        (sb.ledger.account("funding", "seed", "BDT"), Decimal("-2000000")),
        (sb.ledger.wallet("abbu", "BDT"), Decimal("2000000"))])
    big = best_quote(sb, "abbu", "BDT", "CNY", "1300000", "send", "family_support",
                     payee(sb, "abbu", "Nusrat")["id"])
    a = sb.draft_payment("abbu", big["id"], payee(sb, "abbu", "Nusrat")["id"], "family_support")
    assert a["status"] == "blocked"
    assert "maximum single payment" in reasons(a)


def test_many_payments_in_a_few_minutes_trigger_step_up(sb):
    for _ in range(3):
        a = pay(sb, "nusrat", "Li Wei", "CNY", "100", "rent")
        sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN if a["card"]["needs_pin"] else None)
        sb.advance_time(minutes=1)
    a = pay(sb, "nusrat", "Li Wei", "CNY", "100", "rent")
    assert "payments in the last 10 minutes" in reasons(a)
    assert a["card"]["needs_pin"]


def test_splitting_a_payment_does_not_dodge_the_pin(sb):
    # Rent to Li Wei is usually CNY 2,000. One CNY 5,000 payment is about 2.5x that; two in a day are about 5x.
    first = pay(sb, "nusrat", "Li Wei", "BDT", "5000", "rent", amount_type="receive")
    second = pay(sb, "nusrat", "Li Wei", "BDT", "5000", "rent", amount_type="receive")
    assert not first["card"]["needs_pin"] and not second["card"]["needs_pin"]
    sb.confirm("nusrat", first["id"])
    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", second["id"])
    assert e.value.code == "step_up_required"
    card = action_card(sb.actions.get(second["id"]))
    assert card["needs_pin"]  # the card now asks for the PIN and says why
    assert "other payments to this payee in the last 24 hours" in " ".join(card["reasons"])
    sb.confirm("nusrat", second["id"], pin=NUSRAT_PIN)
    assert sb.actions.get(second["id"])["status"] == "executed"


def test_a_pin_the_card_asked_for_is_still_needed_after_the_trigger_passes(sb):
    for _ in range(3):
        a = pay(sb, "nusrat", "Li Wei", "CNY", "100", "rent")
        sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN if a["card"]["needs_pin"] else None)
        sb.advance_time(minutes=1)
    a = pay(sb, "nusrat", "Li Wei", "CNY", "100", "rent")
    assert a["card"]["needs_pin"]  # 3 payments in 10 minutes
    sb.advance_time(minutes=8)  # the burst has left the window, and the draft is still valid
    assert sb.policy.evaluate(a["payload"]).outcome == "allow"
    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", a["id"])
    assert e.value.code == "step_up_required"
    sb.confirm("nusrat", a["id"], pin=NUSRAT_PIN)


def test_missing_purpose_is_denied(sb):
    li = payee(sb, "nusrat", "Li Wei")
    q = best_quote(sb, "nusrat", "CNY", "CNY", "100", "send", None, li["id"])
    a = sb.draft_payment("nusrat", q["id"], li["id"], "gift")
    assert a["status"] == "blocked"
    assert "purpose is required" in reasons(a)


def test_insufficient_balance_is_denied(sb):
    a = pay(sb, "nusrat", "Li Wei", "CNY", "5000", "rent")
    assert a["status"] == "blocked"
    assert "Not enough CNY" in reasons(a)


def test_policy_is_rechecked_at_execution(sb):
    first = pay(sb, "nusrat", "Li Wei", "CNY", "1000", "rent")
    second = pay(sb, "nusrat", "Li Wei", "CNY", "1000", "rent")
    assert first["status"] == second["status"] == "awaiting_confirmation"
    sb.confirm("nusrat", first["id"])
    with pytest.raises(ExecutionError) as e:
        sb.confirm("nusrat", second["id"])
    assert e.value.code == "policy_denied"
    assert sb.actions.get(second["id"])["status"] == "blocked"


def test_drafts_expire(sb):
    a = pay(sb, "abbu", "Nusrat", "BDT", "50000", "living_expenses")
    sb.advance_time(minutes=11)
    with pytest.raises(ExecutionError) as e:
        sb.confirm("abbu", a["id"])
    assert e.value.code == "expired"


# ---------- untrusted content ----------

def test_after_a_high_risk_message_payments_to_people_are_quarantined(sb):
    a = pay(sb, "nusrat", "Li Wei", "CNY", "100", "rent", origin="document", risk_score=85)
    assert a["status"] == "blocked"
    assert "scam risk 85/100" in reasons(a)


def test_after_a_high_risk_message_the_real_university_can_still_be_paid_with_pin(sb):
    a = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "13000", "tuition", amount_type="receive",
            origin="document", risk_score=85)
    assert a["status"] == "awaiting_confirmation"
    assert a["card"]["needs_pin"]
    assert "Prepared after reading a forwarded message" in reasons(a)


def test_payment_drafted_after_a_low_risk_message_still_needs_pin(sb):
    a = pay(sb, "nusrat", "Li Wei", "CNY", "100", "rent", origin="document", risk_score=10)
    assert a["status"] == "awaiting_confirmation"
    assert a["card"]["needs_pin"]
    assert "Prepared after reading a forwarded message" in reasons(a)
