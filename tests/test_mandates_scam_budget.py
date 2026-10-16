from decimal import Decimal

import pytest

from sathi.executor import ExecutionError
from sathi.mandates import MandateError
from tests.conftest import NUSRAT_PIN, best_quote, pay

# ---------- T3: mandates ----------

def test_mandate_waits_for_the_rate_then_executes_on_its_own(sb):
    m = sb.propose_mandate("nusrat", "USD", "CNY", "300", "7.15", days_valid=14)
    assert m["status"] == "proposed"
    assert sb.market_tick("0")["mandate_events"] == []  # not signed yet: nothing happens

    with pytest.raises(MandateError):
        sb.sign_mandate("nusrat", m["id"], "0000")
    sb.sign_mandate("nusrat", m["id"], NUSRAT_PIN)

    events = sb.set_rate("CNY", "7.12")["mandate_events"]  # offered ~7.095 < 7.15
    assert events[0]["event"] == "waiting"
    assert sb.ledger.balances("nusrat")["USD"] == Decimal("450.00")

    events = sb.set_rate("CNY", "7.25")["mandate_events"]  # offered ~7.2246 >= 7.15
    assert events[0]["event"] == "executed"
    assert sb.ledger.balances("nusrat")["USD"] == Decimal("150.00")
    assert sb.mandates.get(m["id"])["status"] == "completed"
    assert any(e["event"] == "mandate.executed" and e["actor"] == "mandate" for e in sb.audit.entries())


def test_mandate_caps_are_enforced(sb):
    with pytest.raises(MandateError):
        sb.propose_mandate("nusrat", "BDT", "CNY", "400000", "0.05")  # about USD 3,270 > cap
    with pytest.raises(MandateError):
        sb.propose_mandate("nusrat", "USD", "CNY", "100", "7.1", days_valid=90)
    with pytest.raises(MandateError):
        sb.propose_mandate("nusrat", "USD", "USD", "100", "1")


def test_revoked_or_expired_mandates_do_nothing(sb):
    m = sb.propose_mandate("nusrat", "USD", "CNY", "100", "7.0")
    sb.sign_mandate("nusrat", m["id"], NUSRAT_PIN)
    sb.revoke_mandate("nusrat", m["id"])
    assert sb.set_rate("CNY", "7.5")["mandate_events"] == []

    m2 = sb.propose_mandate("nusrat", "USD", "CNY", "100", "7.6", days_valid=2)
    sb.sign_mandate("nusrat", m2["id"], NUSRAT_PIN)
    sb.advance_time(days=3)
    events = sb.set_rate("CNY", "7.9")["mandate_events"]
    assert events == [{"mandate_id": m2["id"], "user_id": "nusrat", "event": "expired"}]
    assert sb.ledger.balances("nusrat")["USD"] == Decimal("450.00")


def test_executor_refuses_an_action_outside_the_mandate(sb):
    m = sb.propose_mandate("nusrat", "USD", "CNY", "50", "7.0")
    sb.sign_mandate("nusrat", m["id"], NUSRAT_PIN)
    q = best_quote(sb, "nusrat", "USD", "CNY", "200", mode="conversion")  # more than the mandate allows
    a = sb.drafts.conversion("nusrat", q["id"], origin="mandate", mandate_id=m["id"])
    with pytest.raises(ExecutionError) as e:
        sb.executor.execute_mandated(a["id"], sb.mandates.get(m["id"]))
    assert e.value.code == "mandate_scope"


# ---------- T4: scam shield ----------

SCAM = """Dear student, URGENT: the bank details of Shenzhen Harbour University have changed.
Pay your spring tuition today only to our agent's account 6222 4444 5555 6666 777 and get a 20% discount.
Contact us on WhatsApp. Please don't contact the university office, it is busy."""


def test_classic_tuition_scam_scores_high(sb):
    r = sb.analyze_message("nusrat", SCAM)
    ids = {f["id"] for f in r["flags"]}
    assert r["risk_level"] == "high" and r["risk_score"] >= 60
    assert {"account_mismatch", "discount_offer", "urgency", "off_channel", "secrecy"} <= ids
    assert r["registry_checks"][0]["result"] == "does_not_match_verified_account"
    assert "6222 4444" not in str(r)  # account numbers are masked


def test_genuine_invoice_with_the_verified_account_scores_low(sb):
    text = ("Shenzhen Harbour University - spring tuition invoice. Amount CNY 13,000. "
            "Pay to account 6222 0202 0011 2233 445 at Demo Bank of Shenzhen before 1 March.")
    r = sb.analyze_message("nusrat", text)
    assert r["risk_level"] == "low"
    assert r["registry_checks"][0]["result"] == "matches_verified_account"


def test_bangla_red_flags_are_detected(sb):
    r = sb.analyze_message("abbu", "জরুরি! আজকেই টাকা পাঠান, ৩০% ডিসকাউন্ট পাবেন। OTP টা আমাকে দিন")
    ids = {f["id"] for f in r["flags"]}
    assert {"urgency", "discount_offer", "credentials"} <= ids
    assert r["risk_level"] == "high"


# ---------- T5: budget and runway ----------

def test_runway_sets_aside_tuition_and_reports_months(sb):
    r = sb.runway("nusrat")
    assert r["covers_upcoming_deadlines"] is True
    assert r["upcoming_deadlines"][0]["title"] == "Spring semester tuition"
    assert Decimal(r["reserved_for_deadlines"]) > 0
    assert Decimal("5") < Decimal(r["months_if_income_stops"]) < Decimal("8")


def test_budget_summary_and_update(sb):
    s = sb.budget_summary("nusrat")
    food = next(c for c in s["categories"] if c["category"] == "food")
    assert Decimal(food["spent"]) == Decimal("378.10")
    sb.set_budget("nusrat", "Food", "1500", "CNY")
    food = next(c for c in sb.budget_summary("nusrat")["categories"] if c["category"] == "food")
    assert food["limit"] == "1500.00"


def test_deadlines_list_days_left(sb):
    sb.add_deadline("nusrat", "Health insurance", "2026-11-01", "800", "CNY")
    titles = [d["title"] for d in sb.deadlines("nusrat")]
    assert titles == ["Health insurance", "Spring semester tuition"]
    assert sb.deadlines("nusrat")[0]["days_left"] == 20


def test_paying_tuition_closes_the_deadline_and_frees_the_reserve(sb):
    assert [d["title"] for d in sb.deadlines("nusrat")] == ["Spring semester tuition"]
    draft = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "13000", "tuition", amount_type="receive")
    receipt = sb.confirm("nusrat", draft["id"], NUSRAT_PIN)
    assert receipt["deadline_paid"] == "Spring semester tuition"
    assert sb.deadlines("nusrat") == []
    assert sb.runway("nusrat")["reserved_for_deadlines"] == "0.00"
    assert any(e["event"] == "deadline.paid" for e in sb.audit.entries("nusrat"))


def test_a_smaller_payment_leaves_the_deadline_open(sb):
    draft = pay(sb, "nusrat", "Shenzhen Harbour", "BDT", "5000", "tuition", amount_type="receive")
    receipt = sb.confirm("nusrat", draft["id"], NUSRAT_PIN)
    assert "deadline_paid" not in receipt
    assert len(sb.deadlines("nusrat")) == 1


def test_pin_phishing_is_flagged(sb):
    report = sb.analyze_message("nusrat", "Sathi Security Team: unusual login. Reply with your 4-digit PIN within "
                                          "10 minutes or your account will be closed.")
    assert "credentials" in [f["id"] for f in report["flags"]]
    assert report["risk_score"] >= 30

