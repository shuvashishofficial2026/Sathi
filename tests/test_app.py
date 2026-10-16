"""Streamlit UI tests: the app runs headless with the offline demo script (no API key, no browser)."""

from decimal import Decimal
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from tests.test_mandates_scam_budget import SCAM

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def start(monkeypatch, llm: str | None = "scripted-demo") -> AppTest:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    if llm:
        monkeypatch.setenv("SATHI_LLM", llm)
    else:
        monkeypatch.delenv("SATHI_LLM", raising=False)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    return at


def button(at: AppTest, label: str):
    return next(b for b in at.button if b.label == label)


def wallet(at: AppTest, user: str) -> dict:
    return {c: Decimal(v) for c, v in at.session_state["sb"].ledger.balances(user).items()}


def test_app_works_without_an_api_key(monkeypatch):
    at = start(monkeypatch, llm=None)
    assert any("API key" in i.value for i in at.info)
    assert at.chat_input[0].disabled
    assert any("Audit chain intact" in c.value for c in at.caption)


def test_tuition_needs_the_pin_and_then_pays(monkeypatch):
    at = start(monkeypatch)
    before = wallet(at, "nusrat")
    at.button(key="suggest_nusrat_0").click().run()
    sb = at.session_state["sb"]
    [draft] = sb.pending("nusrat")
    assert draft["card"]["needs_pin"]
    assert wallet(at, "nusrat") == before  # the AI only prepared it

    at.text_input(key=f"pin_c1_{draft['id']}").input("1111")
    at.button(key=f"ok_c1_{draft['id']}").click().run()
    assert any("Wrong PIN" in e.value for e in at.error)
    assert sb.actions.get(draft["id"])["status"] == "awaiting_confirmation"

    at.text_input(key=f"pin_c1_{draft['id']}").input("2468")
    at.button(key=f"ok_c1_{draft['id']}").click().run()
    assert not at.exception
    assert sb.actions.get(draft["id"])["status"] == "executed"
    assert wallet(at, "nusrat")["BDT"] == before["BDT"] - Decimal(draft["payload"]["total_debit"])
    assert any("Done: Pay Shenzhen Harbour University" in s.value for s in at.success)


def test_fathers_allowance_lands_in_daughters_wallet(monkeypatch):
    at = start(monkeypatch)
    at.sidebar.radio[0].set_value("abbu").run()
    nusrat_before = wallet(at, "nusrat")
    at.chat_input[0].set_value("মেয়েকে এই মাসের হাতখরচ ৫০,০০০ টাকা পাঠাও").run()
    sb = at.session_state["sb"]
    [draft] = sb.pending("abbu")
    assert draft["card"]["title"] == "Pay Nusrat (daughter)"
    assert any(b.label == "নিশ্চিত করুন" for b in at.button)
    if draft["card"]["needs_pin"]:
        at.text_input(key=f"pin_c1_{draft['id']}").input("1357")
    at.button(key=f"ok_c1_{draft['id']}").click().run()
    assert sb.actions.get(draft["id"])["status"] == "executed"
    received = Decimal(draft["payload"]["receive_amount"])
    assert wallet(at, "nusrat")["CNY"] == nusrat_before["CNY"] + received


def test_a_card_asks_for_the_pin_when_it_becomes_needed(monkeypatch):
    at = start(monkeypatch)
    sb = at.session_state["sb"]
    li = next(p for p in sb.list_payees("nusrat") if p["display_name"].startswith("Li Wei"))
    drafts = []
    for _ in range(2):  # a split payment: each half looks normal on its own
        quote = sb.get_quotes("nusrat", "BDT", "CNY", "5000", "receive", "rent", li["id"])["quotes"][0]
        drafts.append(sb.draft_payment("nusrat", quote["id"], li["id"], "rent"))
    at.run()
    first, second = (d["id"] for d in drafts)
    assert f"pin_a_{second}" not in [w.key for w in at.text_input]
    at.button(key=f"ok_a_{first}").click().run()
    assert sb.actions.get(first)["status"] == "executed"
    at.button(key=f"ok_a_{second}").click().run()
    assert not at.exception
    assert sb.actions.get(second)["status"] == "awaiting_confirmation"
    assert any("other payments to this payee" in w.value for w in at.warning)
    at.text_input(key=f"pin_a_{second}").input("2468")
    at.button(key=f"ok_a_{second}").click().run()
    assert sb.actions.get(second)["status"] == "executed"


def test_signed_mandate_converts_on_its_own_when_the_rate_is_met(monkeypatch):
    at = start(monkeypatch)
    sb = at.session_state["sb"]
    m = sb.propose_mandate("nusrat", "USD", "CNY", "300", "7.15", 14)  # what the agent's tool would do
    at.run()
    at.text_input(key=f"mpin_a_{m['id']}").input("2468")
    at.button(key=f"msign_a_{m['id']}").click().run()
    assert sb.mandates.get(m["id"])["status"] == "active"

    before = wallet(at, "nusrat")
    at.sidebar.number_input[0].set_value(7.40).run()
    button(at, "Apply rate").click().run()
    assert not at.exception
    assert any("mandate ran on its own" in s.value for s in at.success)
    after = wallet(at, "nusrat")
    assert after["USD"] < before["USD"] and after["CNY"] > before["CNY"]


def test_scam_check_flags_a_fake_invoice(monkeypatch):
    at = start(monkeypatch)
    at.text_area(key="scam_text").input(SCAM)
    button(at, "Check it").click().run()
    assert any("Scam risk" in e.value and "(high)" in e.value for e in at.error)
    assert any("account mismatch" in m.value for m in at.markdown)


@pytest.mark.parametrize("user", ["nusrat", "abbu"])
def test_every_tab_renders_for_both_users(monkeypatch, user):
    at = start(monkeypatch)
    at.sidebar.radio[0].set_value(user).run()
    assert not at.exception
    assert any("Hash chain verified" in s.value for s in at.success)
    assert len(at.dataframe) == 2  # transactions and audit log
