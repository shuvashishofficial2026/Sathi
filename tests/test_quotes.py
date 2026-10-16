from decimal import Decimal

import pytest

from sathi.drafts import DraftError
from sathi.sandbox import SandboxError
from tests.conftest import payee


def test_tuition_quotes_only_offer_providers_that_can_pay_a_university(sb):
    shu = payee(sb, "nusrat", "Shenzhen Harbour")
    r = sb.get_quotes("nusrat", "BDT", "CNY", "13000", "receive", "tuition", shu["id"])
    names = [x["provider_name"] for x in r["quotes"]]
    assert names == ["CampusPay (education payments)", "Bank wire (SWIFT)"]
    assert r["quotes"][0]["recommended"] is True
    assert Decimal(r["quotes"][0]["savings_vs_bank"]) > 0
    excluded = {e["provider"] for e in r["excluded"]}
    assert "DigiSend (digital transfer)" in excluded


def test_receive_fixed_quote_delivers_exactly_the_amount(sb):
    shu = payee(sb, "nusrat", "Shenzhen Harbour")
    for x in sb.get_quotes("nusrat", "BDT", "CNY", "13000", "receive", "tuition", shu["id"])["quotes"]:
        assert Decimal(x["receive_amount"]) == Decimal("13000.00")
        delivered = Decimal(x["send_amount"]) * Decimal(x["offered_rate"]) - Decimal(x["receiver_fee"])
        assert abs(delivered - Decimal("13000")) < Decimal("0.02")


def test_allowance_quotes_are_ranked_by_total_cost(sb):
    daughter = payee(sb, "abbu", "Nusrat")
    quotes = sb.get_quotes("abbu", "BDT", "CNY", "50000", "send", "living_expenses", daughter["id"])["quotes"]
    assert [x["provider_id"] for x in quotes] == ["digisend", "quickremit", "bankwire"]
    costs = [Decimal(x["total_cost"]) for x in quotes]
    assert costs == sorted(costs)
    # The bank route costs several times the digital route (as in the World Bank's data).
    assert Decimal(quotes[-1]["total_cost_pct"]) > 3 * Decimal(quotes[0]["total_cost_pct"])


def test_conversion_mode_uses_wallet_fx_only(sb):
    quotes = sb.get_quotes("nusrat", "USD", "CNY", "100", mode="conversion")["quotes"]
    assert [x["provider_id"] for x in quotes] == ["walletfx"]


def test_quote_for_wrong_currency_payee_is_refused(sb):
    shu = payee(sb, "nusrat", "Shenzhen Harbour")
    with pytest.raises(SandboxError):
        sb.get_quotes("nusrat", "BDT", "USD", "100", payee_id=shu["id"])


def test_expired_quote_cannot_be_drafted(sb):
    daughter = payee(sb, "abbu", "Nusrat")
    q = sb.get_quotes("abbu", "BDT", "CNY", "50000", "send", "living_expenses", daughter["id"])["quotes"][0]
    sb.advance_time(hours=0.2)
    with pytest.raises(DraftError):
        sb.draft_payment("abbu", q["id"], daughter["id"], "living_expenses")


def test_quote_of_another_user_cannot_be_used(sb):
    daughter = payee(sb, "abbu", "Nusrat")
    q = sb.get_quotes("abbu", "BDT", "CNY", "50000", "send", "living_expenses", daughter["id"])["quotes"][0]
    with pytest.raises(DraftError):
        sb.draft_conversion("nusrat", q["id"])
