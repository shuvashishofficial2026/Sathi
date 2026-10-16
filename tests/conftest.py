from datetime import UTC, datetime

import pytest

from sathi import Sandbox
from sathi.util import Clock

NOW = datetime(2026, 10, 12, 3, 0, tzinfo=UTC)
NUSRAT_PIN, ABBU_PIN = "2468", "1357"


@pytest.fixture
def sb():
    return Sandbox(clock=Clock(NOW, frozen=True), rng_seed=1)


def payee(sb, user_id, prefix):
    return next(p for p in sb.list_payees(user_id) if p["display_name"].startswith(prefix))


def best_quote(sb, user_id, from_ccy, to_ccy, amount, amount_type="send", purpose=None, payee_id=None,
               mode="payment"):
    quotes = sb.get_quotes(user_id, from_ccy, to_ccy, amount, amount_type, purpose, payee_id, mode)["quotes"]
    assert quotes, "expected at least one quote"
    return quotes[0]


def pay(sb, user_id, payee_prefix, from_ccy, amount, purpose, amount_type="send", **kw):
    """Quote and draft a payment to a payee; returns the draft action."""
    p = payee(sb, user_id, payee_prefix)
    q = best_quote(sb, user_id, from_ccy, p["currency"], amount, amount_type, purpose, p["id"])
    return sb.draft_payment(user_id, q["id"], p["id"], purpose, **kw)
