"""Money helpers. Amounts are always Decimal, never float."""

from __future__ import annotations

from decimal import ROUND_HALF_UP, ROUND_UP, Decimal, InvalidOperation

# Minor units per supported currency.
CURRENCIES: dict[str, int] = {"BDT": 2, "CNY": 2, "USD": 2, "MYR": 2, "GBP": 2}
ZERO = Decimal("0")


def D(value) -> Decimal:
    """Parse a number into a Decimal ("13,000" and 13000.5 both work)."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool) or value is None:
        raise ValueError(f"not a valid amount: {value!r}")
    try:
        return Decimal(str(value).replace(",", "").strip())
    except InvalidOperation as exc:
        raise ValueError(f"not a valid amount: {value!r}") from exc


def currency(code: str) -> str:
    c = (code or "").strip().upper()
    if c not in CURRENCIES:
        raise ValueError(f"unsupported currency {code!r}; supported: {', '.join(CURRENCIES)}")
    return c


def q(amount, ccy: str, rounding=ROUND_HALF_UP) -> Decimal:
    """Round to the currency's minor unit."""
    exp = Decimal(1).scaleb(-CURRENCIES[currency(ccy)])
    return D(amount).quantize(exp, rounding=rounding)


def q_up(amount, ccy: str) -> Decimal:
    return q(amount, ccy, ROUND_UP)


def rate(value) -> Decimal:
    return D(value).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)


def fmt(amount, ccy: str) -> str:
    return f"{currency(ccy)} {q(amount, ccy):,.2f}"
