"""Exchange rates and transfer quotes.

Rates and providers are simulated. Provider fee models are archetypes (bank
wire, money transfer operator, digital service, education payment platform),
not real companies. Every quote shows its full cost against the mid-market
rate, so routes can be compared honestly.
"""

from __future__ import annotations

import json
import random
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from .money import D, currency, q, q_up, rate
from .util import Clock, dumps, iso, loads, new_id


class QuoteError(Exception):
    pass


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    kind: str  # bank | mto | digital | edu | wallet_fx | local
    fixed_fee_usd: Decimal
    pct_fee: Decimal  # fraction of the send amount
    fx_margin: Decimal  # fraction below the mid-market rate
    receiver_fee_usd: Decimal  # deducted from what arrives (e.g. correspondent bank fees)
    eta_hours: int
    min_usd: Decimal
    max_usd: Decimal
    cross_border: bool
    same_currency: bool
    conversion_only: bool
    purposes: tuple[str, ...] | None
    payee_types: tuple[str, ...] | None
    note: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Provider:
        return cls(
            id=d["id"], name=d["name"], kind=d["kind"],
            fixed_fee_usd=D(d.get("fixed_fee_usd", 0)), pct_fee=D(d.get("pct_fee", 0)),
            fx_margin=D(d.get("fx_margin", 0)), receiver_fee_usd=D(d.get("receiver_fee_usd", 0)),
            eta_hours=int(d.get("eta_hours", 24)),
            min_usd=D(d.get("min_usd", 0)), max_usd=D(d.get("max_usd", 1_000_000)),
            cross_border=bool(d.get("cross_border", True)), same_currency=bool(d.get("same_currency", False)),
            conversion_only=bool(d.get("conversion_only", False)),
            purposes=tuple(d["purposes"]) if d.get("purposes") else None,
            payee_types=tuple(d["payee_types"]) if d.get("payee_types") else None,
            note=d.get("note", ""),
        )


def load_providers(path: str | Path) -> list[Provider]:
    return [Provider.from_dict(p) for p in json.loads(Path(path).read_text(encoding="utf-8"))["providers"]]


class RateFeed:
    """Mid-market rates, held as units of each currency per 1 USD."""

    def __init__(self, usd_rates: dict, as_of: str, source: str = "", seed: int | None = None):
        self._usd = {currency(c): D(v) for c, v in usd_rates.items()}
        self._usd["USD"] = Decimal(1)
        self.as_of = as_of
        self.source = source
        self._rng = random.Random(seed)

    @classmethod
    def from_file(cls, path: str | Path, seed: int | None = None) -> RateFeed:
        snap = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(snap["usd_rates"], snap["as_of"], snap.get("source", ""), seed)

    def mid(self, base: str, quote: str) -> Decimal:
        """Units of `quote` per 1 unit of `base`."""
        return rate(self._usd[currency(quote)] / self._usd[currency(base)])

    def to_usd(self, amount, ccy: str) -> Decimal:
        return D(amount) / self._usd[currency(ccy)]

    def from_usd(self, amount_usd, ccy: str) -> Decimal:
        return D(amount_usd) * self._usd[currency(ccy)]

    def set_usd_rate(self, ccy: str, value, as_of: str | None = None) -> None:
        self._usd[currency(ccy)] = D(value)
        if as_of:
            self.as_of = as_of

    def tick(self, volatility="0.004", as_of: str | None = None) -> dict:
        """Random-walk every rate (demo market movement)."""
        v = float(D(volatility))
        for c in self._usd:
            if c != "USD":
                factor = Decimal(str(round(1 + self._rng.uniform(-v, v), 6)))
                self._usd[c] = (self._usd[c] * factor).quantize(Decimal("0.0001"))
        if as_of:
            self.as_of = as_of
        return self.snapshot()

    def snapshot(self) -> dict:
        return {"usd_rates": {c: str(v) for c, v in self._usd.items()}, "as_of": self.as_of, "source": self.source}


class QuoteEngine:
    def __init__(self, conn: sqlite3.Connection, feed: RateFeed, providers: list[Provider], clock: Clock,
                 ttl_minutes: int = 10):
        self.conn = conn
        self.feed = feed
        self.providers = providers
        self.clock = clock
        self.ttl = timedelta(minutes=ttl_minutes)

    def provider(self, provider_id: str) -> Provider:
        for p in self.providers:
            if p.id == provider_id:
                return p
        raise QuoteError(f"unknown provider {provider_id}")

    def _ineligible_reason(self, p: Provider, mode: str, cross: bool, purpose: str | None,
                           payee_type: str | None) -> str | None:
        if mode == "conversion":
            return None if p.conversion_only else "not a wallet conversion service"
        if p.conversion_only:
            return "only converts between your own wallets"
        if cross and not p.cross_border:
            return "same-currency payments only"
        if not cross and not p.same_currency:
            return "cross-currency transfers only"
        if purpose and p.purposes and purpose not in p.purposes:
            return f"doesn't handle {purpose} payments"
        if payee_type and p.payee_types and payee_type not in p.payee_types:
            return f"can't pay a {payee_type}"
        return None

    def _price(self, p: Provider, from_ccy: str, to_ccy: str, amount: Decimal, amount_type: str):
        cross = from_ccy != to_ccy
        mid = self.feed.mid(from_ccy, to_ccy) if cross else Decimal(1)
        offered = rate(mid * (1 - p.fx_margin)) if cross else Decimal(1)
        receiver_fee = q(self.feed.from_usd(p.receiver_fee_usd, to_ccy), to_ccy)
        if amount_type == "send":
            send = q(amount, from_ccy)
            receive = q(send * offered - receiver_fee, to_ccy)
        else:
            receive = q(amount, to_ccy)
            send = q_up((receive + receiver_fee) / offered, from_ccy)
        if send <= 0 or receive <= 0:
            return None, "amount too small after fees"
        send_usd = self.feed.to_usd(send, from_ccy)
        if send_usd < p.min_usd:
            return None, f"minimum is about USD {p.min_usd}"
        if send_usd > p.max_usd:
            return None, f"maximum is about USD {p.max_usd}"
        fee = q(self.feed.from_usd(p.fixed_fee_usd, from_ccy) + send * p.pct_fee, from_ccy)
        total_debit = send + fee
        total_cost = q(total_debit - receive / mid, from_ccy)
        return {
            "provider_id": p.id, "provider_name": p.name, "provider_kind": p.kind, "provider_note": p.note,
            "from_currency": from_ccy, "to_currency": to_ccy,
            "send_amount": send, "fee": fee, "total_debit": total_debit,
            "mid_rate": mid, "offered_rate": offered, "receive_amount": receive,
            "fx_margin_cost": q(send * p.fx_margin, from_ccy),
            "receiver_fee": receiver_fee,
            "total_cost": total_cost,
            "total_cost_pct": (total_cost / send * 100).quantize(Decimal("0.01")),
            "eta_hours": p.eta_hours,
            "usd_equivalent": q(self.feed.to_usd(total_debit, from_ccy), "USD"),
        }, None

    def quote(self, user_id: str, from_ccy: str, to_ccy: str, amount, amount_type: str = "send",
              purpose: str | None = None, payee_type: str | None = None, mode: str = "payment") -> dict:
        """Price every eligible provider and rank them by total cost (then speed)."""
        from_ccy, to_ccy = currency(from_ccy), currency(to_ccy)
        if amount_type not in ("send", "receive"):
            raise QuoteError("amount_type must be 'send' or 'receive'")
        if mode not in ("payment", "conversion"):
            raise QuoteError("mode must be 'payment' or 'conversion'")
        if mode == "conversion" and from_ccy == to_ccy:
            raise QuoteError("conversion needs two different currencies")
        amount = D(amount)
        if amount <= 0:
            raise QuoteError("amount must be positive")

        now = self.clock.now()
        cross = from_ccy != to_ccy
        quotes, excluded = [], []
        for p in self.providers:
            reason = self._ineligible_reason(p, mode, cross, purpose, payee_type)
            priced = None
            if reason is None:
                priced, reason = self._price(p, from_ccy, to_ccy, amount, amount_type)
            if priced is None:
                if mode == "payment" and not p.conversion_only:
                    excluded.append({"provider": p.name, "reason": reason})
                continue
            quotes.append(priced)

        quotes.sort(key=lambda x: (x["total_cost"], x["eta_hours"]))
        bank_cost = next((x["total_cost"] for x in quotes if x["provider_kind"] == "bank"), None)
        for i, x in enumerate(quotes):
            x.update({
                "id": new_id("qt"), "user_id": user_id, "rank": i + 1, "recommended": i == 0,
                "amount_type": amount_type, "purpose": purpose, "payee_type": payee_type, "mode": mode,
                "created_at": iso(now), "expires_at": iso(now + self.ttl),
                "arrives_by": iso(now + timedelta(hours=x["eta_hours"])),
                "savings_vs_bank": q(bank_cost - x["total_cost"], from_ccy) if bank_cost is not None else None,
            })
            self.conn.execute(
                "INSERT INTO quotes(id, user_id, data, created_at, expires_at) VALUES (?,?,?,?,?)",
                (x["id"], user_id, dumps(x), x["created_at"], x["expires_at"]),
            )
        return {
            "quotes": [loads(dumps(x)) for x in quotes],
            "excluded": excluded,
            "mid_rate": str(self.feed.mid(from_ccy, to_ccy)),
            "rates_as_of": self.feed.as_of,
            "valid_minutes": int(self.ttl.total_seconds() // 60),
        }

    def get(self, quote_id: str) -> dict | None:
        row = self.conn.execute("SELECT data FROM quotes WHERE id = ?", (quote_id,)).fetchone()
        return loads(row["data"]) if row else None
