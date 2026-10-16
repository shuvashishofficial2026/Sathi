"""Turning a quote into a draft action (tier 1: nothing moves yet)."""

from __future__ import annotations

from .actions import Actions, action_card
from .audit import AuditLog
from .fx import QuoteEngine
from .payees import Payees
from .policy import PolicyEngine, beneficiary_student
from .util import Clock, parse_dt

ORIGINS = ("chat", "document", "mandate")


class DraftError(Exception):
    pass


def _clean_reference(text: str | None) -> str:
    text = " ".join((text or "").split())
    return text[:140]


class Drafts:
    def __init__(self, clock: Clock, audit: AuditLog, quotes: QuoteEngine, payees: Payees, policy: PolicyEngine,
                 actions: Actions):
        self.clock = clock
        self.audit = audit
        self.quotes = quotes
        self.payees = payees
        self.policy = policy
        self.actions = actions

    def _quote(self, user_id: str, quote_id: str, mode: str) -> dict:
        quote = self.quotes.get(quote_id)
        if quote is None or quote["user_id"] != user_id:
            raise DraftError("Unknown quote. Get a quote first.")
        if quote["mode"] != mode:
            raise DraftError(f"That quote is for a {quote['mode']}, not a {mode}.")
        if self.clock.now() > parse_dt(quote["expires_at"]):
            raise DraftError("That quote has expired. Get a fresh quote.")
        return quote

    def payment(self, user_id: str, quote_id: str, payee_id: str, purpose: str, reference: str = "",
                origin: str = "chat", risk_score: int = 0) -> dict:
        if origin not in ORIGINS:
            raise DraftError(f"bad origin {origin}")
        quote = self._quote(user_id, quote_id, "payment")
        payee = self.payees.get(user_id, payee_id, full=True)
        if payee["currency"] != quote["to_currency"]:
            raise DraftError(f"{payee['display_name']} receives {payee['currency']}, but the quote pays "
                             f"{quote['to_currency']}. Get a quote in {payee['currency']}.")
        provider = self.quotes.provider(quote["provider_id"])
        if quote.get("purpose") and quote["purpose"] != purpose:
            raise DraftError("The quote was for a different purpose. Get a new quote with this purpose.")
        if provider.purposes and purpose not in provider.purposes:
            raise DraftError(f"{provider.name} doesn't handle {purpose} payments. Pick another quote.")
        if provider.payee_types and payee["payee_type"] not in provider.payee_types:
            raise DraftError(f"{provider.name} can't pay a {payee['payee_type']}. Pick another quote.")
        payload = {
            "kind": "payment", "user_id": user_id, "quote_id": quote_id,
            **{k: quote[k] for k in (
                "provider_id", "provider_name", "from_currency", "to_currency", "send_amount", "fee",
                "total_debit", "receive_amount", "mid_rate", "offered_rate", "total_cost", "total_cost_pct",
                "eta_hours", "arrives_by", "usd_equivalent")},
            "quote_expires_at": quote["expires_at"],
            "payee_id": payee["id"], "payee_name": payee["display_name"], "payee_type": payee["payee_type"],
            "institution_id": payee["institution_id"],
            "student_user_id": beneficiary_student(user_id, payee),
            "purpose": purpose, "reference": _clean_reference(reference),
            "origin": origin, "risk_score": int(risk_score),
        }
        decision = self.policy.evaluate(payload)
        action = self.actions.create(user_id, "payment", payload, decision, origin, quote["expires_at"])
        return {**action, "card": action_card(action)}

    def conversion(self, user_id: str, quote_id: str, origin: str = "chat", mandate_id: str | None = None) -> dict:
        if origin not in ORIGINS:
            raise DraftError(f"bad origin {origin}")
        quote = self._quote(user_id, quote_id, "conversion")
        payload = {
            "kind": "conversion", "user_id": user_id, "quote_id": quote_id,
            **{k: quote[k] for k in (
                "provider_id", "provider_name", "from_currency", "to_currency", "send_amount", "fee",
                "total_debit", "receive_amount", "mid_rate", "offered_rate", "total_cost", "total_cost_pct",
                "eta_hours", "arrives_by", "usd_equivalent")},
            "quote_expires_at": quote["expires_at"],
            "purpose": "conversion", "origin": origin, "risk_score": 0,
        }
        decision = self.policy.evaluate(payload)
        action = self.actions.create(user_id, "conversion", payload, decision, origin, quote["expires_at"],
                                     mandate_id=mandate_id)
        return {**action, "card": action_card(action)}
