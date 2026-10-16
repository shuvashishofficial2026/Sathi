"""The executor: the only code that moves money.

It runs a draft only when the user confirms it with a valid one-time token
(plus the PIN for step-up actions), or when a user-signed mandate covers it.
Policy is re-checked at execution time, so a draft that was fine a minute ago
but no longer is (balance spent, limit used, quote expired) is refused.
"""

from __future__ import annotations

import sqlite3

from .actions import Actions, ConfirmationAuthority, action_card, summary_line
from .audit import AuditLog
from .ledger import DuplicateRequest, InsufficientFunds, Ledger
from .money import D
from .payees import Payees
from .policy import DENY, STEP_UP, PolicyEngine
from .users import PinLocked, Users
from .util import Clock, parse_dt


class ExecutionError(Exception):
    def __init__(self, code: str, message: str, reasons: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.reasons = reasons or []


class Executor:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, audit: AuditLog, ledger: Ledger, actions: Actions,
                 policy: PolicyEngine, users: Users, payees: Payees, authority: ConfirmationAuthority):
        self.conn = conn
        self.clock = clock
        self.audit = audit
        self.ledger = ledger
        self.actions = actions
        self.policy = policy
        self.users = users
        self.payees = payees
        self.authority = authority

    def confirm(self, user_id: str, action_id: str, token: str, pin: str | None = None) -> dict:
        """The user tapped Confirm (and entered a PIN if asked)."""
        action = self._load(user_id, action_id)
        if not self.authority.check(action, token):
            self.audit.record("system", "action.confirm_rejected", {"action_id": action_id, "why": "bad token"},
                              user_id)
            raise ExecutionError("bad_token", "Confirmation token is invalid for this action.")
        return self._execute(action, actor="user", pin=pin)

    def execute_mandated(self, action_id: str, mandate: dict) -> dict:
        """Called by the mandate engine only, for a conversion inside a signed mandate."""
        action = self.actions.get(action_id)
        p = action["payload"]
        problems = []
        if mandate["status"] != "active":
            problems.append("mandate is not active")
        if action["mandate_id"] != mandate["id"] or action["user_id"] != mandate["user_id"]:
            problems.append("action is not covered by this mandate")
        if p["kind"] != "conversion" or (p["from_currency"], p["to_currency"]) != (
                mandate["from_currency"], mandate["to_currency"]):
            problems.append("action does not match the mandate's currencies")
        if D(p["send_amount"]) > D(mandate["max_amount"]) - D(mandate["used_amount"]):
            problems.append("amount exceeds what is left on the mandate")
        if D(p["offered_rate"]) < D(mandate["min_rate"]):
            problems.append("rate is below the mandate's minimum")
        if self.clock.now() > parse_dt(mandate["expires_at"]):
            problems.append("mandate has expired")
        if problems:
            self.audit.record("mandate", "mandate.execution_refused", {"action_id": action_id, "problems": problems},
                              action["user_id"])
            raise ExecutionError("mandate_scope", "Not covered by the mandate.", problems)
        return self._execute(action, actor="mandate", mandate=True)

    def reject(self, user_id: str, action_id: str) -> dict:
        action = self._load(user_id, action_id)
        if action["status"] != "awaiting_confirmation":
            raise ExecutionError("not_pending", f"Action is {action['status']}.")
        action = self.actions.update(action_id, "rejected")
        self.audit.record("user", "action.rejected", {"action_id": action_id}, user_id)
        return action

    # internals
    def _load(self, user_id: str, action_id: str) -> dict:
        try:
            action = self.actions.get(action_id)
        except KeyError:
            raise ExecutionError("not_found", "No such action.") from None
        if action["user_id"] != user_id:
            raise ExecutionError("not_found", "No such action.")
        return action

    def _execute(self, action: dict, actor: str, pin: str | None = None, mandate: bool = False) -> dict:
        action_id, user_id, p = action["id"], action["user_id"], action["payload"]
        if action["status"] != "awaiting_confirmation":
            raise ExecutionError("not_pending", f"Action is already {action['status']}.")
        if self.clock.now() > parse_dt(action["expires_at"]):
            self.actions.update(action_id, "expired")
            self.audit.record("system", "action.expired", {"action_id": action_id}, user_id)
            raise ExecutionError("expired", "This draft expired. Ask for a fresh quote.")

        decision = self.policy.evaluate(p)
        if decision.outcome == DENY:
            self.actions.update(action_id, "blocked", decision=decision)
            reasons = [r.message for r in decision.reasons if r.outcome == DENY]
            self.audit.record("policy", "action.blocked_at_execution", {"action_id": action_id, "reasons": reasons},
                              user_id)
            raise ExecutionError("policy_denied", "Blocked by policy.", reasons)
        # A PIN the card asked for is still needed even if the fresh check alone wouldn't ask for it.
        drafted_with_pin = action["decision"]["outcome"] == STEP_UP
        needs_pin = decision.outcome == STEP_UP or drafted_with_pin
        if needs_pin:
            why = [r.message for r in decision.reasons] or [r["message"] for r in action["decision"]["reasons"]]
            if mandate:
                raise ExecutionError("step_up_required", "Needs the user's PIN; a mandate can't approve this.", why)
            if not pin:
                if not drafted_with_pin:  # newly needed since the draft: make the card ask for the PIN and say why
                    self.actions.set_decision(action_id, decision)
                    self.audit.record("policy", "action.step_up_at_execution", {
                        "action_id": action_id, "reasons": [r.rule for r in decision.reasons]}, user_id)
                raise ExecutionError("step_up_required", "Enter your PIN to approve this.", why)
            try:
                ok = self.users.check_pin(user_id, pin)
            except PinLocked as exc:
                raise ExecutionError("pin_locked", str(exc)) from None
            if not ok:
                raise ExecutionError("wrong_pin", "Wrong PIN.")

        try:
            journal_id = self.ledger.post(
                kind=p["kind"], user_id=user_id, legs=self._legs(p), idempotency_key=action_id,
                memo=summary_line(p), category=p.get("purpose") if p["kind"] == "payment" else None,
                meta={"action_id": action_id, "provider_id": p["provider_id"], "reference": p.get("reference", "")},
            )
        except InsufficientFunds:
            self.actions.update(action_id, "blocked", decision=decision)
            raise ExecutionError("insufficient_funds", "Not enough balance.") from None
        except DuplicateRequest as exc:
            raise ExecutionError("duplicate", f"Already executed as {exc.journal_id}.") from None

        action = self.actions.update(action_id, "executed", decision=decision, journal_id=journal_id)
        self.audit.record(actor, "action.executed", {
            "action_id": action_id, "journal_id": journal_id, "summary": summary_line(p),
            "decision": decision.outcome, "step_up": needs_pin,
        }, user_id)
        return {"action_id": action_id, "journal_id": journal_id, "executed_at": action["resolved_at"],
                "summary": summary_line(p), "card": action_card(action)}

    def _legs(self, p: dict) -> list:
        L = self.ledger
        send, fee = D(p["send_amount"]), D(p["fee"])
        total, receive = D(p["total_debit"]), D(p["receive_amount"])
        src, dst_ccy, prov = p["from_currency"], p["to_currency"], p["provider_id"]
        legs = [(L.wallet(p["user_id"], src), -total)]
        if fee:
            legs.append((L.account("fees", prov, src), fee))
        if src != dst_ccy:
            legs.append((L.account("fxpool", prov, src), send))
            legs.append((L.account("fxpool", prov, dst_ccy), -receive))
        elif send != receive:
            legs.append((L.account("fees", prov, src), send - receive))
        if p["kind"] == "conversion":
            dest = L.wallet(p["user_id"], dst_ccy)
        else:
            payee = self.payees.get(p["user_id"], p["payee_id"], full=True)
            dest = (L.wallet(payee["linked_user_id"], dst_ccy) if payee["linked_user_id"]
                    else L.account("external", payee["id"], dst_ccy))
        legs.append((dest, receive))
        return legs
