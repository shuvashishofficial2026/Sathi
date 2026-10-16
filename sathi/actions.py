"""Pending actions (drafts), confirmation tokens and the action card.

A draft is frozen when it is created: its payload is hashed, and the user's
confirmation token is bound to that hash. The card the user confirms is built
by code from the payload, never from the agent's words.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from decimal import Decimal

from .audit import AuditLog
from .money import D, fmt
from .policy import DENY, STEP_UP, Decision
from .util import Clock, dumps, iso, loads, new_id, parse_dt


class ConfirmationAuthority:
    """Issues and checks one-time confirmation tokens.

    Only the app's UI layer holds this object. The agent's tools never see it,
    so the agent has no way to confirm its own drafts.
    """

    def __init__(self, secret: bytes):
        self._secret = secret

    def token_for(self, action: dict) -> str:
        msg = f"{action['id']}|{action['action_hash']}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def check(self, action: dict, token: str | None) -> bool:
        return bool(token) and hmac.compare_digest(self.token_for(action), token)


class Actions:
    def __init__(self, conn: sqlite3.Connection, clock: Clock, audit: AuditLog):
        self.conn = conn
        self.clock = clock
        self.audit = audit

    def create(self, user_id: str, kind: str, payload: dict, decision: Decision, origin: str, expires_at: str,
               mandate_id: str | None = None) -> dict:
        action_id = new_id("act")
        payload_json = dumps(payload)
        action_hash = hashlib.sha256(payload_json.encode()).hexdigest()
        status = "blocked" if decision.outcome == DENY else "awaiting_confirmation"
        self.conn.execute(
            "INSERT INTO actions(id, user_id, kind, status, origin, payload, action_hash, decision, created_at, "
            "expires_at, mandate_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (action_id, user_id, kind, status, origin, payload_json, action_hash, dumps(decision.to_dict()),
             iso(self.clock.now()), expires_at, mandate_id),
        )
        self.audit.record("policy", "action.drafted", {
            "action_id": action_id, "kind": kind, "origin": origin, "status": status,
            "decision": decision.outcome, "reasons": [r.rule for r in decision.reasons],
            "summary": summary_line(payload),
        }, user_id)
        return self.get(action_id)

    def get(self, action_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown action {action_id}")
        return {**dict(row), "payload": loads(row["payload"]), "decision": loads(row["decision"])}

    def list(self, user_id: str, statuses: tuple[str, ...] | None = None, limit: int = 20) -> list[dict]:
        sql = "SELECT id FROM actions WHERE user_id = ?"
        args: list = [user_id]
        if statuses:
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args += list(statuses)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        args.append(limit)
        return [self.get(r["id"]) for r in self.conn.execute(sql, args)]

    def set_decision(self, action_id: str, decision: Decision) -> dict:
        """Refresh a pending draft's decision, e.g. when it needs a PIN that it didn't need when drafted."""
        self.conn.execute("UPDATE actions SET decision = ? WHERE id = ?", (dumps(decision.to_dict()), action_id))
        return self.get(action_id)

    def update(self, action_id: str, status: str, decision: Decision | None = None,
               journal_id: str | None = None) -> dict:
        sets, args = ["status = ?", "resolved_at = ?"], [status, iso(self.clock.now())]
        if decision is not None:
            sets.append("decision = ?")
            args.append(dumps(decision.to_dict()))
        if journal_id is not None:
            sets.append("journal_id = ?")
            args.append(journal_id)
        self.conn.execute(f"UPDATE actions SET {', '.join(sets)} WHERE id = ?", (*args, action_id))
        return self.get(action_id)


def summary_line(p: dict) -> str:
    if p["kind"] == "payment":
        return (f"Pay {p['payee_name']} {fmt(p['receive_amount'], p['to_currency'])} "
                f"for {fmt(p['total_debit'], p['from_currency'])} via {p['provider_name']}")
    return (f"Convert {fmt(p['send_amount'], p['from_currency'])} to "
            f"{fmt(p['receive_amount'], p['to_currency'])} via {p['provider_name']}")


def rate_line(from_ccy: str, to_ccy: str, offered: Decimal, mid: Decimal) -> str:
    """Show the rate the way people quote it: 1 CNY = 17.37 BDT, not 1 BDT = 0.0576 CNY."""
    if offered >= 1:
        return f"Rate: 1 {from_ccy} = {offered.normalize():f} {to_ccy} (mid-market {mid.normalize():f})"
    four = Decimal("0.0001")
    return (f"Rate: 1 {to_ccy} = {(1 / offered).quantize(four)} {from_ccy} "
            f"(mid-market {(1 / mid).quantize(four)})")


def action_card(action: dict) -> dict:
    """What the user sees and confirms. Built only from the frozen payload and decision."""
    p, d = action["payload"], action["decision"]
    lines = []
    if p["kind"] == "payment":
        title = f"Pay {p['payee_name']}"
        lines.append(f"They receive: {fmt(p['receive_amount'], p['to_currency'])}")
    else:
        title = f"Convert {p['from_currency']} to {p['to_currency']}"
        lines.append(f"You receive: {fmt(p['receive_amount'], p['to_currency'])}")
    if D(p["fee"]):
        lines.append(f"You pay: {fmt(p['total_debit'], p['from_currency'])} "
                     f"({fmt(p['send_amount'], p['from_currency'])} + fee {fmt(p['fee'], p['from_currency'])})")
    else:
        lines.append(f"You pay: {fmt(p['total_debit'], p['from_currency'])} (no separate fee)")
    if p["from_currency"] != p["to_currency"]:
        lines.append(rate_line(p["from_currency"], p["to_currency"], D(p["offered_rate"]), D(p["mid_rate"])))
    lines.append(f"Total cost vs mid-market: {fmt(p['total_cost'], p['from_currency'])} ({p['total_cost_pct']}%)")
    lines.append(f"Via {p['provider_name']}, arrives by {parse_dt(p['arrives_by']).strftime('%d %b %H:%M')} UTC")
    if p.get("purpose"):
        lines.append(f"Purpose: {p['purpose']}")
    if p.get("reference"):
        lines.append(f"Reference: {p['reference']}")
    if action.get("mandate_id"):
        lines.append(f"Under your signed mandate {action['mandate_id']}")
    status = action["status"]
    return {
        "action_id": action["id"],
        "title": title,
        "lines": lines,
        "status": status,
        "needs_pin": d["outcome"] == STEP_UP,
        "blocked": status == "blocked",
        "reasons": [r["message"] for r in d["reasons"] if status != "blocked" or r["outcome"] == DENY],
        "checks_passed": [r["message"] for r in d["passed"]],
        "expires_at": action["expires_at"],
    }
