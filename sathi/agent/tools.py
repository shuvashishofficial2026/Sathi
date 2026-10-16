"""The agent's tools: read (tier 0) and prepare (tier 1) only.

There is deliberately no tool that confirms, executes, verifies a payee or signs
a mandate. The agent reaches the sandbox only through AgentView, which exposes
an allow-list of read and draft methods.
"""

from __future__ import annotations

import functools
import json
import re

from ..drafts import DraftError
from ..fx import QuoteError
from ..mandates import MandateError
from ..payees import PayeeError
from ..sandbox import SandboxError
from ..util import dumps

AGENT_SAFE_METHODS = frozenset({
    "profile", "balances", "rates", "get_quotes", "list_payees", "history", "documents_on_record", "pending",
    "list_mandates", "budget_summary", "runway", "deadlines",
    "draft_payment", "draft_conversion", "add_payee", "propose_mandate", "analyze_message", "set_budget",
    "add_deadline",
    "redact_pin",  # used by the session to scrub user messages; not a tool
})

PURPOSES = ["tuition", "rent", "living_expenses", "family_support", "personal"]
CURRENCY = {"type": "string", "description": "ISO currency code: BDT, CNY, USD, MYR or GBP."}
AMOUNT = {"type": "string", "description": "Amount as a plain number string, e.g. \"13000\" or \"250.50\"."}


class AgentView:
    """The agent's only door into the sandbox: an allow-list of read and draft methods."""

    __slots__ = ("_call",)

    def __init__(self, sandbox):
        def call(name, *args, **kwargs):
            if name not in AGENT_SAFE_METHODS:
                raise PermissionError(f"{name} is not available to the agent")
            return getattr(sandbox, name)(*args, **kwargs)

        object.__setattr__(self, "_call", call)

    def __getattr__(self, name):
        if name in AGENT_SAFE_METHODS:
            return functools.partial(self._call, name)
        raise AttributeError(f"{name} is not available to the agent")

    def __setattr__(self, name, value):
        raise AttributeError("AgentView is read-only")


def _obj(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


TOOL_SPECS: list[dict] = [
    # ---- tier 0: read ----
    {"name": "get_profile", "description": "The user's name, home currency, country, language and today's date.",
     "input_schema": _obj({}, [])},
    {"name": "get_balances", "description": "Wallet balances per currency, with totals in USD and home currency.",
     "input_schema": _obj({}, [])},
    {"name": "get_fx_rate", "description": "Mid-market exchange rate between two currencies (no fees).",
     "input_schema": _obj({"base": CURRENCY, "quote": CURRENCY}, ["base", "quote"])},
    {"name": "get_quotes",
     "description": "Price a transfer with every eligible provider, ranked by total cost (fees + FX margin vs "
                    "mid-market). Quotes are valid for 10 minutes. Use mode 'payment' to pay a payee (pass "
                    "payee_id and purpose) or 'conversion' to convert between the user's own wallets. To compare "
                    "providers for someone who isn't a saved payee (for example family sending money from "
                    "abroad), use mode 'payment' with a purpose and leave payee_id out.",
     "input_schema": _obj({
         "from_currency": CURRENCY, "to_currency": CURRENCY, "amount": AMOUNT,
         "amount_type": {"type": "string", "enum": ["send", "receive"],
                         "description": "'send': amount leaves the user's wallet. 'receive': amount must arrive."},
         "mode": {"type": "string", "enum": ["payment", "conversion"]},
         "purpose": {"type": "string", "enum": PURPOSES, "description": "Required for payments."},
         "payee_id": {"type": "string", "description": "The payee's id from list_payees (payments)."},
     }, ["from_currency", "to_currency", "amount", "amount_type", "mode"])},
    {"name": "list_payees",
     "description": "The user's saved payees with masked account numbers, type, currency and verification status.",
     "input_schema": _obj({}, [])},
    {"name": "get_transaction_history", "description": "Recent wallet transactions, newest first.",
     "input_schema": _obj({"limit": {"type": "integer", "description": "How many (default 10, max 30)."}}, [])},
    {"name": "get_budget_summary", "description": "This month's spending against each budget category.",
     "input_schema": _obj({}, [])},
    {"name": "get_runway",
     "description": "How long the user's money lasts after setting aside upcoming deadlines such as tuition.",
     "input_schema": _obj({}, [])},
    {"name": "list_deadlines", "description": "Upcoming payment deadlines (tuition, fees) with days left.",
     "input_schema": _obj({}, [])},
    {"name": "list_documents",
     "description": "Compliance documents on record, such as the student file and admission letter.",
     "input_schema": _obj({}, [])},
    {"name": "list_mandates", "description": "The user's FX mandates (proposed, active, completed, expired).",
     "input_schema": _obj({}, [])},
    {"name": "list_pending_actions", "description": "Drafts waiting for the user to confirm in the app.",
     "input_schema": _obj({}, [])},
    # ---- tier 1: prepare (nothing moves) ----
    {"name": "draft_payment",
     "description": "Prepare a payment from a quote. It does NOT send money: it creates a draft card that the "
                    "user must confirm in the app. The result says whether policy allows it, needs the PIN, or "
                    "blocks it, and why.",
     "input_schema": _obj({
         "quote_id": {"type": "string"}, "payee_id": {"type": "string"},
         "purpose": {"type": "string", "enum": PURPOSES},
         "reference": {"type": "string", "description": "Optional payment reference, e.g. student number."},
     }, ["quote_id", "payee_id", "purpose"])},
    {"name": "draft_conversion",
     "description": "Prepare a conversion between the user's own wallets from a conversion quote. The user "
                    "confirms it in the app.",
     "input_schema": _obj({"quote_id": {"type": "string"}}, ["quote_id"])},
    {"name": "propose_mandate",
     "description": "Propose a standing FX instruction: convert up to max_amount of from_currency when the rate "
                    "offered is at least min_rate (units of to_currency per 1 from_currency), until it expires. "
                    "It does nothing until the user signs it in the app with their PIN.",
     "input_schema": _obj({
         "from_currency": CURRENCY, "to_currency": CURRENCY, "max_amount": AMOUNT,
         "min_rate": {"type": "string", "description": "Minimum rate, e.g. \"7.15\"."},
         "days_valid": {"type": "integer", "description": "1 to 30 days."},
         "note": {"type": "string"},
     }, ["from_currency", "to_currency", "max_amount", "min_rate", "days_valid"])},
    {"name": "add_payee",
     "description": "Save a new payee. Institutions are verified automatically only if the account matches the "
                    "official registry. People and businesses stay unverified until the user verifies them in "
                    "the app, and a 24-hour cooling-off period follows.",
     "input_schema": _obj({
         "display_name": {"type": "string"},
         "payee_type": {"type": "string", "enum": ["institution", "person", "business"]},
         "currency": CURRENCY,
         "account_number": {"type": "string"},
         "bank_name": {"type": "string"},
         "country": {"type": "string", "description": "Two-letter country code."},
     }, ["display_name", "payee_type", "currency", "account_number"])},
    {"name": "analyze_payment_request",
     "description": "Scam check for a payment request someone sent the user (email, invoice, chat). Returns a "
                    "risk score, red flags and whether the account matches the institution's verified account.",
     "input_schema": _obj({"text": {"type": "string"}}, ["text"])},
    {"name": "set_budget", "description": "Create or change a monthly budget for a spending category.",
     "input_schema": _obj({"category": {"type": "string"}, "monthly_limit": AMOUNT, "currency": CURRENCY},
                          ["category", "monthly_limit", "currency"])},
    {"name": "add_deadline", "description": "Track an upcoming payment deadline.",
     "input_schema": _obj({
         "title": {"type": "string"},
         "due_date": {"type": "string", "description": "YYYY-MM-DD"},
         "amount": AMOUNT, "currency": CURRENCY,
         "payee_id": {"type": "string"},
         "purpose": {"type": "string", "enum": PURPOSES},
     }, ["title", "due_date", "amount", "currency"])},
]

TOOL_NAMES = frozenset(t["name"] for t in TOOL_SPECS)
_EXPECTED_ERRORS = (ValueError, KeyError, SandboxError, DraftError, PayeeError, QuoteError, MandateError)


def _quote_view(x: dict) -> dict:
    keep = ("id", "rank", "recommended", "provider_name", "provider_note", "send_amount", "fee", "total_debit",
            "receive_amount", "offered_rate", "mid_rate", "total_cost", "total_cost_pct", "savings_vs_bank",
            "eta_hours", "arrives_by", "from_currency", "to_currency")
    return {k: x[k] for k in keep if k in x}


def _draft_view(action: dict) -> dict:
    card = action["card"]
    if card["blocked"]:
        next_step = "Blocked by policy. Explain the reasons to the user; do not try to work around them."
    elif card["needs_pin"]:
        next_step = "Waiting for the user to tap Confirm and enter their PIN in the app."
    else:
        next_step = "Waiting for the user to tap Confirm in the app."
    return {"action_id": action["id"], "status": action["status"], "card": card, "next_step": next_step}


class ToolBox:
    """Validates and runs tool calls for one agent session."""

    def __init__(self, view: AgentView, session):
        self.view = view
        self.session = session

    @staticmethod
    def specs(strict: bool = True) -> list[dict]:
        return [{**t, "strict": True} if strict else dict(t) for t in TOOL_SPECS]

    def run(self, name: str, tool_input: dict) -> tuple[str, bool]:
        """Returns (result as JSON text, is_error)."""
        if name not in TOOL_NAMES:
            return dumps({"error": f"No tool named {name}. Money can only move when the user confirms in the "
                                   "app."}), True
        spec = next(t for t in TOOL_SPECS if t["name"] == name)
        problem = _validate(spec["input_schema"], tool_input)
        if problem:
            return dumps({"error": problem}), True
        try:
            result = getattr(self, f"_t_{name}")(**tool_input)
            return dumps(result), False
        except PermissionError as exc:
            return dumps({"error": str(exc)}), True
        except _EXPECTED_ERRORS as exc:
            message = exc.args[0] if exc.args else exc.__class__.__name__
            return dumps({"error": str(message)}), True
        except Exception as exc:  # a bug in one tool must not end the conversation; the loop audits the error
            return dumps({"error": f"{name} failed with an internal error ({exc.__class__.__name__})."}), True

    # ---- tier 0 ----
    def _t_get_profile(self):
        p = self.view.profile(self.session.user_id)
        return {**p, "today": self.session.today()}

    def _t_get_balances(self):
        return self.view.balances(self.session.user_id)

    def _t_get_fx_rate(self, base, quote):
        return self.view.rates(base, quote)

    def _t_get_quotes(self, from_currency, to_currency, amount, amount_type, mode, purpose=None, payee_id=None):
        r = self.view.get_quotes(self.session.user_id, from_currency, to_currency, amount, amount_type, purpose,
                                 payee_id, mode)
        return {**r, "quotes": [_quote_view(x) for x in r["quotes"]]}

    def _t_list_payees(self):
        keep = ("id", "display_name", "payee_type", "currency", "country", "bank_name", "account_number",
                "verified", "verified_at", "flags", "institution_id")
        return [{k: p[k] for k in keep} for p in self.view.list_payees(self.session.user_id)]

    def _t_get_transaction_history(self, limit=10):
        return self.view.history(self.session.user_id, max(1, min(int(limit), 30)))

    def _t_get_budget_summary(self):
        return self.view.budget_summary(self.session.user_id)

    def _t_get_runway(self):
        return self.view.runway(self.session.user_id)

    def _t_list_deadlines(self):
        return self.view.deadlines(self.session.user_id)

    def _t_list_documents(self):
        return [{k: d[k] for k in ("kind", "institution_id", "status", "valid_from", "valid_until", "data")}
                for d in self.view.documents_on_record(self.session.user_id)]

    def _t_list_mandates(self):
        keep = ("id", "status", "description", "remaining", "used_amount", "expires_at")
        return [{k: m[k] for k in keep} for m in self.view.list_mandates(self.session.user_id)]

    def _t_list_pending_actions(self):
        return [_draft_view(a) for a in self.view.pending(self.session.user_id)]

    # ---- tier 1 ----
    def _t_draft_payment(self, quote_id, payee_id, purpose, reference=""):
        origin, risk = self.session.draft_origin()
        action = self.view.draft_payment(self.session.user_id, quote_id, payee_id, purpose, reference, origin, risk)
        self.session.note_action(action["id"])
        return _draft_view(action)

    def _t_draft_conversion(self, quote_id):
        origin, _ = self.session.draft_origin()
        action = self.view.draft_conversion(self.session.user_id, quote_id, origin)
        self.session.note_action(action["id"])
        return _draft_view(action)

    def _t_propose_mandate(self, from_currency, to_currency, max_amount, min_rate, days_valid, note=""):
        m = self.view.propose_mandate(self.session.user_id, from_currency, to_currency, max_amount, min_rate,
                                      days_valid, note)
        self.session.note_mandate(m["id"])
        return {"mandate_id": m["id"], "status": m["status"], "description": m["description"],
                "next_step": "The user must review and sign this mandate in the app with their PIN."}

    def _t_add_payee(self, display_name, payee_type, currency, account_number, bank_name=None, country=None):
        p = self.view.add_payee(self.session.user_id, display_name, payee_type, currency, account_number,
                                bank_name, country, "agent")
        return {k: p[k] for k in ("id", "display_name", "payee_type", "currency", "account_number", "verified",
                                  "flags")}

    def _t_analyze_payment_request(self, text):
        report = self.view.analyze_message(self.session.user_id, text)
        self.session.mark_untrusted(report["risk_score"])
        return report

    def _t_set_budget(self, category, monthly_limit, currency):
        return self.view.set_budget(self.session.user_id, category, monthly_limit, currency)

    def _t_add_deadline(self, title, due_date, amount, currency, payee_id=None, purpose=None):
        return self.view.add_deadline(self.session.user_id, title, due_date, amount, currency, payee_id, purpose)


_TYPES = {"string": str, "integer": int, "object": dict, "array": list, "boolean": bool}


def _validate(schema: dict, value) -> str | None:
    """Small JSON-schema check for tool inputs (types, required, enums, no extras)."""
    if not isinstance(value, dict):
        return "tool input must be an object"
    props = schema.get("properties", {})
    for key in schema.get("required", []):
        if key not in value:
            return f"missing required field '{key}'"
    for key, v in value.items():
        if key not in props:
            return f"unexpected field '{key}'"
        expected = _TYPES[props[key]["type"]]
        if expected is int and isinstance(v, bool) or not isinstance(v, expected):
            return f"field '{key}' must be a {props[key]['type']}"
        if "enum" in props[key] and v not in props[key]["enum"]:
            return f"field '{key}' must be one of {props[key]['enum']}"
    return None


def looks_forwarded(text: str) -> bool:
    """Heuristic: long pasted content with account-like numbers is treated as untrusted."""
    has_account = re.search(r"(?<!\d)(?:\d[ -]?){8,30}\d(?!\d)", text or "") is not None
    return has_account and len(text) > 200


def result_preview(result_json: str, limit: int = 300) -> str:
    try:
        return json.dumps(json.loads(result_json), ensure_ascii=False)[:limit]
    except ValueError:
        return result_json[:limit]
