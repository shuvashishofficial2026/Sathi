"""Sathi demo app. Run: streamlit run app.py

The chat needs a Claude API key: set ANTHROPIC_API_KEY, or put it in .streamlit/secrets.toml.
Everything else (approvals, wallet, budget, scam check, audit log) works without one.
SATHI_LLM=scripted-demo replays one fixed conversation instead of calling Claude, for offline testing.
"""

from __future__ import annotations

import os
from decimal import Decimal

import pandas as pd
import streamlit as st

from sathi import Sandbox
from sathi.actions import action_card
from sathi.agent import AgentSession, ClaudeLLM, ScriptedLLM
from sathi.executor import ExecutionError
from sathi.mandates import MandateError
from sathi.money import fmt
from sathi.payees import PayeeError
from sathi.sandbox import SandboxError
from sathi.users import PinLocked
from sathi.util import dumps

st.set_page_config(page_title="Sathi", page_icon="🤝", layout="wide")

USERS = {
    "nusrat": {"label": "Nusrat · master's student in Shenzhen", "lang": "en", "avatar": "🎓"},
    "abbu": {"label": "আব্বু (Abbu) · father in Chattogram", "lang": "bn", "avatar": "👨"},
}
TEXT = {
    "en": {"confirm": "Confirm", "reject": "Reject", "pin": "PIN", "sign": "Sign with PIN", "decline": "Decline",
           "revoke": "Revoke", "verify": "Verify with PIN", "working": "Sathi is working…",
           "ask": "Ask Sathi… e.g. “Pay my spring tuition” or “How long will my money last?”"},
    "bn": {"confirm": "নিশ্চিত করুন", "reject": "বাতিল", "pin": "পিন", "sign": "পিন দিয়ে সই করুন",
           "decline": "বাতিল", "revoke": "প্রত্যাহার", "verify": "পিন দিয়ে যাচাই করুন",
           "working": "সাথী কাজ করছে…", "ask": "সাথীকে লিখুন… যেমন “মেয়েকে ৫০,০০০ টাকা পাঠাও”"},
}
WELCOME = {
    "nusrat": "Hi Nusrat! I'm Sathi. I can pay tuition and rent at the lowest cost, convert currency when the rate "
              "is right, track your budget and check suspicious payment requests. Nothing moves until you tap "
              "**Confirm**.",
    "abbu": "স্বাগতম! আমি সাথী। মেয়ের কাছে টাকা পাঠাতে, সবচেয়ে কম খরচের উপায় খুঁজতে আর প্রতারণার মেসেজ চিনতে "
            "সাহায্য করি। প্রতিটি পেমেন্ট আপনি নিজে নিশ্চিত করবেন।",
}
SUGGESTIONS = {
    "nusrat": ["Pay my spring tuition", "How long will my money last?",
               "Convert my USD to CNY when the rate is good", "Am I over budget this month?"],
    "abbu": ["মেয়েকে এই মাসের হাতখরচ ৫০,০০০ টাকা পাঠাও", "টাকা পাঠাতে কোন সার্ভিসে খরচ সবচেয়ে কম?",
             "আমার ব্যালেন্স কত?"],
}
TOOL_LABELS = {
    "get_profile": "Reading your profile", "get_balances": "Checking balances", "get_fx_rate": "Checking the rate",
    "get_quotes": "Comparing providers", "list_payees": "Looking up payees", "draft_payment": "Preparing the payment",
    "draft_conversion": "Preparing the conversion", "propose_mandate": "Drafting a rate mandate",
    "analyze_payment_request": "Running the scam check", "get_runway": "Working out your runway",
    "get_budget_summary": "Checking your budget", "list_deadlines": "Checking deadlines",
    "list_documents": "Checking your student file", "add_payee": "Saving the payee",
    "get_transaction_history": "Reading history", "list_mandates": "Checking mandates",
    "list_pending_actions": "Checking drafts", "set_budget": "Updating the budget", "add_deadline": "Adding a deadline",
}
STATUS_ICON = {"awaiting_confirmation": "🟡", "executed": "✅", "blocked": "⛔", "rejected": "✖️", "expired": "⌛"}


# ---------------------------------------------------------------- AI backend

def api_key() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return os.environ["ANTHROPIC_API_KEY"]
    try:
        return st.secrets.get("ANTHROPIC_API_KEY")
    except Exception:  # no secrets file
        return None


def llm_mode() -> str | None:
    if os.environ.get("SATHI_LLM") == "scripted-demo":
        return "scripted"
    return "claude" if api_key() else None


def _payee_id(c, payee_type: str) -> str:
    return next(p["id"] for p in c.last("list_payees") if p["payee_type"] == payee_type)


def _best(c) -> dict:
    return c.last("get_quotes")["quotes"][0]


def _reply_en(c) -> str:
    q = _best(c)
    saving = q.get("savings_vs_bank")
    saving = f", {fmt(saving, q['from_currency'])} less than a bank wire" if saving and Decimal(saving) > 0 else ""
    return (f"{q['provider_name']} is the cheapest option: {q['total_cost_pct']}% total cost{saving}. "
            "I've prepared the payment below. Check it, then tap **Confirm**.")


def _reply_bn(c) -> str:
    q = _best(c)
    return (f"সবচেয়ে কম খরচ {q['provider_name']}-এ, মোট খরচ {q['total_cost_pct']}%। পেমেন্টটি তৈরি করে রেখেছি। "
            "নিচের কার্ডটি দেখে **নিশ্চিত করুন** চাপুন।")


def demo_script(user: str) -> list:
    """Offline demo only: a fixed tool sequence. The tools, policy checks and approvals it hits are real."""
    if user == "abbu":
        return [
            [("tool", "list_payees", {})],
            [("tool", "get_quotes", lambda c: {"from_currency": "BDT", "to_currency": "CNY", "amount": "50000",
                                               "amount_type": "send", "mode": "payment",
                                               "purpose": "living_expenses", "payee_id": _payee_id(c, "person")})],
            [("tool", "draft_payment", lambda c: {"quote_id": _best(c)["id"], "payee_id": _payee_id(c, "person"),
                                                  "purpose": "living_expenses", "reference": "Monthly allowance"})],
            [("text", _reply_bn)],
        ]
    return [
        [("text", "Let me find your university."), ("tool", "list_payees", {})],
        [("tool", "get_quotes", lambda c: {"from_currency": "BDT", "to_currency": "CNY", "amount": "13000",
                                           "amount_type": "receive", "mode": "payment", "purpose": "tuition",
                                           "payee_id": _payee_id(c, "institution")})],
        [("tool", "draft_payment", lambda c: {"quote_id": _best(c)["id"], "payee_id": _payee_id(c, "institution"),
                                              "purpose": "tuition", "reference": "MSc CS spring 2027"})],
        [("text", _reply_en)],
    ]


def make_llm(user: str):
    if llm_mode() == "scripted":
        return ScriptedLLM(demo_script(user), done_text=(
            "Offline demo mode plays one scripted conversation. Add a Claude API key to chat freely."))
    import anthropic

    return ClaudeLLM(client=anthropic.Anthropic(api_key=api_key()))


# ---------------------------------------------------------------- state

def state():
    ss = st.session_state
    if "sb" not in ss:
        ss.sb = Sandbox()
        ss.sessions = {}
        ss.chat = {u: [] for u in USERS}
        ss.scam = {}
        ss.notices = []
    return ss


def agent(user: str) -> AgentSession:
    ss = state()
    if user not in ss.sessions:
        ss.sessions[user] = AgentSession(ss.sb, user, make_llm(user))
    return ss.sessions[user]


def record_turn(user: str, turn) -> None:
    state().chat[user].append({"role": "assistant", "text": turn.text or "…", "actions": turn.actions,
                               "mandates": turn.mandates, "tools": [c["name"] for c in turn.tool_calls],
                               "error": turn.error})


# ---------------------------------------------------------------- widgets

def render_card(user: str, action_id: str, key: str, t: dict) -> None:
    sb = state().sb
    card = action_card(sb.actions.get(action_id))
    with st.container(border=True):
        st.markdown(f"**{STATUS_ICON.get(card['status'], '•')} {card['title']}**")
        st.markdown("\n".join(f"- {line}" for line in card["lines"]))
        waiting = card["status"] == "awaiting_confirmation"
        if card["reasons"] and (waiting or card["blocked"]):
            (st.error if card["blocked"] else st.warning)(" · ".join(card["reasons"]))
        with st.expander(f"✓ {len(card['checks_passed'])} safety checks passed"):
            st.markdown("\n".join(f"- {c}" for c in card["checks_passed"]))
        if not waiting:
            approved = " with your PIN" if card["status"] == "executed" and card["needs_pin"] else ""
            st.caption(f"Status: {card['status'].replace('_', ' ')}{approved}")
            return
        cols = st.columns([2, 1, 1], vertical_alignment="bottom")
        pin = cols[0].text_input(t["pin"], type="password", key=f"pin_{key}", max_chars=6,
                                 placeholder="Required for this one") if card["needs_pin"] else None
        if cols[1].button(t["confirm"], key=f"ok_{key}", type="primary", width="stretch"):
            try:
                receipt = sb.confirm(user, action_id, pin or None)
                paid = f" · Marked “{receipt['deadline_paid']}” as paid." if receipt.get("deadline_paid") else ""
                state().notices.append(("success", f"✅ Done: {receipt['summary']}{paid}"))
                st.rerun()
            except ExecutionError as exc:
                if exc.code == "step_up_required" and not card["needs_pin"]:
                    st.rerun()  # it needs a PIN since it was drafted: the card now asks for it and says why
                st.error(" ".join([exc.message, *exc.reasons]))
            except PinLocked as exc:
                st.error(f"{exc}. Reset the sandbox in Demo controls.")
        if cols[2].button(t["reject"], key=f"no_{key}", width="stretch"):
            sb.reject(user, action_id)
            st.rerun()


def render_mandate(user: str, mandate_id: str, key: str, t: dict) -> None:
    sb = state().sb
    m = sb.mandates.get(mandate_id)
    with st.container(border=True):
        st.markdown(f"**📜 Rate mandate · {m['status']}**")
        st.markdown(m["description"])
        if m["status"] == "proposed":
            cols = st.columns([2, 1, 1], vertical_alignment="bottom")
            pin = cols[0].text_input(t["pin"], type="password", key=f"mpin_{key}", max_chars=6)
            if cols[1].button(t["sign"], key=f"msign_{key}", type="primary", width="stretch"):
                try:
                    sb.sign_mandate(user, mandate_id, pin)
                    state().notices.append(("success", "Mandate signed. Sathi will act only inside these limits."))
                    st.rerun()
                except (MandateError, PinLocked) as exc:
                    st.error(str(exc))
            if cols[2].button(t["decline"], key=f"mdecl_{key}", width="stretch"):
                sb.revoke_mandate(user, mandate_id)
                st.rerun()
        elif m["status"] == "active":
            st.caption(f"Left to convert: {fmt(m['remaining'], m['from_currency'])}")
            if st.button(t["revoke"], key=f"mrev_{key}"):
                sb.revoke_mandate(user, mandate_id)
                st.rerun()


def notify(events: list[dict]) -> None:
    for e in events:
        who = USERS.get(e["user_id"], {}).get("label", e["user_id"]).split(" · ")[0]
        if e["event"] == "executed":
            state().notices.append(("success", f"🤖 {who}'s mandate ran on its own: {e['summary']}"))
        elif e["event"] == "expired":
            state().notices.append(("info", f"{who}'s mandate expired."))
        elif e["event"] not in ("waiting", "no_balance"):
            state().notices.append(("warning", f"{who}'s mandate couldn't run: {'; '.join(e.get('reasons', []))}"))


def run_turn(user: str, prompt: str, t: dict) -> None:
    shown, _ = state().sb.redact_pin(user, prompt, audit=False)  # the agent session scrubs and logs it too
    state().chat[user].append({"role": "user", "text": shown})
    with st.status(t["working"], expanded=True) as status:
        turn = agent(user).send(prompt, on_event=lambda e: status.write(TOOL_LABELS.get(e["name"], e["name"])))
        status.update(label="Done", state="error" if turn.error else "complete", expanded=False)
    record_turn(user, turn)
    st.rerun()


# ---------------------------------------------------------------- layout

ss = state()
sb: Sandbox = ss.sb
mode = llm_mode()

with st.sidebar:
    st.markdown("## 🤝 Sathi · সাথী")
    st.caption("AI money companion for international students and their families. Sandbox money only.")
    user = st.radio("Signed in as", list(USERS), format_func=lambda u: USERS[u]["label"])
    t = TEXT[USERS[user]["lang"]]

    bal = sb.balances(user)
    st.markdown("#### Wallet")
    st.markdown("\n".join(f"- **{ccy}** {Decimal(amount):,.2f}" for ccy, amount in bal["balances"].items()))
    st.caption(f"Total ≈ USD {Decimal(bal['total_usd']):,.2f}")

    with st.expander("🛡️ How Sathi keeps money safe"):
        st.markdown(
            "- The AI can only read and prepare drafts. It has no tool that sends money.\n"
            "- Every draft is checked by fixed rules in code: limits, verified payee, scam risk, student file "
            "and more.\n"
            "- Only you approve, by tapping Confirm. Risky payments also need your PIN.\n"
            "- Every step goes into a tamper-evident audit log.")

    with st.expander("🎛️ Demo controls"):
        usd_cny = sb.feed.mid("USD", "CNY")
        new_rate = st.number_input("USD → CNY mid-market rate", value=float(usd_cny), step=0.01, format="%.4f")
        if st.button("Apply rate"):
            notify(sb.set_rate("CNY", Decimal(str(new_rate)))["mandate_events"])
            st.rerun()
        if st.button("📈 Random market move"):
            notify(sb.market_tick()["mandate_events"])
            st.rerun()
        if st.button("⏩ Skip ahead 1 day"):
            sb.advance_time(days=1)
            notify(sb.mandates.run())
            st.rerun()
        if st.button("🧹 New chat"):
            ss.sessions.pop(user, None)
            ss.chat[user] = []
            st.rerun()
        if st.button("♻️ Reset sandbox"):
            for k in ("sb", "sessions", "chat", "scam", "notices"):
                ss.pop(k, None)
            st.rerun()
        st.caption("Demo PINs: Nusrat 2468 · Abbu 1357")

    chain = sb.audit.verify_chain()
    n = chain["entries"]
    st.caption(("🔗 Audit chain intact" if chain["ok"] else "⚠️ Audit chain broken") +
               f" · {n} {'entry' if n == 1 else 'entries'}")
    st.caption({"claude": "AI: Claude", "scripted": "AI: offline demo script", None: "AI: not connected"}[mode])

with st.container():  # always present, so the tabs below keep their place and their selected tab
    for kind, message in ss.notices:
        getattr(st, kind)(message)
ss.notices = []

tab_chat, tab_approve, tab_wallet, tab_budget, tab_scam, tab_audit = st.tabs(
    ["💬 Chat", "✅ Approvals", "📒 Wallet", "📊 Budget", "🔍 Scam check", "🛡️ Audit log"],
    key="tab", on_change="rerun")

with tab_chat:
    if mode is None:
        st.info("Add a Claude API key (ANTHROPIC_API_KEY) to chat with Sathi. The other tabs work without it.")
    elif mode == "scripted":
        st.warning("Offline demo mode: replies are scripted, not written by Claude. The tools, rule checks and "
                   "approvals are real.")
    history = ss.chat[user]
    with st.chat_message("assistant", avatar="🤝"):
        st.markdown(WELCOME[user])
    for i, m in enumerate(history):
        with st.chat_message(m["role"], avatar=USERS[user]["avatar"] if m["role"] == "user" else "🤝"):
            st.markdown(m["text"])
            if m.get("tools"):
                st.caption("🔧 " + " → ".join(TOOL_LABELS.get(n, n) for n in m["tools"]))
            if m.get("error"):
                st.caption(f"Error detail: {m['error']}")
            for aid in m.get("actions", []):
                render_card(user, aid, f"c{i}_{aid}", t)
            for mid in m.get("mandates", []):
                render_mandate(user, mid, f"c{i}_{mid}", t)
    prompt = st.chat_input(t["ask"], disabled=mode is None)
    if not history and mode:
        cols = st.columns(len(SUGGESTIONS[user]))
        for n, (col, suggestion) in enumerate(zip(cols, SUGGESTIONS[user], strict=True)):
            if col.button(suggestion, key=f"suggest_{user}_{n}", width="stretch"):
                prompt = suggestion
    if prompt:
        run_turn(user, prompt, t)

with tab_approve:
    pending = sb.pending(user)
    open_mandates = [m for m in sb.list_mandates(user) if m["status"] in ("proposed", "active")]
    if not pending and not open_mandates:
        st.success("Nothing waiting for you.")
    for a in pending:
        render_card(user, a["id"], f"a_{a['id']}", t)
    for m in open_mandates:
        render_mandate(user, m["id"], f"a_{m['id']}", t)
    decided = [a for a in sb.recent_actions(user, 10) if a["status"] != "awaiting_confirmation"]
    if decided:
        st.markdown("#### Recent decisions")
        for a in decided:
            c = a["card"]
            st.markdown(f"{STATUS_ICON.get(c['status'], '•')} {c['title']} · {c['lines'][0]} · "
                        f"*{c['status'].replace('_', ' ')}*")

with tab_wallet:
    st.markdown("#### Payees")
    for p in sb.list_payees(user):
        cols = st.columns([3, 1, 2], vertical_alignment="center")
        badge = "✅ verified" if p["verified"] else ("⚠️ " + ", ".join(p["flags"]) if p["flags"] else "⏳ unverified")
        cols[0].markdown(f"**{p['display_name']}** · {p['payee_type']} · {p['currency']} · {p['account_number']}")
        cols[1].markdown(badge)
        if not p["verified"] and p["payee_type"] != "institution":
            with cols[2].form(f"verify_{p['id']}", border=False):
                pin = st.text_input(t["pin"], type="password", max_chars=6, key=f"vpin_{p['id']}")
                if st.form_submit_button(t["verify"]):
                    try:
                        sb.verify_payee(user, p["id"], pin)
                        ss.notices.append(("success", "Payee verified. Payments open after a 24-hour cooling-off "
                                                      "period."))
                        st.rerun()
                    except (SandboxError, PayeeError, PinLocked) as exc:
                        st.error(str(exc))
    st.markdown("#### Transactions")
    rows = [{"date": h["ts"][:10], "what": h["memo"], "category": h["category"] or "", **h["amounts"]}
            for h in sb.history(user, 40)]
    st.dataframe(pd.DataFrame(rows).fillna(""), hide_index=True)  # blank, not "None", for other currencies

with tab_budget:
    r = sb.runway(user)
    home = r["home_currency"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Free after upcoming bills", fmt(r["free_after_deadlines"], home))
    c2.metric("Months it lasts if income stops", r["months_if_income_stops"] or "—")
    c3.metric("Average monthly spending", fmt(r["avg_monthly_spending"], home))
    for d in r["upcoming_deadlines"]:
        st.markdown(f"📅 **{d['title']}**: {fmt(d['amount'], d['currency'])} due {d['due_date']} "
                    f"({d['days_left']} days)")
    summary = sb.budget_summary(user)
    st.markdown(f"#### Budget · {summary['month']}")
    if not summary["categories"]:
        st.caption("No budgets yet. Ask Sathi to set one.")
    for c in summary["categories"]:
        st.markdown(f"**{c['category'].title()}**: {fmt(c['spent'], c['currency'])} of "
                    f"{fmt(c['limit'], c['currency'])}")
        st.progress(min(c["pct_used"], 100) / 100)

with tab_scam:
    st.markdown("Paste a payment request you received (email, invoice, chat). The risk score comes from fixed "
                "rules in code, and Sathi explains it.")
    text = st.text_area("Message", height=180, key="scam_text")
    if st.button("Check it", type="primary") and text.strip():
        report = sb.analyze_message(user, text)
        explanation = None
        if mode == "claude":
            with st.spinner("Sathi is reading it…"):
                turn = agent(user).check_message(text)
            ss.chat[user].append({"role": "user", "text": "Please check this message I received."})
            record_turn(user, turn)
            explanation = turn.text
        ss.scam[user] = (report, explanation)
    if user in ss.scam:
        report, explanation = ss.scam[user]
        level = report["risk_level"]
        (st.error if level == "high" else st.warning if level == "medium" else st.success)(
            f"Scam risk {report['risk_score']}/100 ({level}). {report['advice']}")
        for f in report["flags"]:
            st.markdown(f"- **{f['id'].replace('_', ' ')}**: {f['why']}")
        if explanation:
            with st.chat_message("assistant", avatar="🤝"):
                st.markdown(explanation)

with tab_audit:
    chain = sb.audit.verify_chain()
    (st.success if chain["ok"] else st.error)(
        f"Hash chain {'verified' if chain['ok'] else 'BROKEN at entry ' + str(chain['first_bad_seq'])}: "
        f"{chain['entries']} entries. Each entry stores the hash of the one before it, so any edit to history "
        "shows up here.")
    entries = sb.audit.entries(user_id=user, limit=300)
    st.dataframe(pd.DataFrame([{"#": e["seq"], "time (UTC)": e["ts"][:19].replace("T", " "), "actor": e["actor"],
                                "event": e["event"], "details": dumps(e["data"])[:200]} for e in entries]),
                 hide_index=True)
    export = "\n".join(dumps(e) for e in reversed(entries))
    st.download_button("Download audit log (JSONL)", export, file_name=f"sathi_audit_{user}.jsonl")
