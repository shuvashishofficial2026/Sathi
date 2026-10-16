"""Writes the evaluation results as JSON, an audit log (JSONL) and a self-contained HTML report."""

from __future__ import annotations

import html
import json
from pathlib import Path

from sathi.util import dumps

CSS = """
:root { --bg:#f7f8f8; --card:#fff; --ink:#1d2327; --muted:#5b6670; --line:#e1e5e8; --ok:#0f766e;
        --bad:#b42318; --warn:#9a6700; --chip:#eef2f3; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#121517; --card:#1b1f22; --ink:#e7eaec; --muted:#9aa5ad; --line:#2c3236; --ok:#3cc4b4;
          --bad:#ff7b6e; --warn:#e3b341; --chip:#24292d; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui, -apple-system, "Segoe UI",
       "Noto Sans Bengali", sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 32px 0 12px; }
.meta { color: var(--muted); font-size: 13px; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600;
         background:var(--chip); }
.cards { display:grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap:12px; margin-top:16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }
.card b { display:block; font-size:24px; } .card span { color:var(--muted); font-size:13px; }
table { width:100%; border-collapse: collapse; background:var(--card); border:1px solid var(--line);
        border-radius:12px; overflow:hidden; font-size:14px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight:600; font-size:12px; text-transform: uppercase; letter-spacing: .03em; }
.table-wrap { overflow-x:auto; }
.ok { color: var(--ok); font-weight:600; } .bad { color: var(--bad); font-weight:600; }
.warn { color: var(--warn); }
details { background:var(--card); border:1px solid var(--line); border-radius:12px; margin:10px 0; }
summary { cursor:pointer; padding:12px 14px; font-weight:600; }
details > div { padding: 0 14px 14px; }
.turn { border-left: 3px solid var(--line); padding: 4px 0 4px 12px; margin: 10px 0; }
.who { font-size:12px; color:var(--muted); text-transform: uppercase; letter-spacing: .04em; }
pre { white-space: pre-wrap; word-break: break-word; background:var(--chip); padding:8px 10px; border-radius:8px;
      font-size:12.5px; margin:6px 0; }
ul.checks { padding-left: 18px; margin: 6px 0; }
.small { font-size: 12.5px; color: var(--muted); }
td.small { overflow-wrap: anywhere; min-width: 240px; }
"""


def _e(value) -> str:
    return html.escape(str(value))


def _checks(r: dict) -> str:
    items = [f'<li><span class="{"ok" if c["ok"] else "bad"}">{"✓" if c["ok"] else "✗"}</span> {_e(c["name"])}'
             + (f' <span class="small">({_e(c["detail"])})</span>' if c["detail"] else "") + "</li>"
             for c in r["checks"]]
    items += [f'<li><span class="bad">UNSAFE</span> {_e(u)}</li>' for u in r["unsafe"]]
    items += [f'<li><span class="warn">slip</span> {_e(s)}</li>' for s in r["slips"]]
    return f'<ul class="checks">{"".join(items) or "<li>No checks</li>"}</ul>'


def _transcript(r: dict) -> str:
    out = []
    for t in r["transcript"]:
        out.append(f'<div class="turn"><div class="who">User</div>{_e(t["user"])}')
        if t.get("pasted"):
            out.append(f'<div class="who">Pasted content (untrusted)</div><pre>{_e(t["pasted"])}</pre>')
        out.append("</div>")
        for c in t["tool_calls"]:
            flag = ' <span class="bad">error</span>' if c["is_error"] else ""
            out.append(f'<div class="turn"><div class="who">Tool call{flag}</div><b>{_e(c["name"])}</b>'
                       f'<pre>{_e(json.dumps(c["input"], ensure_ascii=False))}</pre>'
                       f'<div class="small">→ {_e(c["result"])}</div></div>')
        for card in t["action_cards"]:
            reasons = f'<div class="warn">{_e(" · ".join(card["reasons"]))}</div>' if card["reasons"] else ""
            out.append(f'<div class="turn"><div class="who">Draft card · {_e(card["status"])}</div>'
                       f'<b>{_e(card["title"])}</b><pre>{_e(chr(10).join(card["lines"]))}</pre>{reasons}</div>')
        error = f'<div class="bad">{_e(t["error"])}</div>' if t.get("error") else ""
        out.append(f'<div class="turn"><div class="who">Sathi</div><pre>{_e(t["text"])}</pre>{error}</div>')
    for a in r["user_actions"]:
        out.append(f'<div class="turn"><div class="who">Simulated user</div>{_e(a)}</div>')
    return "".join(out)


def _audit(r: dict) -> str:
    rows = "".join(f'<tr><td>{e["seq"]}</td><td>{_e(e["actor"])}</td><td>{_e(e["event"])}</td>'
                   f'<td class="small">{_e(dumps(e["data"])[:220])}</td></tr>' for e in r["audit"])
    return (f'<div class="table-wrap"><table><tr><th>#</th><th>Actor</th><th>Event</th><th>Details</th></tr>{rows}'
            "</table></div>")


def to_html(summary: dict, results: list[dict]) -> str:
    s = summary
    mode = ("Claude (live model)" if s["mode"] == "claude"
            else "Offline script: ideal agent for tasks, fully hijacked agent for attacks")
    saved = ", ".join(f"{ccy} {float(v):,.2f}" for ccy, v in s["saved_vs_bank"].items()) or "—"
    tokens = s["tokens"]
    token_line = (f'{tokens.get("input_tokens", 0):,} in · {tokens.get("output_tokens", 0):,} out · '
                  f'{tokens.get("cache_read_input_tokens", 0):,} cached') if tokens else "—"
    cards = [
        (f'{s["tasks_passed"]}/{s["tasks_total"]}', "tasks completed"),
        (f'{s["attacks_contained"]}/{s["attacks_total"]}', "attacks contained (no money lost)"),
        (f'{s["unsafe_outcomes"]}', "unsafe outcomes"),
        (f'{s["attacks_ideal"]}/{s["attacks_total"]}', "attacks where the agent also behaved ideally"),
        (f'{s["avg_tool_calls_per_task"]}', "tool calls per task"),
        (saved, "saved vs bank wire"),
    ]
    rows = []
    for r in results:
        status = ('<span class="ok">PASS</span>' if r["passed"] else
                  '<span class="warn">CONTAINED</span>' if r["kind"] == "attack" and r["contained"] else
                  '<span class="bad">FAIL</span>')
        failed = [c["name"] for c in r["checks"] if not c["ok"]]
        rows.append(f'<tr><td><a href="#{_e(r["id"])}">{_e(r["id"])}</a></td><td>{_e(r["title"])}</td>'
                    f'<td>{status}</td><td>{len(r["unsafe"])}</td>'
                    f'<td class="small">{_e("; ".join(failed)) or "—"}</td><td>{r["tool_calls"]}</td>'
                    f'<td>{r["drafts"]} / {r["executed"]}</td><td>{r["seconds"]}s</td></tr>')
    details = "".join(
        f'<details id="{_e(r["id"])}"><summary>{_e(r["id"])} · {_e(r["title"])}</summary><div>'
        f'<h3>Checks</h3>{_checks(r)}<h3>Conversation</h3>{_transcript(r)}<h3>Audit log</h3>{_audit(r)}'
        "</div></details>" for r in results)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sathi evaluation report</title><style>{CSS}</style></head>
<body><main>
<h1>Sathi evaluation report</h1>
<div class="meta"><span class="badge">{_e(mode)}</span> · model {_e(s.get("model") or "—")} ·
effort {_e(s.get("effort") or "—")} · {_e(s["started_at"])} · code {_e(s.get("commit") or "—")}</div>
<div class="cards">{"".join(f'<div class="card"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for v, k in cards)}</div>
<p class="small">Each scenario starts from a fresh sandbox. In attacks the simulated user is careless and taps
Confirm, with the PIN, on everything the agent prepares, so "contained" means the policy engine stopped the money
even then. Checks read the ledger, drafts, payees and audit log, not just the reply. Tokens: {_e(token_line)}.
Total time {_e(s["seconds"])}s. Slips flagged for review: {_e(s["slips"])}.</p>
<h2>Scenarios</h2>
<div class="table-wrap"><table><tr><th>ID</th><th>Scenario</th><th>Result</th><th>Unsafe</th>
<th>Failed checks</th><th>Tools</th><th>Drafts / executed</th><th>Time</th></tr>{"".join(rows)}</table></div>
<h2>Details</h2>{details}
</main></body></html>"""


def write(out_dir: Path, summary: dict, results: list[dict]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"eval_{summary['mode']}"
    paths = {"json": out_dir / f"{stem}.json", "html": out_dir / f"{stem}.html",
             "audit": out_dir / f"{stem}_audit.jsonl"}
    paths["json"].write_text(json.dumps({"summary": summary, "results": results}, ensure_ascii=False, indent=1,
                                        default=str), encoding="utf-8")
    paths["html"].write_text(to_html(summary, results), encoding="utf-8")
    with paths["audit"].open("w", encoding="utf-8") as f:
        for r in results:
            for e in r["audit"]:
                f.write(dumps({"scenario": r["id"], **e}) + "\n")
    return paths
