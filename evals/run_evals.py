"""Run the evaluation scenarios and write the report.

    python -m evals.run_evals                   # the real agent on Claude (needs ANTHROPIC_API_KEY)
    python -m evals.run_evals --mode scripted   # offline: ideal agent for tasks, hijacked agent for attacks
    python -m evals.run_evals --only T1,A3      # a subset

Writes evidence/eval_<mode>.html, .json and _audit.jsonl. Exits with 1 if any unsafe outcome is found.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from evals import report
from evals.harness import load_scenarios, run_scenario, scripted_llm, summarize

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["claude", "scripted"], default="claude")
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("--kind", choices=["task", "attack"])
    ap.add_argument("--model", help="Claude model (default: SATHI_MODEL or claude-opus-5-5)")
    ap.add_argument("--effort", help="low, medium or high (default: SATHI_EFFORT or medium)")
    ap.add_argument("--out", default=str(ROOT / "evidence"))
    args = ap.parse_args(argv)

    scenarios = load_scenarios()
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        scenarios = [s for s in scenarios if s["id"] in wanted]
    if args.kind:
        scenarios = [s for s in scenarios if s["kind"] == args.kind]
    if not scenarios:
        print("No scenarios selected.")
        return 2

    if args.mode == "claude":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("Set ANTHROPIC_API_KEY to run against Claude, or use --mode scripted for the offline run.")
            return 2
        import anthropic

        from sathi.agent import ClaudeLLM

        client = anthropic.Anthropic()
        probe = ClaudeLLM(client=client, model=args.model, effort=args.effort)
        model, effort = probe.model, probe.effort

        def factory(scenario, setup):
            return ClaudeLLM(client=client, model=model, effort=effort)
    else:
        model = effort = None

        def factory(scenario, setup):
            return scripted_llm(scenario, setup)

    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    meta = {"mode": args.mode, "model": model, "effort": effort, "commit": commit,
            "started_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}

    results = []
    for sc in scenarios:
        r = run_scenario(sc, factory)
        results.append(r)
        status = "PASS" if r["passed"] else ("CONTAINED" if r["kind"] == "attack" and r["contained"] else "FAIL")
        print(f"{r['id']:<4} {status:<9} {r['title']}  ({r['tool_calls']} tools, {r['seconds']}s)")
        for c in r["checks"]:
            if not c["ok"]:
                print(f"       ✗ {c['name']} {c['detail']}")
        for u in r["unsafe"]:
            print(f"       UNSAFE {u}")

    summary = summarize(results, meta)
    paths = report.write(Path(args.out), summary, results)
    print(f"\nTasks completed {summary['tasks_passed']}/{summary['tasks_total']} · attacks contained "
          f"{summary['attacks_contained']}/{summary['attacks_total']} · unsafe outcomes {summary['unsafe_outcomes']}"
          f" · slips {summary['slips']}")
    print(f"Report: {paths['html']}")
    return 1 if summary["unsafe_outcomes"] else 0


if __name__ == "__main__":
    sys.exit(main())
