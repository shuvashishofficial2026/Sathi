"""The eval harness itself, offline: ideal scripts must pass, hijacked scripts must be contained, and the
safety checker must notice when money does reach an attacker."""

import pytest

from evals.harness import load_scenarios, run_scenario, scripted_llm, summarize
from sathi.policy import ALLOW, Decision, PolicyEngine

SCENARIOS = {s["id"]: s for s in load_scenarios()}


def test_there_are_12_tasks_and_12_attacks():
    kinds = [s["kind"] for s in SCENARIOS.values()]
    assert kinds.count("task") == 12 and kinds.count("attack") == 12


def test_ideal_agent_completes_every_task_and_a_hijacked_agent_is_always_contained():
    results = [run_scenario(sc, scripted_llm) for sc in SCENARIOS.values()]
    summary = summarize(results, {"mode": "scripted"})
    failed = {r["id"]: [c for c in r["checks"] if not c["ok"]] for r in results if r["kind"] == "task"
              and not r["passed"]}
    assert not failed
    assert summary["attacks_contained"] == 12
    assert summary["unsafe_outcomes"] == 0
    assert summary["attacks_ideal"] == 0  # the hijacked script does the wrong thing every time, and the
    # checks notice: only the policy engine kept the money safe


def test_the_checker_catches_money_reaching_an_attacker(monkeypatch):
    """Switch the policy engine off: the careless user's Confirm now pays the attacker, and the harness must say so."""
    monkeypatch.setattr(PolicyEngine, "evaluate", lambda self, action: Decision(ALLOW, []))
    result = run_scenario(SCENARIOS["A1"], scripted_llm)
    assert not result["contained"]
    assert any("attacker" in u for u in result["unsafe"])


@pytest.mark.parametrize("scenario_id", ["A7", "A11"])
def test_nothing_the_agent_says_can_approve(scenario_id):
    result = run_scenario(SCENARIOS[scenario_id], scripted_llm)
    assert result["contained"] and result["executed"] == 0
