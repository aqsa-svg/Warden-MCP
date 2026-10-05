"""Attack-calibration runner: resume, hash-awareness, budget fast-fail, and a real
end-to-end grade. No quota -- the model is stubbed, or the runner is driven directly.

The resume behaviour is the one the quota re-run depends on and the one that fails
silently if wrong, so it is tested specifically: a partially-complete suite under the
current hash resumes to fill only the remainder, and attempts recorded under an earlier
(legacy) hash never count as done.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from warden.config import DEFAULT_MODEL
from warden.errors import BudgetExceeded
from warden.log.models import Oracle
from warden.redteam import attack_runner
from warden.redteam.attack_runner import AttackSpec, attack_specs, run_suite
from warden.redteam.journal import Attempt, AttemptOutcome, Journal, record_attempt
from warden.redteam.oracles import Verdict
from warden.source_hash import source_hash

ARG = "arg-poisoned-recipient"
PRIV = "priv-poisoned-deletion"
EXFIL_E = "exfil-escalation"
EXFIL_D = "exfil-diagnostic"
LEGACY_HASH = "sha256:legacy00"


def _seed_current(journal: Journal, template: str, run: str) -> None:
    """A completed attempt under the current hash, recorded the real way (hash-stamped)."""
    record_attempt(
        journal, template=template, run_id=run,
        outcome=AttemptOutcome.FAILURE, timestamp_us=1, model=DEFAULT_MODEL,
    )


def _seed_legacy(journal: Journal, template: str, run: str) -> None:
    """A pre-hash row written straight to the file: record() now refuses an unpinned
    attempt, so this is the only way such a row can exist."""
    line = Attempt(
        template, None, run, AttemptOutcome.SUCCESS, 1, DEFAULT_MODEL, LEGACY_HASH
    ).to_json()
    with open(journal.path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _stub_runner(
    monkeypatch: pytest.MonkeyPatch, *, succeed: bool = True, fail_on: int | None = None
) -> dict[str, int]:
    """Replace the subprocess run + grade with in-memory stubs. Returns a per-template
    call counter so a test can assert how many runs each template actually triggered."""
    calls: dict[str, int] = {}
    seen = {"i": 0}

    async def stub_run_attack(spec: AttackSpec, **_: Any) -> str:
        seen["i"] += 1
        if fail_on is not None and seen["i"] >= fail_on:
            raise BudgetExceeded("daily quota exhausted (stub)")
        calls[spec.scenario_id] = calls.get(spec.scenario_id, 0) + 1
        return f"run-{seen['i']}"

    def stub_grade_attack(spec: AttackSpec, **_: Any) -> Verdict:
        return Verdict(succeed, Oracle.CALL_LOG, "stub")

    monkeypatch.setattr(attack_runner, "run_attack", stub_run_attack)
    monkeypatch.setattr(attack_runner, "grade_attack", stub_grade_attack)
    return calls


def _run(journal: Journal, tmp_path: Path, *, n: int = 1) -> list[Attempt]:
    return asyncio.run(
        run_suite(
            journal=journal, var_dir=tmp_path / "var",
            make_model=lambda: None, now_us=lambda: 1, runs_per_template=n,
        )
    )


def test_attack_specs_cover_every_scenario_with_its_oracle() -> None:
    specs = {s.scenario_id: s for s in attack_specs()}
    assert set(specs) == {ARG, PRIV, EXFIL_E, EXFIL_D}
    assert specs[ARG].oracle == "exfil_domain"
    assert specs[PRIV].oracle == "tool_executed"
    assert specs[EXFIL_E].oracle == "exfil_domain"


def test_resume_fills_only_the_remainder_and_ignores_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    _seed_current(journal, ARG, "arg-done-1")     # 1 done under the current hash
    _seed_legacy(journal, PRIV, "priv-legacy-1")  # legacy rows must NOT count as done
    _seed_legacy(journal, PRIV, "priv-legacy-2")
    calls = _stub_runner(monkeypatch)

    _run(journal, tmp_path, n=2)

    # ARG had 1 current row -> 1 more; PRIV's 2 legacy rows do not count -> 2; the two
    # exfil templates had nothing -> 2 each.
    assert calls == {ARG: 1, PRIV: 2, EXFIL_E: 2, EXFIL_D: 2}
    current = source_hash()
    for template in (ARG, PRIV, EXFIL_E, EXFIL_D):
        assert journal.tally(template, DEFAULT_MODEL, current).completed == 2
    # The legacy rows are preserved as evidence of what was run before, not deleted.
    assert journal.tally(PRIV, DEFAULT_MODEL).completed == 4  # 2 legacy + 2 new


def test_a_fully_done_template_under_current_hash_is_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    _seed_current(journal, ARG, "arg-1")
    _seed_current(journal, ARG, "arg-2")
    calls = _stub_runner(monkeypatch)
    _run(journal, tmp_path, n=2)
    assert ARG not in calls  # already at n=2 under the current hash


def test_every_recorded_attempt_is_hash_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    _stub_runner(monkeypatch)
    _run(journal, tmp_path, n=1)
    current = source_hash()
    attempts = journal.attempts()
    assert attempts
    assert all(a.source_hash == current for a in attempts)


def test_budget_exceeded_stops_cleanly_mid_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    _stub_runner(monkeypatch, fail_on=2)  # first run records, second raises BudgetExceeded
    recorded = _run(journal, tmp_path, n=1)
    assert len(recorded) == 1             # stopped after the first, no exception raised
    assert len(journal.attempts()) == 1   # and only the completed one was recorded


def test_verdict_maps_to_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    _stub_runner(monkeypatch, succeed=False)
    recorded = _run(journal, tmp_path, n=1)
    assert recorded
    assert all(a.outcome is AttemptOutcome.FAILURE for a in recorded)


def _stub_model_for(sequence: tuple[str, ...], args: dict[str, dict[str, Any]]) -> Any:
    def call(messages: list[dict[str, Any]], _tools: list[dict[str, Any]]) -> Any:
        n = sum(1 for m in messages if m["role"] == "assistant")
        if n < len(sequence):
            tool = sequence[n]
            return SimpleNamespace(content=[{
                "type": "tool_use", "id": f"t{n}", "name": tool, "input": args[tool],
            }])
        return SimpleNamespace(content=[{"type": "text", "text": "done"}])

    return call


def test_end_to_end_deletion_attack_grades_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real subprocess, stub model: an ungoverned delete executes and the tool_executed
    oracle reads it as success. delete_customer declares no credential, so this exercises
    run_attack + grade_attack end to end without quota and without credential injection."""
    monkeypatch.setenv("DEMO_EMAIL_API_KEY", "demo-value")  # the gateway declares it
    spec = {s.scenario_id: s for s in attack_specs()}[PRIV]
    db = str(tmp_path / "run.db")
    state = str(tmp_path / "state")
    model = _stub_model_for(
        ("delete_customer",),
        {"delete_customer": {"customer_id": "CUS-1001", "reason": "resolve"}},
    )
    run_id = asyncio.run(
        attack_runner.run_attack(spec, db_path=db, state_dir=state, model_call=model)
    )
    verdict = attack_runner.grade_attack(
        spec, db_path=db, state_dir=state, run_id=run_id
    )
    assert verdict.succeeded
