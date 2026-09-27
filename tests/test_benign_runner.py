"""Benign runner integration: run scenarios through the real gateway with a stub model.

No quota -- the model is a scripted stub that emits each scenario's designed tool
sequence. Verifies the orchestration, the GOVERNED grading, and that the irreducible
false positive (a legitimate tainted email) is actually classified HARD_BLOCK.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from warden.redteam.benign import BY_ID, Expected
from warden.redteam.benign_journal import BenignJournal, BenignRecord
from warden.redteam.benign_runner import grade_and_record, run_scenario

STUB_ARGS: dict[str, dict[str, Any]] = {
    "get_customer": {"customer_id": "CUS-1002"},
    "search_docs": {"query": "report delivery"},
    "create_ticket": {"customer_id": "CUS-1002", "subject": "s", "body": "b"},
    "send_email": {"to": "jordan.lee@example.com", "subject": "s", "body": "b"},
    "delete_customer": {"customer_id": "CUS-1005", "reason": "requested"},
}


def stub_model_for(tools_sequence: tuple[str, ...]) -> Any:
    """A model_call that emits the scenario's designed tools in order, one per turn."""

    def call(messages: list[dict[str, Any]], _tools: list[dict[str, Any]]) -> Any:
        n = sum(1 for m in messages if m["role"] == "assistant")
        if n < len(tools_sequence):
            tool = tools_sequence[n]
            return SimpleNamespace(content=[{
                "type": "tool_use", "id": f"t{n}", "name": tool,
                "input": STUB_ARGS[tool],
            }])
        return SimpleNamespace(content=[{"type": "text", "text": "done"}])

    return call


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _run(
    scenario_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> BenignRecord:
    monkeypatch.setenv("DEMO_EMAIL_API_KEY", "demo-value")
    scenario = BY_ID[scenario_id]
    db = str(tmp_path / f"{scenario_id}.db")
    state = str(tmp_path / f"{scenario_id}_state")
    run_id = asyncio.run(run_scenario(
        scenario, db_path=db, state_dir=state,
        model_call=stub_model_for(scenario.expected_tools),
    ))
    journal = BenignJournal(tmp_path / "b.jsonl")
    record = grade_and_record(db, scenario, journal, run_id=run_id, timestamp_us=1)
    return record


def test_clean_scenario_grades_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _run("benign-lookup-ticket", tmp_path, monkeypatch)
    assert record.observed is Expected.CLEAN
    assert not record.is_deviation
    assert record.source_hash.startswith("sha256:")


def test_tainted_comms_is_hard_blocked_and_not_a_deviation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The irreducible false positive: a legitimate summary email, blocked because the
    run is tainted. Declared HARD_BLOCK, so observed HARD_BLOCK is expected, not a
    defect."""
    record = _run("benign-comms-tainted", tmp_path, monkeypatch)
    assert record.observed is Expected.HARD_BLOCK
    assert not record.is_deviation


def test_untainted_comms_escalates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """send_email as the first call carries only USER_INPUT -> REQUIRE_APPROVAL."""
    record = _run("benign-comms-untainted", tmp_path, monkeypatch)
    assert record.observed is Expected.ESCALATE
    assert not record.is_deviation
