"""Benign journal: round-trip, legacy tolerance, deviation flag, resume."""

from __future__ import annotations

from pathlib import Path

from warden.redteam.benign import Expected
from warden.redteam.benign_journal import BenignJournal, BenignRecord

MODEL = "gemini-3.6-flash"


def make(scenario: str, observed: Expected, expected: Expected) -> BenignRecord:
    return BenignRecord(
        scenario_id=scenario, run_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        observed=observed, expected=expected, timestamp_us=1, model=MODEL,
        source_hash="sha256:abc",
    )


def test_record_round_trips(tmp_path: Path) -> None:
    journal = BenignJournal(tmp_path / "b.jsonl")
    original = make("benign-lookup-ticket", Expected.CLEAN, Expected.CLEAN)
    journal.record(original)
    back = journal.records()[0]
    assert back.scenario_id == original.scenario_id
    assert back.observed is Expected.CLEAN
    assert back.source_hash == "sha256:abc"


def test_deviation_flag() -> None:
    """Declared-irreducible outcomes are not deviations; unexpected blocks are."""
    assert not make("benign-comms-tainted", Expected.HARD_BLOCK, Expected.HARD_BLOCK).is_deviation
    assert make("benign-lookup-ticket", Expected.HARD_BLOCK, Expected.CLEAN).is_deviation
    assert make("benign-comms-untainted", Expected.HARD_BLOCK, Expected.ESCALATE).is_deviation


def test_legacy_record_without_hash_loads(tmp_path: Path) -> None:
    path = tmp_path / "b.jsonl"
    path.write_text(
        '{"v":1,"scenario_id":"s","run_id":"r","observed":"CLEAN",'
        '"expected":"CLEAN","timestamp_us":1,"model":"' + MODEL + '"}\n',
        encoding="utf-8",
    )
    assert BenignJournal(path).records()[0].source_hash == ""


def test_resume_skips_done_scenarios(tmp_path: Path) -> None:
    journal = BenignJournal(tmp_path / "b.jsonl")
    journal.record(make("benign-lookup-ticket", Expected.CLEAN, Expected.CLEAN))
    all_ids = ["benign-lookup-ticket", "benign-triage", "benign-comms-tainted"]
    assert journal.outstanding(all_ids, MODEL) == ["benign-triage", "benign-comms-tainted"]
    assert journal.done_scenarios(MODEL) == {"benign-lookup-ticket"}


def test_other_model_is_not_counted_done(tmp_path: Path) -> None:
    journal = BenignJournal(tmp_path / "b.jsonl")
    journal.record(make("benign-triage", Expected.CLEAN, Expected.CLEAN))
    assert journal.outstanding(["benign-triage"], "some-other-model") == ["benign-triage"]
