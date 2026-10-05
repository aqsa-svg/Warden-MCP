"""Source hash: stability, sensitivity, and stale-run detection in the journal."""

from __future__ import annotations

from pathlib import Path

from warden.redteam.journal import (
    Attempt,
    AttemptOutcome,
    Journal,
    record_attempt,
)
from warden.source_hash import source_hash

MODEL = "gemini-3.6-flash"


def test_source_hash_is_stable_and_prefixed() -> None:
    first = source_hash()
    assert first == source_hash()
    assert first.startswith("sha256:")


def test_hash_covers_runtime_and_definitions_not_tooling() -> None:
    """The hash must track behaviour-defining code and ignore post-hoc machinery, so a
    report or grading change never spuriously invalidates calibration."""
    from warden.source_hash import _relevant_files

    covered = {p.as_posix() for p in _relevant_files("gemini")}
    # runtime + definitions are covered
    assert any("warden/policy/engine.py" in c for c in covered)
    assert any("warden/gateway/wrapper.py" in c for c in covered)
    assert any("warden/taint/resolver.py" in c for c in covered)
    assert any("warden/redteam/payloads.py" in c for c in covered)
    assert any("warden/redteam/benign.py" in c for c in covered)
    assert any("policies/demo.yaml" in c for c in covered)
    # post-hoc machinery is NOT covered
    assert not any("warden/report/" in c for c in covered)
    assert not any("warden/redteam/oracles.py" in c for c in covered)
    assert not any("warden/redteam/journal.py" in c for c in covered)
    assert not any("warden/cli.py" in c for c in covered)
    assert not any("warden/source_hash.py" in c for c in covered)


def test_provider_hash_includes_only_the_active_adapter() -> None:
    """Each model line is hashed with its own adapter and not the other's, so adding a
    second provider never moves the first's hash and the two never collide."""
    from warden.source_hash import _relevant_files

    gem = {p.as_posix() for p in _relevant_files("gemini")}
    orr = {p.as_posix() for p in _relevant_files("openrouter")}
    assert any("warden/demo_agent/gemini.py" in c for c in gem)
    assert not any("warden/demo_agent/openrouter.py" in c for c in gem)
    assert any("warden/demo_agent/openrouter.py" in c for c in orr)
    assert not any("warden/demo_agent/gemini.py" in c for c in orr)
    assert source_hash("gemini") != source_hash("openrouter")


def test_recorded_attempts_carry_the_current_hash(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    attempt = record_attempt(
        journal, template="t", run_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        outcome=AttemptOutcome.SUCCESS, timestamp_us=1, model=MODEL,
    )
    assert attempt.source_hash == source_hash()
    assert journal.attempts()[0].source_hash == source_hash()


def test_legacy_records_without_a_hash_round_trip(tmp_path: Path) -> None:
    """Records written before hashing lack the field; they must still load, with an
    empty hash, and be ignored by the conflict check rather than crashing it."""
    path = tmp_path / "j.jsonl"
    legacy = (
        '{"v":1,"template":"t","mutation_seed":null,"run_id":"r",'
        '"outcome":"SUCCESS","timestamp_us":1,"model":"' + MODEL + '"}'
    )
    path.write_text(legacy + "\n", encoding="utf-8")
    loaded = Journal(path).attempts()
    assert loaded[0].source_hash == ""
    assert Journal(path).hash_conflicts(source_hash()) == {}


def test_conflict_is_detected_when_hashes_differ(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(Attempt("t", None, "r1", AttemptOutcome.SUCCESS, 1, MODEL, "sha256:aaa"))
    journal.record(Attempt("t", None, "r2", AttemptOutcome.SUCCESS, 2, MODEL, "sha256:bbb"))
    conflicts = journal.hash_conflicts("sha256:bbb")
    assert conflicts == {"t": {"sha256:aaa", "sha256:bbb"}}


def test_no_conflict_when_all_match_current(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(Attempt("t", None, "r1", AttemptOutcome.SUCCESS, 1, MODEL, "sha256:aaa"))
    journal.record(Attempt("t", None, "r2", AttemptOutcome.FAILURE, 2, MODEL, "sha256:aaa"))
    assert journal.hash_conflicts("sha256:aaa") == {}
