"""Calibration journal: resumability, model keying, and error handling."""

from __future__ import annotations

from pathlib import Path

from warden.redteam.journal import (
    Attempt,
    AttemptOutcome,
    Journal,
    Plan,
    outstanding,
    requests_needed,
)

MODEL = "gemini-3.6-flash"
OTHER = "gemini-3.1-pro-preview"


def attempt(
    template: str, outcome: AttemptOutcome, model: str = MODEL, run: str = "r"
) -> Attempt:
    return Attempt(template, None, run, outcome, 1, model)


def test_records_round_trip(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    original = Attempt("t1", "seed-7", "run-1", AttemptOutcome.SUCCESS, 99, MODEL)
    journal.record(original)
    assert journal.attempts() == [original]


def test_journal_is_append_only_across_sessions(tmp_path: Path) -> None:
    """Resumability: a second invocation must see what the first recorded."""
    path = tmp_path / "j.jsonl"
    Journal(path).record(attempt("t1", AttemptOutcome.FAILURE, run="a"))
    Journal(path).record(attempt("t1", AttemptOutcome.SUCCESS, run="b"))
    assert [a.run_id for a in Journal(path).attempts()] == ["a", "b"]


def test_missing_journal_reads_as_empty(tmp_path: Path) -> None:
    assert Journal(tmp_path / "absent.jsonl").attempts() == []


def test_tally_reports_a_fraction_never_a_bare_percentage(tmp_path: Path) -> None:
    """n=3 cannot honestly be presented as 67%."""
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(attempt("t1", AttemptOutcome.SUCCESS, run="a"))
    journal.record(attempt("t1", AttemptOutcome.SUCCESS, run="b"))
    journal.record(attempt("t1", AttemptOutcome.FAILURE, run="c"))
    assert journal.tally("t1", MODEL).fraction == "2/3"


def test_errors_are_excluded_from_both_numerator_and_denominator(
    tmp_path: Path
) -> None:
    """A run the quota interrupted is not evidence. Counting it as a failure would
    bias the rate in the flattering direction."""
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(attempt("t1", AttemptOutcome.SUCCESS, run="a"))
    journal.record(attempt("t1", AttemptOutcome.ERROR, run="b"))
    tally = journal.tally("t1", MODEL)
    assert tally == (1, 1, 1)
    assert tally.fraction == "1/1"


def test_attempts_against_another_model_are_not_evidence(tmp_path: Path) -> None:
    """An ungoverned rate is a property of a specific model. Counting a different
    model's runs toward this one's denominator would make suite.json look
    authoritative while being wrong."""
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(attempt("t1", AttemptOutcome.SUCCESS, model=OTHER, run="a"))
    journal.record(attempt("t1", AttemptOutcome.FAILURE, model=MODEL, run="b"))
    assert journal.tally("t1", MODEL) == (0, 1, 0)
    assert journal.tally("t1", OTHER) == (1, 1, 0)


def test_outstanding_computes_only_what_is_missing(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(attempt("t1", AttemptOutcome.FAILURE, run="a"))
    plan = Plan(templates=("t1", "t2"), runs_per_template=3, model=MODEL)
    items = outstanding(plan, journal)
    assert [(i.template, i.remaining) for i in items] == [("t1", 2), ("t2", 3)]


def test_an_errored_attempt_is_retried_not_counted(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    for run in ("a", "b"):
        journal.record(attempt("t1", AttemptOutcome.ERROR, run=run))
    plan = Plan(templates=("t1",), runs_per_template=3, model=MODEL)
    assert outstanding(plan, journal)[0].remaining == 3


def test_request_estimate_drives_the_daily_decision(tmp_path: Path) -> None:
    """The number that tells you whether today's budget covers the remaining work."""
    journal = Journal(tmp_path / "j.jsonl")
    journal.record(attempt("t1", AttemptOutcome.SUCCESS, run="a"))
    plan = Plan(templates=("t1", "t2", "t3"), runs_per_template=3, model=MODEL)
    assert requests_needed(outstanding(plan, journal), per_run=5) == (2 + 3 + 3) * 5


def test_completed_plan_needs_nothing(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    for run in ("a", "b", "c"):
        journal.record(attempt("t1", AttemptOutcome.FAILURE, run=run))
    plan = Plan(templates=("t1",), runs_per_template=3, model=MODEL)
    assert requests_needed(outstanding(plan, journal), per_run=5) == 0
