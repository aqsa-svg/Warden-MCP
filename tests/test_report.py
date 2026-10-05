"""The results report pins every rate to the current source hash.

A number produced by code that no longer matches the frozen hash must never be
presented as a current result -- the same stance the methodology takes everywhere else,
and the one the README's table placeholders assume. Table 2 already filtered; these
tests hold Table 1 to it, guarding the bug where 3/3 successes recorded under an older
hash rendered as a current rate.
"""

from __future__ import annotations

from pathlib import Path

from warden.redteam.benign_journal import BenignJournal
from warden.redteam.journal import Attempt, AttemptOutcome, Journal
from warden.report.generate import attack_rows, render

MODEL = "gemini-3.6-flash"
CURRENT = "sha256:current0"
OLD = "sha256:old00000"
TEMPLATE = "arg-poisoned-recipient"  # a real key in generate._CONTROLS


def _record(journal: Journal, run: str, source_hash: str) -> None:
    journal.record(
        Attempt(TEMPLATE, None, run, AttemptOutcome.SUCCESS, 1, MODEL, source_hash)
    )


def _append_legacy(journal: Journal, run: str) -> None:
    """A pre-hash (blank source_hash) row, written straight to the file: record() now
    refuses an unpinned attempt, so this is the only way a legacy row can exist."""
    line = Attempt(TEMPLATE, None, run, AttemptOutcome.SUCCESS, 1, MODEL, "").to_json()
    with open(journal.path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _row(journal: Journal):  # type: ignore[no-untyped-def]
    return next(
        r for r in attack_rows(journal, MODEL, CURRENT) if r.template == TEMPLATE
    )


def test_attack_row_shows_a_rate_only_under_the_current_hash(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    _record(journal, "a", CURRENT)
    _record(journal, "b", CURRENT)
    assert _row(journal).ungoverned == "2/2"


def test_attack_row_under_an_old_hash_is_pending_not_a_rate(tmp_path: Path) -> None:
    """The bug this guards: three successes under an old hash rendered as 3/3. They must
    show pending, with the excluded count visible, never as a current rate."""
    journal = Journal(tmp_path / "j.jsonl")
    for run in ("a", "b", "c"):
        _record(journal, run, OLD)
    row = _row(journal)
    assert "pending" in row.ungoverned
    assert "3" in row.ungoverned  # the excluded count travels with the omission
    assert "3/3" not in row.ungoverned


def test_blank_hash_attempts_are_also_excluded(tmp_path: Path) -> None:
    """Pre-hashing records (blank source_hash) cannot be confirmed against current code,
    so they are excluded exactly like a mismatched hash."""
    journal = Journal(tmp_path / "j.jsonl")
    _append_legacy(journal, "a")
    assert "pending" in _row(journal).ungoverned


def test_template_never_attempted_is_omitted(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    assert all(r.template != TEMPLATE for r in attack_rows(journal, MODEL, CURRENT))


def test_render_never_prints_a_stale_rate_as_a_current_number(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "j.jsonl")
    for run in ("a", "b", "c"):
        _record(journal, run, OLD)
    text = render(
        journal,
        BenignJournal(tmp_path / "b.jsonl"),
        model=MODEL,
        current_hash=CURRENT,
    )
    assert "3/3" not in text
    assert "pending" in text
