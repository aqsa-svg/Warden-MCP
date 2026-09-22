"""Append-only calibration journal.

Calibration spans days because the free tier allows 20 model requests per day, so the
runner must survive being stopped by quota and continued tomorrow without re-spending
requests it already made. The journal is what makes that possible: one durable record
per attempt, read at startup to compute what is still missing.

Every count is keyed by MODEL. An ungoverned success rate is a property of a specific
model at a specific time, not of the attack, so attempts made against a different
model are not evidence about this one and must not be counted toward its denominator.

Records are flushed and fsynced on write. A crash mid-day must not lose the record of
requests that were actually spent -- that would cause the next run to repeat them,
which is the precise failure the journal exists to prevent.
"""

from __future__ import annotations

import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Final, Iterable, NamedTuple

JOURNAL_VERSION: Final = 1


class AttemptOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    """The oracle confirmed the attack succeeded against the ungoverned agent."""

    FAILURE = "FAILURE"
    """The run completed and the attack did not succeed. Real evidence."""

    ERROR = "ERROR"
    """The run did not complete -- quota, crash, upstream failure. NOT evidence, and
    excluded from both numerator and denominator: counting an unfinished run as a
    failure biases the rate in the flattering direction."""


class Attempt(NamedTuple):
    template: str
    mutation_seed: str | None
    run_id: str
    outcome: AttemptOutcome
    timestamp_us: int
    model: str
    source_hash: str = ""
    """The content hash of the source that produced this run (see source_hash.py).
    Empty for records written before hashing was added. Every attempt for a template
    should share a hash; a mismatch means a run executed against different code and its
    result is not comparable with the others."""

    def to_json(self) -> str:
        return json.dumps(
            {
                "v": JOURNAL_VERSION,
                "template": self.template,
                "mutation_seed": self.mutation_seed,
                "run_id": self.run_id,
                "outcome": self.outcome.value,
                "timestamp_us": self.timestamp_us,
                "model": self.model,
                "source_hash": self.source_hash,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, line: str) -> Attempt:
        row = json.loads(line)
        return cls(
            template=str(row["template"]),
            mutation_seed=row["mutation_seed"],
            run_id=str(row["run_id"]),
            outcome=AttemptOutcome(row["outcome"]),
            timestamp_us=int(row["timestamp_us"]),
            model=str(row["model"]),
            source_hash=str(row.get("source_hash", "")),
        )


class Tally(NamedTuple):
    successes: int
    completed: int
    errors: int

    @property
    def fraction(self) -> str:
        """Always the fraction, never a bare percentage.

        n=3 cannot honestly be reported as 67%; the denominator has to travel with
        the number or the reader infers a precision that was never measured.
        """
        return f"{self.successes}/{self.completed}"


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, attempt: Attempt) -> None:
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(attempt.to_json() + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def attempts(self) -> list[Attempt]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as handle:
            return [
                Attempt.from_json(line) for line in handle if line.strip()
            ]

    def tally(self, template: str, model: str) -> Tally:
        rows = [
            a
            for a in self.attempts()
            if a.template == template and a.model == model
        ]
        errors = sum(1 for a in rows if a.outcome is AttemptOutcome.ERROR)
        completed = [a for a in rows if a.outcome is not AttemptOutcome.ERROR]
        successes = sum(
            1 for a in completed if a.outcome is AttemptOutcome.SUCCESS
        )
        return Tally(successes, len(completed), errors)

    def source_hashes(self, template: str) -> set[str]:
        """The distinct source hashes recorded for a template, ignoring legacy blanks.

        More than one means the template's attempts were run against different code and
        their rates are not comparable -- the exact stale-run failure the hash exists
        to catch."""
        return {
            a.source_hash
            for a in self.attempts()
            if a.template == template and a.source_hash
        }

    def hash_conflicts(self, current: str) -> dict[str, set[str]]:
        """Templates whose recorded hashes are not all equal to `current`.

        Legacy blank-hash records are ignored. Returns {template: hashes seen} for any
        template that has a recorded hash differing from the current source, so the
        dry-run can refuse to treat mixed-hash calibration as a single rate."""
        conflicts: dict[str, set[str]] = {}
        templates = {a.template for a in self.attempts()}
        for template in templates:
            hashes = self.source_hashes(template)
            if hashes and hashes != {current}:
                conflicts[template] = hashes
        return conflicts


def record_attempt(
    journal: Journal,
    *,
    template: str,
    run_id: str,
    outcome: AttemptOutcome,
    timestamp_us: int,
    model: str,
    mutation_seed: str | None = None,
) -> Attempt:
    """Record an attempt, stamping the current source hash automatically.

    Every recording of a calibration result must go through here rather than
    constructing an Attempt by hand, so the source hash can never be omitted and a
    stale run can always be detected after the fact."""
    from warden.source_hash import source_hash

    attempt = Attempt(
        template=template,
        mutation_seed=mutation_seed,
        run_id=run_id,
        outcome=outcome,
        timestamp_us=timestamp_us,
        model=model,
        source_hash=source_hash(),
    )
    journal.record(attempt)
    return attempt


class Plan(NamedTuple):
    templates: tuple[str, ...]
    runs_per_template: int
    model: str


class Outstanding(NamedTuple):
    template: str
    done: int
    needed: int

    @property
    def remaining(self) -> int:
        return max(0, self.needed - self.done)


def outstanding(plan: Plan, journal: Journal) -> list[Outstanding]:
    """What still needs running. ERROR attempts do not count as done, so a run the
    quota interrupted is retried rather than silently recorded as evidence."""
    return [
        Outstanding(
            template,
            journal.tally(template, plan.model).completed,
            plan.runs_per_template,
        )
        for template in plan.templates
    ]


def requests_needed(items: Iterable[Outstanding], per_run: int) -> int:
    return sum(item.remaining for item in items) * per_run
