"""Durable, resumable store for benign-suite results.

Parallel to the attack calibration journal, and separate because the two measure
different things: an attack attempt is SUCCESS/FAILURE, a benign run is
CLEAN/ESCALATE/HARD_BLOCK (what Warden did to legitimate work). Keeping them apart
stops one suite's rows from being counted in the other's rate.

Append-only and fsynced, keyed by scenario and model, and stamped with the source hash
so a run against changed code is detectable. Resumable so the suite -- which needs
several free-tier quota days -- can be continued without re-spending requests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final

from warden.redteam.benign import Expected

BENIGN_JOURNAL_VERSION: Final = 1


class BenignRecord:
    """One graded benign run. A plain class, not a NamedTuple, so json (de)serialisation
    stays explicit and legacy-tolerant like the attack journal."""

    def __init__(
        self,
        *,
        scenario_id: str,
        run_id: str,
        observed: Expected,
        expected: Expected,
        timestamp_us: int,
        model: str,
        source_hash: str = "",
    ) -> None:
        self.scenario_id = scenario_id
        self.run_id = run_id
        self.observed = observed
        self.expected = expected
        self.timestamp_us = timestamp_us
        self.model = model
        self.source_hash = source_hash

    @property
    def is_deviation(self) -> bool:
        """A defect is an observed outcome worse than declared. A tainted case that was
        declared HARD_BLOCK and came back HARD_BLOCK is not a deviation; an ordinary
        case declared CLEAN that came back HARD_BLOCK is."""
        return self.observed is not self.expected

    def to_json(self) -> str:
        return json.dumps(
            {
                "v": BENIGN_JOURNAL_VERSION,
                "scenario_id": self.scenario_id,
                "run_id": self.run_id,
                "observed": self.observed.value,
                "expected": self.expected.value,
                "timestamp_us": self.timestamp_us,
                "model": self.model,
                "source_hash": self.source_hash,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, line: str) -> "BenignRecord":
        row = json.loads(line)
        return cls(
            scenario_id=str(row["scenario_id"]),
            run_id=str(row["run_id"]),
            observed=Expected(row["observed"]),
            expected=Expected(row["expected"]),
            timestamp_us=int(row["timestamp_us"]),
            model=str(row["model"]),
            source_hash=str(row.get("source_hash", "")),
        )


class BenignJournal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, record: BenignRecord) -> None:
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(record.to_json() + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def records(self) -> list[BenignRecord]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as handle:
            return [BenignRecord.from_json(line) for line in handle if line.strip()]

    def done_scenarios(self, model: str, source_hash: str | None = None) -> set[str]:
        """Scenario ids already run for this model. Drives resume: a scenario with a
        record is skipped rather than re-run and re-charged.

        When `source_hash` is given, only records under that hash count as done, so a
        policy or runtime change (which moves the hash) correctly re-opens every stale
        scenario for re-running rather than leaving a result produced by different code
        standing. A legacy blank hash never matches a real current hash, so legacy
        records are re-run under the current code, which is the safe direction."""
        return {
            r.scenario_id
            for r in self.records()
            if r.model == model and (source_hash is None or r.source_hash == source_hash)
        }

    def outstanding(
        self, scenario_ids: list[str], model: str, source_hash: str | None = None
    ) -> list[str]:
        done = self.done_scenarios(model, source_hash)
        return [s for s in scenario_ids if s not in done]
