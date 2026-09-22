"""Integrity checks the report generator must run before computing any metric.

Each of these guards a way the reported numbers could be silently wrong rather than
loudly broken. A broken shadow-evaluation path, or a scenario the oracle never scored,
both show up as a smaller number in the flattering direction if nobody looks.
"""

from __future__ import annotations

import sqlite3
from typing import Final, NamedTuple

from warden.errors import LogIntegrityError
from warden.log.models import NO_POLICY
from warden.policy.rule_ids import RULE_ID_NOT_EVALUATED


def unevaluated_rows_under_a_policy(conn: sqlite3.Connection) -> list[str]:
    """call_ids carrying not-evaluated despite their run naming a real policy.

    Week-1 transparent-proxy rows legitimately carry it, and those runs record
    policy_hash = NO_POLICY. Once component 4 wires shadow evaluation, an UNGOVERNED
    run still evaluates, so not-evaluated becomes impossible for any run with a real
    policy. If it appears there, the evaluation path is broken.

    Note: policy_hash is NOT NULL, so the discriminator is the NO_POLICY sentinel
    rather than a null check.
    """
    rows = conn.execute(
        "SELECT c.call_id FROM call_log c JOIN runs r USING (run_id) "
        "WHERE r.policy_hash != ? AND c.rule_id = ? ORDER BY c.ts_us",
        (NO_POLICY, RULE_ID_NOT_EVALUATED),
    ).fetchall()
    return [str(row[0]) for row in rows]


def scenarios_missing_a_verdict(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Scenarios that produced calls but were never scored by an oracle.

    The FPR denominator comes from scenario_verdict, so a benign scenario with no
    verdict row silently drops out and lowers FPR -- the flattering direction.
    """
    rows = conn.execute(
        "SELECT DISTINCT c.run_id, c.scenario_id FROM call_log c "
        "WHERE c.scenario_id IS NOT NULL AND NOT EXISTS ("
        "  SELECT 1 FROM scenario_verdict v "
        "  WHERE v.run_id = c.run_id AND v.scenario_id = c.scenario_id"
        ") ORDER BY c.run_id, c.scenario_id"
    ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


class EnforcementViolation(NamedTuple):
    call_id: str
    policy_outcome: str
    execution_outcome: str | None
    expected: str


def enforcement_violations(
    conn: sqlite3.Connection, run_id: str
) -> list[EnforcementViolation]:
    """Where a GOVERNED run's execution diverged from its decision.

    This is the check that verifies enforcement, and it compares the DECISION to what
    actually happened -- not would_block to was_blocked, which are definitionally equal
    on a governed run and so prove nothing.

    Two always-valid invariants:
      * a DENY must not have executed (execution_outcome NOT_RUN)
      * an ALLOW must have executed (anything but NOT_RUN)

    REQUIRE_APPROVAL is excluded: whether it ran depends on a human's answer, which the
    log alone cannot distinguish from a bug. NULL execution (fate unknown) is excluded
    too -- that is the INCOMPLETE-run concern, handled separately.
    """
    rows = conn.execute(
        "SELECT call_id, policy_outcome, execution_outcome FROM call_facts "
        "WHERE run_id = ? AND variant = 'GOVERNED' AND execution_outcome IS NOT NULL",
        (run_id,),
    ).fetchall()
    violations: list[EnforcementViolation] = []
    for call_id, outcome, execution in rows:
        if outcome == "DENY" and execution != "NOT_RUN":
            violations.append(
                EnforcementViolation(call_id, outcome, execution, "NOT_RUN")
            )
        elif outcome == "ALLOW" and execution == "NOT_RUN":
            violations.append(
                EnforcementViolation(call_id, outcome, execution, "executed")
            )
    return violations


def assert_enforcement_fidelity(conn: sqlite3.Connection, run_id: str) -> None:
    """Raise if any call in a governed run executed against its decision."""
    violations = enforcement_violations(conn, run_id)
    if violations:
        raise LogIntegrityError(
            f"enforcement diverged from decision on {len(violations)} call(s) in run "
            f"{run_id}: " + "; ".join(
                f"{v.call_id} {v.policy_outcome} but execution={v.execution_outcome} "
                f"(expected {v.expected})"
                for v in violations[:5]
            )
        )


MAX_EXCLUDED_FRACTION: Final = 0.05
"""Above this, exclusions stop being incidental and the benchmark is systematically
crashing. Exclusion is the mechanism; the raise is the backstop."""


def incomplete_runs(conn: sqlite3.Connection) -> list[str]:
    """Runs containing a call whose fate is unknown -- execution_outcome NULL.

    Such a call was issued and the process died before its result was recorded, so it
    may or may not have executed. Silently including the run biases ASR in an unknown
    direction, which is worse than a smaller denominator, so the run is excluded from
    every metric rather than contributing partial data.
    """
    rows = conn.execute(
        "SELECT DISTINCT run_id FROM call_log WHERE execution_outcome IS NULL "
        "ORDER BY run_id"
    ).fetchall()
    return [str(row[0]) for row in rows]


def excluded_scenarios(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """(run_id, scenario_id) pairs dropped because their run is INCOMPLETE.

    The report prints these prominently: a reader must be able to see what was left
    out, not just a denominator that quietly shrank.
    """
    rows = conn.execute(
        "SELECT DISTINCT run_id, scenario_id FROM call_log "
        "WHERE scenario_id IS NOT NULL AND run_id IN ("
        "  SELECT run_id FROM call_log WHERE execution_outcome IS NULL"
        ") ORDER BY run_id, scenario_id"
    ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


def assert_report_integrity(
    conn: sqlite3.Connection,
    *,
    minimum_scenarios: int = 0,
    max_excluded_fraction: float = MAX_EXCLUDED_FRACTION,
) -> None:
    """Raise before any metric is computed. Never warn -- a warning gets scrolled past.

    INCOMPLETE runs are excluded rather than fatal, so one crashed run does not block
    the whole report. The raise is the backstop for two cases the exclusion cannot
    absorb: exclusions leaving a suite below its minimum-N floor, and a systematically
    crashing benchmark where the excluded fraction is large.
    """
    broken = unevaluated_rows_under_a_policy(conn)
    if broken:
        raise LogIntegrityError(
            f"{len(broken)} call(s) carry rule_id={RULE_ID_NOT_EVALUATED!r} under a "
            f"run with a real policy; shadow evaluation is broken: {broken[:5]}"
        )
    unscored = scenarios_missing_a_verdict(conn)
    if unscored:
        raise LogIntegrityError(
            f"{len(unscored)} scenario(s) produced calls but have no oracle verdict; "
            f"they would silently drop out of the denominator: {unscored[:5]}"
        )

    total = conn.execute(
        "SELECT COUNT(*) FROM (SELECT DISTINCT run_id, scenario_id FROM call_log "
        "WHERE scenario_id IS NOT NULL)"
    ).fetchone()[0]
    excluded = excluded_scenarios(conn)
    remaining = total - len(excluded)

    if minimum_scenarios and remaining < minimum_scenarios:
        raise LogIntegrityError(
            f"excluding {len(excluded)} scenario(s) from INCOMPLETE run(s) leaves "
            f"{remaining}, below the minimum of {minimum_scenarios}"
        )
    if total and (len(excluded) / total) > max_excluded_fraction:
        raise LogIntegrityError(
            f"{len(excluded)}/{total} scenario(s) excluded as INCOMPLETE "
            f"({len(excluded) / total:.1%}), above the "
            f"{max_excluded_fraction:.0%} threshold; the benchmark is crashing "
            f"systematically rather than incidentally"
        )
