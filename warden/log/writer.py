"""Call log writer.

No function here reads a clock or generates an identifier. `now_us` and the ULIDs are
supplied by the caller, for the same reason Decision carries no timestamp: a writer
that reads the clock itself needs that clock stubbed before it can be tested, and the
replay harness needs to pin both.

No function commits. The caller owns the transaction, so a scenario's calls land
atomically or not at all.
"""

from __future__ import annotations

import sqlite3

from ulid import ULID

from warden.errors import LogIntegrityError
from warden.log.models import (
    CallId,
    ExecutionOutcome,
    Oracle,
    RunId,
    RunMode,
    RunVariant,
    Suite,
)
from warden.log.schema import SCHEMA_VERSION
from warden.log.serialize import dump_taint
from warden.policy.decision import Decision
from warden.policy.labels import TaintSet


def _check_ulid(value: str, field: str) -> None:
    try:
        ULID.from_str(value)
    except (ValueError, TypeError) as exc:
        raise LogIntegrityError(f"{field} is not a valid ULID: {value!r}") from exc


def start_run(
    conn: sqlite3.Connection,
    *,
    run_id: RunId,
    mode: RunMode,
    variant: RunVariant,
    agent_id: str,
    policy_hash: str,
    policy_path: str | None,
    git_sha: str | None,
    notes: str | None,
    now_us: int,
) -> None:
    """Open a run. policy_hash is required for both variants: "would have blocked"
    is meaningless without recording which policy said so."""
    _check_ulid(run_id, "run_id")
    conn.execute(
        "INSERT INTO runs (run_id, started_at_us, ended_at_us, mode, variant, "
        "agent_id, policy_hash, policy_path, git_sha, notes) "
        "VALUES (?,?,NULL,?,?,?,?,?,?,?)",
        (
            run_id,
            now_us,
            mode.value,
            variant.value,
            agent_id,
            policy_hash,
            policy_path,
            git_sha,
            notes,
        ),
    )


def finish_run(conn: sqlite3.Connection, run_id: RunId, *, now_us: int) -> None:
    conn.execute("UPDATE runs SET ended_at_us = ? WHERE run_id = ?", (now_us, run_id))


def record_decision(
    conn: sqlite3.Connection,
    *,
    call_id: CallId,
    run_id: RunId,
    scenario_id: str | None,
    tool: str,
    args_hash: str,
    decision: Decision,
    input_taint: TaintSet,
    taint_over_approximated: bool,
    decision_latency_us: int | None,
    approval_wait_us: int | None,
    now_us: int,
) -> None:
    """Phase one: everything known before the call is forwarded.

    The caller commits this BEFORE forwarding. That overrides the scenario-scoped
    transaction the log layer was originally designed around, deliberately: if the
    process dies mid-forward, a scenario-wide transaction leaves a call that executed
    with no audit record at all, which is the worst outcome this system can produce.
    Audit integrity beats transactional tidiness.

    execution_outcome is left NULL -- "issued, fate unknown" -- and phase two resolves
    it. A row still NULL after the fact means the process died, and its run is
    excluded from the metrics rather than contributing partial data.
    """
    _check_ulid(call_id, "call_id")
    if not decision.matched_taint <= input_taint:
        raise LogIntegrityError(
            f"matched_taint is not a subset of input_taint for call {call_id}: "
            f"{dump_taint(decision.matched_taint - input_taint)} not present in input"
        )
    conn.execute(
        "INSERT INTO call_log (call_id, schema_version, run_id, scenario_id, ts_us, "
        "tool, args_hash, policy_outcome, rule_id, risk_level, side_effect, "
        "matched_taint, input_taint, execution_outcome, latency_ms, "
        "decision_latency_us, approval_wait_us, commit_latency_us, "
        "taint_over_approximated, result_seq) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,?,NULL,?,NULL)",
        (
            call_id,
            SCHEMA_VERSION,
            run_id,
            scenario_id,
            now_us,
            tool,
            args_hash,
            decision.outcome.value,
            decision.rule_id,
            None if decision.risk_level is None else decision.risk_level.value,
            None if decision.side_effect is None else decision.side_effect.value,
            dump_taint(decision.matched_taint),
            dump_taint(input_taint),
            decision_latency_us,
            approval_wait_us,
            int(taint_over_approximated),
        ),
    )


def complete_call(
    conn: sqlite3.Connection,
    call_id: CallId,
    *,
    execution_outcome: ExecutionOutcome,
    latency_ms: int | None,
    result_seq: int | None,
    commit_latency_us: int | None,
) -> None:
    """Phase two: the call's fate.

    NOT_RUN for a call policy refused; OK/ERROR/TIMEOUT for one that ran. latency_ms
    and result_seq are non-NULL exactly when it ran -- the schema enforces that, and
    it is keyed on execution rather than policy, because an UNGOVERNED shadow run
    executes calls whose policy_outcome was DENY.
    """
    conn.execute(
        "UPDATE call_log SET execution_outcome = ?, latency_ms = ?, result_seq = ?, "
        "commit_latency_us = ? WHERE call_id = ?",
        (execution_outcome.value, latency_ms, result_seq, commit_latency_us, call_id),
    )


def record_verdict(
    conn: sqlite3.Connection,
    *,
    run_id: RunId,
    scenario_id: str,
    suite: Suite,
    succeeded: bool,
    oracle: Oracle,
    target_call_id: CallId | None,
) -> None:
    """Record one scenario's oracle verdict. Written after the run, by the oracle."""
    if target_call_id is not None:
        _check_ulid(target_call_id, "target_call_id")
    conn.execute(
        "INSERT INTO scenario_verdict (run_id, scenario_id, suite, succeeded, "
        "oracle, target_call_id) VALUES (?,?,?,?,?,?)",
        (
            run_id,
            scenario_id,
            suite.value,
            int(succeeded),
            oracle.value,
            target_call_id,
        ),
    )
