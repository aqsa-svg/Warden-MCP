"""The taint distinctions that are easy to invert, pinned explicitly.

The load-bearing one: taint is gated on whether a call EXECUTED, never on what the
policy said about it. Getting that backwards silently inflates taint in UNGOVERNED
shadow runs -- exactly the runs the governed/ungoverned comparison depends on.
"""

from __future__ import annotations

import sqlite3

import pytest

from warden.log.models import RunId
from warden.log.schema import init_db
from warden.policy.labels import Retrieved, ToolOutput, UserInput
from warden.taint.resolver import TaintAccumulator, reconstruct

RETRIEVAL = frozenset({"search_docs"})


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def add_run(conn: sqlite3.Connection, run_id: str, variant: str) -> None:
    conn.execute(
        "INSERT INTO runs VALUES (?,1,NULL,'BENCH',?,'a','sha256:p',NULL,NULL,NULL)",
        (run_id, variant),
    )


def add_call(
    conn: sqlite3.Connection, run_id: str, call_id: str, tool: str,
    policy_outcome: str, execution_outcome: str, result_seq: int | None,
) -> None:
    conn.execute(
        "INSERT INTO call_log (call_id, run_id, ts_us, tool, args_hash, "
        "policy_outcome, rule_id, matched_taint, input_taint, execution_outcome, "
        "latency_ms, result_seq) VALUES (?,?,1,?,'h',?,'r','[]','[]',?,?,?)",
        (call_id, run_id, tool, policy_outcome, execution_outcome,
         1 if result_seq is not None else None, result_seq),
    )


def test_ungoverned_denied_call_that_executed_still_taints(
    db: sqlite3.Connection,
) -> None:
    """The shadow-evaluation case. policy_outcome is DENY but the call ran, produced
    output, and that output is in the agent's context. It taints."""
    add_run(db, "r", "UNGOVERNED")
    add_call(db, "r", "c1", "search_docs", "DENY", "OK", 1)
    db.commit()
    taint = reconstruct(db, RunId("r"), RETRIEVAL)
    assert ToolOutput(tool="search_docs") in taint
    assert Retrieved() in taint


def test_governed_denied_call_that_never_ran_does_not_taint(
    db: sqlite3.Connection,
) -> None:
    add_run(db, "r", "GOVERNED")
    add_call(db, "r", "c1", "search_docs", "DENY", "NOT_RUN", None)
    db.commit()
    taint = reconstruct(db, RunId("r"), RETRIEVAL)
    assert taint == frozenset({UserInput()})


def test_the_two_cases_differ_only_by_execution(db: sqlite3.Connection) -> None:
    """Same policy_outcome, opposite taint. Proves the gate is execution."""
    add_run(db, "enforced", "GOVERNED")
    add_run(db, "observed", "UNGOVERNED")
    add_call(db, "enforced", "c1", "search_docs", "DENY", "NOT_RUN", None)
    add_call(db, "observed", "c2", "search_docs", "DENY", "OK", 1)
    db.commit()
    assert reconstruct(db, RunId("enforced"), RETRIEVAL) == frozenset({UserInput()})
    assert Retrieved() in reconstruct(db, RunId("observed"), RETRIEVAL)


def test_before_result_seq_gives_the_state_just_before_that_result(
    db: sqlite3.Connection,
) -> None:
    add_run(db, "r", "GOVERNED")
    add_call(db, "r", "c1", "get_customer", "ALLOW", "OK", 1)
    add_call(db, "r", "c2", "search_docs", "ALLOW", "OK", 2)
    add_call(db, "r", "c3", "create_ticket", "ALLOW", "OK", 3)
    db.commit()

    assert reconstruct(db, RunId("r"), RETRIEVAL, before_result_seq=1) == frozenset(
        {UserInput()}
    )
    assert reconstruct(db, RunId("r"), RETRIEVAL, before_result_seq=2) == frozenset(
        {UserInput(), ToolOutput(tool="get_customer")}
    )
    assert reconstruct(db, RunId("r"), RETRIEVAL, before_result_seq=3) == frozenset(
        {UserInput(), ToolOutput(tool="get_customer"),
         ToolOutput(tool="search_docs"), Retrieved()}
    )


def test_empty_run_is_user_input_only(db: sqlite3.Connection) -> None:
    add_run(db, "r", "GOVERNED")
    db.commit()
    assert reconstruct(db, RunId("r"), RETRIEVAL) == frozenset({UserInput()})


def test_restart_recovery_rebuilds_the_live_accumulator(
    db: sqlite3.Connection,
) -> None:
    """A proxy that restarts mid-run recovers its accumulator from the log."""
    add_run(db, "r", "GOVERNED")
    for seq, tool in enumerate(["get_customer", "search_docs"], start=1):
        add_call(db, "r", f"c{seq}", tool, "ALLOW", "OK", seq)
    db.commit()

    recovered = reconstruct(db, RunId("r"), RETRIEVAL)
    live = TaintAccumulator(RETRIEVAL)
    live.observe_result("get_customer")
    live.observe_result("search_docs")
    assert recovered == live.current()


def test_a_non_retrieval_tool_does_not_emit_retrieved(
    db: sqlite3.Connection,
) -> None:
    add_run(db, "r", "GOVERNED")
    add_call(db, "r", "c1", "get_customer", "ALLOW", "OK", 1)
    db.commit()
    assert Retrieved() not in reconstruct(db, RunId("r"), RETRIEVAL)
