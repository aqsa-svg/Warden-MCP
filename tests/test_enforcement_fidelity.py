"""Enforcement fidelity: a governed run's execution must match its decisions.

This is the check that makes n=1 governed runs sufficient. Warden's rates are derived
from shadow-evaluated ungoverned runs; what a governed run has to prove is only that a
DENY is actually not executed and an ALLOW actually is -- a verification, not a rate.
"""

from __future__ import annotations

import sqlite3

import pytest

from warden.errors import LogIntegrityError
from warden.log.integrity import assert_enforcement_fidelity, enforcement_violations
from warden.log.schema import init_db


def _run(conn: sqlite3.Connection, run_id: str, variant: str) -> None:
    conn.execute(
        "INSERT INTO runs VALUES (?,1,NULL,'BENCH',?,'a','sha256:p',NULL,NULL,NULL)",
        (run_id, variant),
    )


def _call(
    conn: sqlite3.Connection, call_id: str, run_id: str,
    policy_outcome: str, execution_outcome: str,
) -> None:
    ran = execution_outcome != "NOT_RUN"
    conn.execute(
        "INSERT INTO call_log (call_id, run_id, ts_us, tool, args_hash, "
        "policy_outcome, rule_id, matched_taint, input_taint, execution_outcome, "
        "latency_ms, result_seq) VALUES (?,?,1,'send_email','h',?,'r','[]','[]',?,?,?)",
        (call_id, run_id, policy_outcome, execution_outcome,
         1 if ran else None, 1 if ran else None),
    )


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def test_a_faithful_governed_run_passes(db: sqlite3.Connection) -> None:
    _run(db, "r", "GOVERNED")
    _call(db, "c1", "r", "ALLOW", "OK")
    _call(db, "c2", "r", "DENY", "NOT_RUN")
    assert enforcement_violations(db, "r") == []
    assert_enforcement_fidelity(db, "r")


def test_a_deny_that_executed_is_a_violation(db: sqlite3.Connection) -> None:
    """The failure that would make Warden a no-op while reporting a block."""
    _run(db, "r", "GOVERNED")
    _call(db, "c1", "r", "DENY", "OK")
    with pytest.raises(LogIntegrityError, match="enforcement diverged"):
        assert_enforcement_fidelity(db, "r")


def test_an_allow_that_never_ran_is_a_violation(db: sqlite3.Connection) -> None:
    _run(db, "r", "GOVERNED")
    _call(db, "c1", "r", "ALLOW", "NOT_RUN")
    assert len(enforcement_violations(db, "r")) == 1


def test_ungoverned_runs_are_not_checked(db: sqlite3.Connection) -> None:
    """A shadow run's whole point is that a DENY still executes. That is not a
    violation -- it is the divergence the governed/ungoverned comparison measures."""
    _run(db, "r", "UNGOVERNED")
    _call(db, "c1", "r", "DENY", "OK")
    assert enforcement_violations(db, "r") == []


def test_require_approval_is_excluded(db: sqlite3.Connection) -> None:
    """Whether an approved call ran depends on a human, which the log cannot see."""
    _run(db, "r", "GOVERNED")
    _call(db, "c1", "r", "REQUIRE_APPROVAL", "NOT_RUN")
    _call(db, "c2", "r", "REQUIRE_APPROVAL", "OK")
    assert enforcement_violations(db, "r") == []
