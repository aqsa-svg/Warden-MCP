"""Integrity checks must actually fire. A check that cannot fail is decoration."""

from __future__ import annotations

import sqlite3

import pytest

from warden.errors import LogIntegrityError
from warden.log.integrity import (
    assert_report_integrity,
    scenarios_missing_a_verdict,
    unevaluated_rows_under_a_policy,
)
from warden.log.models import NO_POLICY
from warden.log.schema import init_db
from warden.policy.rule_ids import RULE_ID_NOT_EVALUATED


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def add_run(conn: sqlite3.Connection, run_id: str, policy_hash: str) -> None:
    conn.execute(
        "INSERT INTO runs VALUES (?,1,NULL,'BENCH','GOVERNED','demo',?,'p.yaml','g',NULL)",
        (run_id, policy_hash),
    )


def add_call(
    conn: sqlite3.Connection, call_id: str, run_id: str, rule_id: str,
    scenario_id: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO call_log (call_id, run_id, scenario_id, ts_us, tool, args_hash, "
        "policy_outcome, rule_id, matched_taint, input_taint, execution_outcome, "
        "latency_ms, result_seq) VALUES (?,?,?,1,'send_email','h','ALLOW',?,'[]','[]',"
        "'OK',5,1)",
        (call_id, run_id, scenario_id, rule_id),
    )


def test_week_one_rows_are_not_flagged(db: sqlite3.Connection) -> None:
    """not-evaluated is legitimate when the run recorded no policy at all."""
    add_run(db, "r1", NO_POLICY)
    add_call(db, "c1", "r1", RULE_ID_NOT_EVALUATED)
    assert unevaluated_rows_under_a_policy(db) == []


def test_unevaluated_under_a_real_policy_is_flagged(db: sqlite3.Connection) -> None:
    """Once shadow evaluation exists this is impossible; if it happens, the
    evaluation path is broken and must not read as a silent zero."""
    add_run(db, "r2", "sha256:realpolicy")
    add_call(db, "c2", "r2", RULE_ID_NOT_EVALUATED)
    assert unevaluated_rows_under_a_policy(db) == ["c2"]
    with pytest.raises(LogIntegrityError, match="shadow evaluation is broken"):
        assert_report_integrity(db)


def test_normal_rows_under_a_real_policy_pass(db: sqlite3.Connection) -> None:
    add_run(db, "r3", "sha256:realpolicy")
    add_call(db, "c3", "r3", "exfil-via-external-comms")
    assert unevaluated_rows_under_a_policy(db) == []


def test_scenario_without_a_verdict_is_flagged(db: sqlite3.Connection) -> None:
    add_run(db, "r4", "sha256:realpolicy")
    add_call(db, "c4", "r4", "read-only-allow", scenario_id="benign-07")
    assert scenarios_missing_a_verdict(db) == [("r4", "benign-07")]
    with pytest.raises(LogIntegrityError, match="no oracle verdict"):
        assert_report_integrity(db)


def test_scenario_with_a_verdict_passes(db: sqlite3.Connection) -> None:
    add_run(db, "r5", "sha256:realpolicy")
    add_call(db, "c5", "r5", "read-only-allow", scenario_id="benign-08")
    db.execute(
        "INSERT INTO scenario_verdict VALUES ('r5','benign-08','BENIGN',0,'CALL_LOG',NULL)"
    )
    assert scenarios_missing_a_verdict(db) == []
    assert_report_integrity(db)


def test_live_rows_without_a_scenario_are_not_flagged(db: sqlite3.Connection) -> None:
    """LIVE runs have no scenario_id and must not be demanded a verdict."""
    add_run(db, "r6", "sha256:realpolicy")
    add_call(db, "c6", "r6", "read-only-allow", scenario_id=None)
    assert scenarios_missing_a_verdict(db) == []
