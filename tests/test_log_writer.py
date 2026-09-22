"""Writer invariants: taint round-trip, subset enforcement, and no hidden clock."""

from __future__ import annotations

import sqlite3
from typing import Final

import pytest

from warden.errors import LogIntegrityError
from warden.log.models import (
    CallId,
    ExecutionOutcome,
    Oracle,
    RunId,
    RunMode,
    RunVariant,
    Suite,
    new_call_id,
    new_run_id,
)
from warden.log.schema import init_db
from warden.log.serialize import dump_taint, load_taint
from warden.log.writer import (
    complete_call,
    finish_run,
    record_decision,
    record_verdict,
    start_run,
)
from warden.policy.decision import Decision, Outcome, RiskLevel, SideEffect
from warden.policy.labels import Retrieved, TaintSet, ToolOutput, UserInput

USER: Final = UserInput()
RETR: Final = Retrieved()
SEARCH: Final = ToolOutput(tool="search_docs")
NOW: Final = 1_756_000_000_000_000


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


@pytest.fixture
def run_id(db: sqlite3.Connection) -> RunId:
    rid = new_run_id()
    start_run(db, run_id=rid, mode=RunMode.BENCH, variant=RunVariant.GOVERNED,
              agent_id="demo", policy_hash="sha256:abc", policy_path="policies/x.yaml",
              git_sha="deadbeef", notes=None, now_us=NOW)
    return rid


def write(
    db: sqlite3.Connection, run_id: RunId, decision: Decision, taint: TaintSet
) -> CallId:
    cid = new_call_id()
    record_decision(db, call_id=cid, run_id=run_id, scenario_id="s1",
                    tool="send_email", args_hash="h", decision=decision,
                    input_taint=taint, taint_over_approximated=False,
                    decision_latency_us=42, approval_wait_us=None, now_us=NOW)
    return cid


# -- serialisation -------------------------------------------------------------


@pytest.mark.parametrize(
    "taint",
    [
        frozenset(),
        frozenset({USER}),
        frozenset({USER, RETR, SEARCH}),
        frozenset({ToolOutput(tool="a"), ToolOutput(tool="b")}),
    ],
)
def test_taint_round_trips(taint: TaintSet) -> None:
    assert load_taint(dump_taint(taint)) == taint


def test_taint_encoding_is_order_independent() -> None:
    """Two rows carrying the same labels must compare equal as text, or replay
    determinism becomes a property of set iteration order."""
    a = dump_taint(frozenset({USER, RETR, SEARCH}))
    b = dump_taint(frozenset({SEARCH, USER, RETR}))
    assert a == b


def test_taint_is_stored_structured_not_as_the_display_string() -> None:
    payload = dump_taint(frozenset({SEARCH}))
    assert "TOOL_OUTPUT:search_docs" not in payload
    assert '"kind":"TOOL_OUTPUT"' in payload and '"tool":"search_docs"' in payload


# -- integrity -----------------------------------------------------------------


def test_matched_taint_must_be_a_subset_of_input_taint(
    db: sqlite3.Connection, run_id: RunId
) -> None:
    decision = Decision(outcome=Outcome.DENY, rule_id="a-rule",
                        risk_level=RiskLevel.HIGH, side_effect=SideEffect.EXTERNAL_COMMS,
                        matched_taint=frozenset({RETR}))
    with pytest.raises(LogIntegrityError, match="not a subset"):
        write(db, run_id, decision, frozenset({USER}))


def test_matched_taint_subset_is_accepted(
    db: sqlite3.Connection, run_id: RunId
) -> None:
    decision = Decision(outcome=Outcome.DENY, rule_id="a-rule",
                        risk_level=RiskLevel.HIGH, side_effect=SideEffect.EXTERNAL_COMMS,
                        matched_taint=frozenset({RETR}))
    write(db, run_id, decision, frozenset({USER, RETR}))
    assert db.execute("SELECT COUNT(*) FROM call_log").fetchone()[0] == 1


def test_malformed_identifiers_are_rejected(
    db: sqlite3.Connection, run_id: RunId
) -> None:
    decision = Decision(outcome=Outcome.ALLOW, rule_id="a-rule")
    with pytest.raises(LogIntegrityError, match="call_id is not a valid ULID"):
        record_decision(db, call_id=CallId("not-a-ulid"), run_id=run_id,
                        scenario_id=None, tool="t", args_hash="h", decision=decision,
                        input_taint=frozenset(), taint_over_approximated=False,
                        decision_latency_us=1, approval_wait_us=None, now_us=NOW)


# -- decision fields land verbatim ---------------------------------------------


def test_decision_fields_are_copied_not_recomputed(
    db: sqlite3.Connection, run_id: RunId
) -> None:
    decision = Decision(outcome=Outcome.REQUIRE_APPROVAL, rule_id="critical-approves",
                        risk_level=RiskLevel.CRITICAL, side_effect=SideEffect.CODE_EXEC,
                        matched_taint=frozenset({SEARCH}))
    cid = write(db, run_id, decision, frozenset({USER, SEARCH}))
    complete_call(db, cid, execution_outcome=ExecutionOutcome.OK, latency_ms=7,
                  result_seq=1, commit_latency_us=99)
    row = db.execute(
        "SELECT policy_outcome, rule_id, risk_level, side_effect, matched_taint, "
        "input_taint, schema_version FROM call_log WHERE call_id = ?", (cid,)
    ).fetchone()
    assert row[:4] == ("REQUIRE_APPROVAL", "critical-approves", "CRITICAL", "CODE_EXEC")
    assert load_taint(row[4]) == frozenset({SEARCH})
    assert load_taint(row[5]) == frozenset({USER, SEARCH})
    assert row[6] == 1


def test_unresolved_tool_records_null_risk_and_side_effect(
    db: sqlite3.Connection, run_id: RunId
) -> None:
    decision = Decision(outcome=Outcome.DENY, rule_id="unknown-tool")
    cid = write(db, run_id, decision, frozenset())
    row = db.execute(
        "SELECT risk_level, side_effect FROM call_log WHERE call_id = ?", (cid,)
    ).fetchone()
    assert row == (None, None)


# -- transaction and clock ownership -------------------------------------------


def test_writer_does_not_commit(db: sqlite3.Connection, run_id: RunId) -> None:
    """The caller owns the transaction, so a scenario's calls land atomically."""
    write(db, run_id, Decision(outcome=Outcome.ALLOW, rule_id="a-rule"), frozenset())
    db.rollback()
    assert db.execute("SELECT COUNT(*) FROM call_log").fetchone()[0] == 0


def test_timestamps_come_from_the_caller(db: sqlite3.Connection, run_id: RunId) -> None:
    cid = write(db, run_id, Decision(outcome=Outcome.ALLOW, rule_id="a-rule"),
                frozenset())
    assert db.execute(
        "SELECT ts_us FROM call_log WHERE call_id = ?", (cid,)
    ).fetchone()[0] == NOW
    finish_run(db, run_id, now_us=NOW + 5)
    assert db.execute(
        "SELECT started_at_us, ended_at_us FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone() == (NOW, NOW + 5)


# -- verdicts ------------------------------------------------------------------


def test_judged_oracle_is_recorded_as_data(
    db: sqlite3.Connection, run_id: RunId
) -> None:
    """Goal hijacking is the one partly-judged oracle. Storing that in a column means
    a report cannot render it as deterministic by accident."""
    cid = write(db, run_id, Decision(outcome=Outcome.ALLOW, rule_id="a-rule"),
                frozenset())
    record_verdict(db, run_id=run_id, scenario_id="s1", suite=Suite.ATTACK,
                   succeeded=True, oracle=Oracle.JUDGED, target_call_id=cid)
    assert db.execute(
        "SELECT oracle, succeeded, target_call_id FROM scenario_verdict"
    ).fetchone() == ("JUDGED", 1, cid)
