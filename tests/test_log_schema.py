"""Call log schema: idempotence, constraints, the block predicate, and drift guards."""

from __future__ import annotations

import pathlib
import re
import sqlite3
from typing import Final

import pytest

from warden.log.models import ExecutionOutcome, Oracle, RunMode, RunVariant, Suite
from warden.log.schema import DDL, init_db
from warden.policy.decision import Outcome, RiskLevel, SideEffect

EMPTY_JSON: Final = "[]"


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _run(conn: sqlite3.Connection, run_id: str, variant: str, mode: str) -> None:
    conn.execute(
        "INSERT INTO runs VALUES (?,1,NULL,?,?,'demo','sha256:abc','p.yaml','git',NULL)",
        (run_id, mode, variant),
    )


INSERT_CALL = (
    "INSERT INTO call_log (call_id, schema_version, run_id, scenario_id, ts_us, tool, "
    "args_hash, policy_outcome, rule_id, risk_level, side_effect, matched_taint, "
    "input_taint, execution_outcome, latency_ms, decision_latency_us, result_seq) "
    "VALUES (:call_id,1,:run_id,'s1',1,'run_shell','h',:policy_outcome,'a-rule',"
    "'CRITICAL','CODE_EXEC','[]','[]',:execution_outcome,:latency_ms,5,:result_seq)"
)


def _call(
    conn: sqlite3.Connection,
    call_id: str,
    run_id: str,
    policy_outcome: str,
    execution_outcome: str,
    latency: int | None,
    result_seq: int | None = 1,
) -> None:
    conn.execute(
        INSERT_CALL,
        {
            "call_id": call_id, "run_id": run_id, "policy_outcome": policy_outcome,
            "execution_outcome": execution_outcome, "latency_ms": latency,
            "result_seq": None if execution_outcome == "NOT_RUN" else result_seq,
        },
    )


def test_init_db_is_idempotent(db: sqlite3.Connection) -> None:
    init_db(db)
    init_db(db)
    tables = {
        r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"runs", "call_log", "scenario_verdict"} <= tables


def test_foreign_keys_are_enforced(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _call(db, "c1", "no-such-run", "ALLOW", "OK", 1)


BARE_INSERT = (
    "INSERT INTO call_log (call_id, run_id, ts_us, tool, args_hash, policy_outcome, "
    "rule_id, risk_level, side_effect, matched_taint, input_taint, "
    "execution_outcome, latency_ms, result_seq) VALUES "
    "('c','r',1,'t','h',:policy_outcome,'x',:risk_level,:side_effect,'[]',"
    ":input_taint,:execution_outcome,:latency_ms,:result_seq)"
)
OK_ROW: dict[str, object] = {
    "policy_outcome": "ALLOW", "risk_level": None, "side_effect": None,
    "input_taint": "[]", "execution_outcome": "OK", "latency_ms": 1, "result_seq": 1,
}


@pytest.mark.parametrize(
    "label,override",
    [
        ("not_run carrying a latency",
         {"execution_outcome": "NOT_RUN", "latency_ms": 7, "result_seq": None}),
        ("executed call with no latency", {"latency_ms": None}),
        ("malformed json in input_taint", {"input_taint": "nope"}),
        ("risk_level without side_effect", {"risk_level": "HIGH"}),
        ("unknown policy_outcome", {"policy_outcome": "MAYBE"}),
        # result_seq is keyed on execution, not policy
        ("not_run carrying a result_seq",
         {"execution_outcome": "NOT_RUN", "latency_ms": None, "result_seq": 3}),
        ("executed call with no result_seq", {"result_seq": None}),
    ],
)
def test_check_constraints_reject(
    db: sqlite3.Connection, label: str, override: dict[str, object]
) -> None:
    _run(db, "r", "GOVERNED", "BENCH")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(BARE_INSERT, {**OK_ROW, **override})


def test_result_seq_is_unique_per_run(db: sqlite3.Connection) -> None:
    _run(db, "r", "GOVERNED", "BENCH")
    _call(db, "c1", "r", "ALLOW", "OK", 5, result_seq=1)
    with pytest.raises(sqlite3.IntegrityError):
        _call(db, "c2", "r", "ALLOW", "OK", 5, result_seq=1)


def test_many_not_run_calls_may_share_a_null_result_seq(db: sqlite3.Connection) -> None:
    """SQLite permits repeated NULLs in a unique index, which denied calls need."""
    _run(db, "r", "GOVERNED", "BENCH")
    _call(db, "c1", "r", "DENY", "NOT_RUN", None)
    _call(db, "c2", "r", "DENY", "NOT_RUN", None)
    assert db.execute("SELECT COUNT(*) FROM call_log").fetchone()[0] == 2


def test_call_facts_separates_would_block_from_was_blocked(
    db: sqlite3.Connection,
) -> None:
    """The whole point of shadow-evaluating: an ungoverned run records what the policy
    would have said while the call runs anyway."""
    _run(db, "r_gov", "GOVERNED", "BENCH")
    _run(db, "r_ung", "UNGOVERNED", "BENCH")
    _call(db, "c_gov", "r_gov", "DENY", "NOT_RUN", None)
    _call(db, "c_ung", "r_ung", "DENY", "OK", 12)

    facts = {
        r[0]: (r[1], r[2])
        for r in db.execute("SELECT call_id, would_block, was_blocked FROM call_facts")
    }
    assert facts["c_gov"] == (1, 1), "governed deny is both predicted and enforced"
    assert facts["c_ung"] == (1, 0), "ungoverned deny is predicted but not enforced"


def test_ungoverned_deny_that_executed_is_legal(db: sqlite3.Connection) -> None:
    _run(db, "r_ung", "UNGOVERNED", "BENCH")
    _call(db, "c", "r_ung", "DENY", "OK", 5)
    assert db.execute("SELECT COUNT(*) FROM call_log").fetchone()[0] == 1


def test_was_blocked_overcounts_a_granted_live_approval(db: sqlite3.Connection) -> None:
    """Known limitation, pinned so it is visible rather than discovered.

    In a LIVE run a human can grant a REQUIRE_APPROVAL and the call executes, but
    was_blocked still reads 1. Harmless for the report tables, which come from BENCH
    runs where approval always auto-denies. Adding `AND execution_outcome='NOT_RUN'`
    to was_blocked would fix it if LIVE runs ever feed a metric.
    """
    _run(db, "r_live", "GOVERNED", "LIVE")
    _call(db, "c", "r_live", "REQUIRE_APPROVAL", "OK", 12)
    row = db.execute("SELECT would_block, was_blocked FROM call_facts").fetchone()
    assert row == (1, 1)


def _in_list(column: str) -> set[str]:
    start = DDL.index("IN (", DDL.index(f"{column} "))
    return set(re.findall(r"'([^']+)'", DDL[start : DDL.index(")", start)]))


@pytest.mark.parametrize(
    "column,enum",
    [
        ("mode", RunMode),
        ("variant", RunVariant),
        ("policy_outcome", Outcome),
        ("risk_level", RiskLevel),
        ("side_effect", SideEffect),
        ("execution_outcome", ExecutionOutcome),
        ("suite", Suite),
        ("oracle", Oracle),
    ],
)
def test_check_lists_match_their_enums(column: str, enum: type[object]) -> None:
    """A value added to a Python enum but not to the CHECK fails at insert time,
    in a benchmark run, hours in. This catches it at test time instead."""
    assert _in_list(column) == {member.value for member in enum}  # type: ignore[attr-defined]


WARDEN_ROOT: Final = pathlib.Path(__file__).parent.parent / "warden"
SQL_MARKERS: Final = ("SELECT", "WHERE", "CASE WHEN", "INSERT INTO", "UPDATE ")


def test_block_predicate_appears_only_in_the_view() -> None:
    """Finding 3 stays fixed rather than being fixed once.

    Currently vacuous -- the report generator does not exist yet. It bites the moment
    someone writes `WHERE policy_outcome = 'DENY'` in report SQL instead of using
    would_block / was_blocked.
    """
    offenders: list[str] = []
    for path in WARDEN_ROOT.rglob("*.py"):
        if path.name == "schema.py" and path.parent.name == "log":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "DENY" in line and any(marker in line for marker in SQL_MARKERS):
                offenders.append(f"{path.relative_to(WARDEN_ROOT.parent)}:{number}")
    assert not offenders, (
        "SQL referencing DENY outside the call_facts view; use would_block/"
        f"was_blocked instead: {offenders}"
    )
