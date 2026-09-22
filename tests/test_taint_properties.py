"""Property-based tests for turn-level taint resolution.

The subject is arbitrary *call sequences*, not arbitrary content graphs: the resolver
inspects no content, so there is no graph to generate. What can go wrong is inclusion
and ordering -- a label appearing too early, a label surviving across runs, a denied
call contributing output it never produced.
"""

from __future__ import annotations

import sqlite3
import string
from typing import Final

from hypothesis import given, settings
from hypothesis import strategies as st

from warden.log.models import RunId
from warden.log.schema import init_db
from warden.policy.labels import Retrieved, ToolOutput, UserInput
from warden.taint.resolver import TaintAccumulator, labels_for, reconstruct

TOOL_ALPHABET: Final = string.ascii_lowercase + "_-"
tool_names = st.text(alphabet=TOOL_ALPHABET, min_size=1, max_size=12)
call_sequences = st.lists(tool_names, max_size=15)
# (tool, did_it_run) -- a call that never ran produced no output
mixed_calls = st.lists(st.tuples(tool_names, st.booleans()), max_size=15)

INSERT = (
    "INSERT INTO call_log (call_id, run_id, ts_us, tool, args_hash, policy_outcome, "
    "rule_id, matched_taint, input_taint, execution_outcome, latency_ms, result_seq) "
    "VALUES (:call_id,:run_id,:ts,:tool,'h',:policy_outcome,'r','[]','[]',"
    ":execution_outcome,:latency,:result_seq)"
)


def fresh_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def add_run(conn: sqlite3.Connection, run_id: str) -> None:
    conn.execute(
        "INSERT INTO runs VALUES (?,1,NULL,'BENCH','GOVERNED','a','sha256:p',NULL,NULL,NULL)",
        (run_id,),
    )


def add_call(
    conn: sqlite3.Connection, run_id: str, index: int, tool: str,
    ran: bool = True, policy_outcome: str = "ALLOW",
) -> None:
    conn.execute(
        INSERT,
        {
            "call_id": f"{run_id}-{index}", "run_id": run_id, "ts": index, "tool": tool,
            "policy_outcome": policy_outcome,
            "execution_outcome": "OK" if ran else "NOT_RUN",
            "latency": 1 if ran else None,
            "result_seq": index + 1 if ran else None,
        },
    )


# -- properties of the live accumulator ---------------------------------------


@given(call_sequences)
def test_taint_is_monotone(tools: list[str]) -> None:
    """Labels are only ever added. This is the mechanism behind FPR rising with
    task length, so it needs to be true on purpose rather than by accident."""
    acc = TaintAccumulator(retrieval_tools=())
    previous = acc.current()
    for tool in tools:
        acc.observe_result(tool)
        current = acc.current()
        assert previous <= current
        previous = current


@given(call_sequences)
def test_user_input_is_always_present(tools: list[str]) -> None:
    acc = TaintAccumulator()
    assert UserInput() in acc.current()
    for tool in tools:
        acc.observe_result(tool)
        assert UserInput() in acc.current()


@given(call_sequences)
def test_a_tools_label_never_appears_before_its_first_result(tools: list[str]) -> None:
    acc = TaintAccumulator()
    seen: set[str] = set()
    for tool in tools:
        for unseen in set(tools) - seen - {tool}:
            assert ToolOutput(tool=unseen) not in acc.current()
        acc.observe_result(tool)
        seen.add(tool)
        assert ToolOutput(tool=tool) in acc.current()


@given(call_sequences, st.sets(tool_names, max_size=4))
def test_retrieval_tools_contribute_both_labels(
    tools: list[str], retrieval: set[str]
) -> None:
    acc = TaintAccumulator(retrieval_tools=retrieval)
    for tool in tools:
        acc.observe_result(tool)
    current = acc.current()
    if set(tools) & retrieval:
        assert Retrieved() in current
    else:
        assert Retrieved() not in current
    for tool in tools:
        assert ToolOutput(tool=tool) in current


@given(tool_names, st.sets(tool_names, max_size=4))
def test_labels_for_is_a_superset_of_tool_output(
    tool: str, retrieval: set[str]
) -> None:
    labels = labels_for(tool, frozenset(retrieval))
    assert ToolOutput(tool=tool) in labels
    assert (Retrieved() in labels) == (tool in retrieval)


# -- properties of log reconstruction -----------------------------------------


@given(call_sequences, st.sets(tool_names, max_size=4))
@settings(deadline=None, max_examples=60)
def test_live_and_reconstructed_paths_agree(
    tools: list[str], retrieval: set[str]
) -> None:
    """Two implementations of the same contract. Disagreement means replay is not
    reproducing what actually happened."""
    conn = fresh_db()
    add_run(conn, "r")
    acc = TaintAccumulator(retrieval_tools=retrieval)
    for index, tool in enumerate(tools):
        add_call(conn, "r", index, tool)
        acc.observe_result(tool)
    conn.commit()
    assert reconstruct(conn, RunId("r"), retrieval) == acc.current()


@given(mixed_calls, st.sets(tool_names, max_size=4))
@settings(deadline=None, max_examples=60)
def test_calls_that_never_ran_contribute_no_taint(
    calls: list[tuple[str, bool]], retrieval: set[str]
) -> None:
    """Keyed on execution, not policy. A denied call produced no output."""
    conn = fresh_db()
    add_run(conn, "r")
    acc = TaintAccumulator(retrieval_tools=retrieval)
    seq = 0
    for index, (tool, ran) in enumerate(calls):
        conn.execute(
            INSERT,
            {
                "call_id": f"c{index}", "run_id": "r", "ts": index, "tool": tool,
                "policy_outcome": "ALLOW" if ran else "DENY",
                "execution_outcome": "OK" if ran else "NOT_RUN",
                "latency": 1 if ran else None,
                "result_seq": (seq := seq + 1) if ran else None,
            },
        )
        if ran:
            acc.observe_result(tool)
    conn.commit()
    assert reconstruct(conn, RunId("r"), retrieval) == acc.current()
    never_ran = {t for t, ran in calls if not ran} - {t for t, ran in calls if ran}
    for tool in never_ran:
        assert ToolOutput(tool=tool) not in acc.current()


@given(call_sequences, call_sequences)
@settings(deadline=None, max_examples=60)
def test_taint_never_crosses_runs(first: list[str], second: list[str]) -> None:
    conn = fresh_db()
    add_run(conn, "run-a")
    add_run(conn, "run-b")
    for index, tool in enumerate(first):
        add_call(conn, "run-a", index, tool)
    for index, tool in enumerate(second):
        add_call(conn, "run-b", index, tool)
    conn.commit()

    only_in_b = set(second) - set(first)
    taint_a = reconstruct(conn, RunId("run-a"))
    for tool in only_in_b:
        assert ToolOutput(tool=tool) not in taint_a


@given(call_sequences)
@settings(deadline=None, max_examples=60)
def test_reconstruct_is_deterministic_and_idempotent(tools: list[str]) -> None:
    conn = fresh_db()
    add_run(conn, "r")
    for index, tool in enumerate(tools):
        add_call(conn, "r", index, tool)
    conn.commit()
    first = reconstruct(conn, RunId("r"))
    assert first == reconstruct(conn, RunId("r"))
    assert first == reconstruct(conn, RunId("r"))
