"""Turn-level taint resolution, reconstructed gateway-side.

The resolver inspects no content. That is not a simplification -- it is what the
measurement forced. Because the agent's message list is append-only, every tool result
that has arrived in a run is still in the context that produces the next tool call, so
taint at call N is determined entirely by which tools have already returned. The
arguments are irrelevant.

Span-level attribution was measured and rejected: on a live trace the model copied a
customer's reported issue into a search query, changed one character's case, truncated
it, and a substring test saw nothing. A near-verbatim copy already defeats it.

Taint is never self-reported by the agent. A compromised agent is the threat model, so
asking it what was in its own context is asking the suspect for an alibi. Everything
here is derived from what the gateway itself returned.

Two paths, which must agree:
  * TaintAccumulator -- the live path, incremented as results arrive.
  * reconstruct()    -- derived from the call log, for proxy restart mid-run and as
                        the check that the live path is right.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable

from warden.log.models import RunId
from warden.policy.labels import (
    Retrieved,
    TaintLabel,
    TaintSet,
    ToolOutput,
    UserInput,
)

USER_INPUT: TaintLabel = UserInput()
"""Always present. The operator's prompt is in context for every call in the run.

Semi-trusted, not trusted: direct prompt injection arrives through it, so the absence
of RETRIEVED and TOOL_OUTPUT is not a warrant for a high-consequence tool.
"""


def labels_for(tool: str, retrieval_tools: frozenset[str]) -> TaintSet:
    """The labels a tool's output contributes once it has arrived.

    A retrieval tool contributes RETRIEVED *in addition to* TOOL_OUTPUT:<tool>, not
    instead of it. Disjoint labels would mean a rule matching only `kind: TOOL_OUTPUT`
    silently misses the most obviously untrusted source in the system. Redundancy
    fails safe; disjointness fails silent, and a lint is the wrong thing to hang a
    security invariant on.
    """
    labels: set[TaintLabel] = {ToolOutput(tool=tool)}
    if tool in retrieval_tools:
        labels.add(Retrieved())
    return frozenset(labels)


class TaintAccumulator:
    """The live per-run taint set. Monotone: labels are only ever added."""

    def __init__(self, retrieval_tools: Iterable[str] = ()) -> None:
        self._retrieval_tools = frozenset(retrieval_tools)
        self._labels: set[TaintLabel] = {USER_INPUT}
        self._over_approximated: set[TaintLabel] = set()

    def observe_result(self, tool: str, *, failed: bool = False) -> None:
        """Record that `tool` has returned output into the agent's context.

        Called when a result arrives, never when a call is issued -- a call that was
        denied or that never ran produced no output and contributes nothing. The
        gate is execution, not policy: in an UNGOVERNED shadow run a call whose
        policy_outcome was DENY still executed and still taints.

        `failed` marks an ERROR or TIMEOUT result. Such a call still taints, because
        an error string does reach the model as a tool result -- but that string came
        from Warden, not from the tool, so TOOL_OUTPUT:<tool> is an over-approximation.
        Deliberately kept, and tracked so its cost can be measured rather than
        disclosed: see over_approximated().
        """
        labels = labels_for(tool, self._retrieval_tools)
        self._labels |= labels
        if failed:
            self._over_approximated |= labels

    def current(self) -> TaintSet:
        return frozenset(self._labels)

    def over_approximated(self) -> bool:
        """True when at least one label present came only from a failed call.

        A label contributed by both a successful and a failed call is not
        over-approximated -- the successful one justifies it on its own.
        """
        return bool(self._over_approximated - (self._labels - self._over_approximated))


def reconstruct(
    conn: sqlite3.Connection,
    run_id: RunId,
    retrieval_tools: Iterable[str] = (),
    before_result_seq: int | None = None,
) -> TaintSet:
    """Rebuild a run's taint set from the call log.

    Orders by result_seq -- result-arrival order, which is what the accumulator
    observed. Rows with a NULL result_seq are calls that never ran and are skipped;
    the schema guarantees that is exactly the NOT_RUN set.

    `before_result_seq` of None means every result so far, which is the proxy
    restart-recovery case. A value means the state as of just before that result.
    """
    return _replay(conn, run_id, retrieval_tools, before_result_seq).current()


def reconstruct_accumulator(
    conn: sqlite3.Connection,
    run_id: RunId,
    retrieval_tools: Iterable[str] = (),
    before_result_seq: int | None = None,
) -> TaintAccumulator:
    """Same replay as reconstruct(), returning the accumulator so the caller also
    gets over_approximated(). This is the proxy restart-recovery entry point."""
    return _replay(conn, run_id, retrieval_tools, before_result_seq)


def _replay(
    conn: sqlite3.Connection,
    run_id: RunId,
    retrieval_tools: Iterable[str],
    before_result_seq: int | None,
) -> TaintAccumulator:
    sql = (
        "SELECT tool, execution_outcome FROM call_log "
        "WHERE run_id = ? AND result_seq IS NOT NULL"
    )
    params: list[object] = [run_id]
    if before_result_seq is not None:
        sql += " AND result_seq < ?"
        params.append(before_result_seq)
    sql += " ORDER BY result_seq"

    accumulator = TaintAccumulator(retrieval_tools)
    for row in conn.execute(sql, params):
        accumulator.observe_result(
            str(row[0]), failed=str(row[1]) in ("ERROR", "TIMEOUT")
        )
    return accumulator
