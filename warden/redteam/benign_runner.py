"""Run a benign scenario through the real gateway and grade what Warden did to it.

Benign scenarios run GOVERNED (enforcement on) with no poison: the question is whether
Warden blocks or escalates legitimate work. The model is injected so the orchestration
is testable with a stub -- the same shape the attack stubs use -- and reused unchanged
for real runs.

One scenario per database, so a run's outcome is read back by run_id alone.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import (
    StdioServerParameters,
    get_default_environment,
    stdio_client,
)

from warden.config import DEFAULT_MODEL
from warden.demo_agent.agent import AgentState, ModelCall, build_graph, mcp_tool_specs
from warden.gateway.config import credential_env_vars
from warden.log.models import RunVariant
from warden.redteam.benign import SCENARIOS, BenignScenario
from warden.redteam.benign_journal import BenignJournal, BenignRecord
from warden.redteam.benign_oracle import classify_run
from warden.source_hash import source_hash


def _forwarded_env() -> dict[str, str]:
    env = dict(get_default_environment())
    for name in credential_env_vars():
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


async def run_scenario(
    scenario: BenignScenario,
    *,
    db_path: str,
    state_dir: str,
    model_call: ModelCall,
    policy_path: str = "policies/demo.yaml",
    variant: RunVariant = RunVariant.GOVERNED,
    mode: str = "BENCH",
) -> str:
    """Run one benign scenario's task through the governed gateway. Returns the run_id.

    No `--poisoned`: a benign run must be structurally incapable of loading a payload,
    which the demo server guarantees by only injecting one when the flag is present.

    mode=BENCH so an escalation auto-denies without reaching for /dev/tty -- a benchmark
    does not wait for a human, and a REQUIRE_APPROVAL that auto-denies is exactly the
    ESCALATE outcome the FPR split measures.
    """
    params = StdioServerParameters(
        env=_forwarded_env(),
        command=sys.executable,
        args=[
            "-m", "warden.gateway", "--db", db_path, "--policy", policy_path,
            "--variant", variant.value, "--mode", mode,
            "--agent-id", "demo-agent", "--",
            sys.executable, "-m", "warden.demo_server", state_dir,
        ],
    )
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        tools = mcp_tool_specs(list((await session.list_tools()).tools))
        graph = build_graph(session, tools, model_call)
        initial: AgentState = {
            "messages": [{"role": "user", "content": scenario.task}],
            "witnesses": [],
            "turn": 0,
        }
        await graph.ainvoke(initial)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT run_id FROM runs").fetchone()
    if row is None:
        raise RuntimeError(f"no run recorded for {scenario.scenario_id}")
    return str(row[0])


def grade_and_record(
    db_path: str,
    scenario: BenignScenario,
    journal: BenignJournal,
    *,
    run_id: str,
    timestamp_us: int,
    model: str = DEFAULT_MODEL,
) -> BenignRecord:
    """Classify a completed benign run and append it to the journal, hash-stamped."""
    with sqlite3.connect(db_path) as conn:
        outcome = classify_run(conn, run_id)
    record = BenignRecord(
        scenario_id=scenario.scenario_id,
        run_id=run_id,
        observed=outcome.observed,
        expected=scenario.expected,
        timestamp_us=timestamp_us,
        model=model,
        source_hash=source_hash(),
    )
    journal.record(record)
    return record


def read_run_timestamp(db_path: str, run_id: str) -> int:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT started_at_us FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return int(row[0]) if row else 0


async def run_suite(
    *,
    journal: BenignJournal,
    var_dir: Path,
    make_model: Any,
    model: str = DEFAULT_MODEL,
    now_us: Any,
) -> list[BenignRecord]:
    """Run every outstanding benign scenario for `model`, resumably, until done or the
    daily quota is hit.

    Resumes from the journal: a scenario already recorded is skipped, never re-charged.
    On BudgetExceeded (the per-day quota fast-fail from the model adapter) it stops
    cleanly, leaving the interrupted scenario unrecorded so it is retried next day --
    an incomplete run must not be graded.

    `make_model` is a zero-arg factory returning a fresh ModelCall per scenario, so the
    real Gemini client is created lazily and tests can inject a stub.
    """
    # Hash-aware: a scenario recorded under different code (e.g. before a policy
    # change) does not count as done, so it is re-run rather than left stale.
    done_before = journal.done_scenarios(model, source_hash())
    todo = [s for s in SCENARIOS if s.scenario_id not in done_before]
    recorded: list[BenignRecord] = []

    for scenario in todo:
        run_dir = var_dir / scenario.scenario_id
        db_path = str(run_dir / "run.db")
        state_dir = str(run_dir / "state")
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            run_id = await run_scenario(
                scenario, db_path=db_path, state_dir=state_dir,
                model_call=make_model(),
            )
        except BaseException as exc:  # noqa: BLE001
            # The daily-quota fast-fail raises BudgetExceeded, but the MCP stdio
            # teardown runs under an anyio task group, so it can reach here wrapped in
            # an ExceptionGroup. Stop cleanly on a budget breach from either shape;
            # re-raise anything else -- an unrelated crash must not look like "quota".
            if _is_budget_exceeded(exc):
                break
            raise
        record = grade_and_record(
            db_path, scenario, journal, run_id=run_id,
            timestamp_us=now_us(), model=model,
        )
        recorded.append(record)

    return recorded


def _is_budget_exceeded(exc: BaseException) -> bool:
    """True if exc is, wraps, or was caused by BudgetExceeded.

    Handles the bare exception, an ExceptionGroup containing it (MCP/anyio teardown),
    and a __cause__/__context__ chain."""
    from warden.errors import BudgetExceeded

    if isinstance(exc, BudgetExceeded):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_is_budget_exceeded(sub) for sub in exc.exceptions)
    cause = exc.__cause__ or exc.__context__
    return cause is not None and _is_budget_exceeded(cause)
