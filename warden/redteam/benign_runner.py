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
from warden.redteam.benign import BenignScenario
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
) -> str:
    """Run one benign scenario's task through the governed gateway. Returns the run_id.

    No `--poisoned`: a benign run must be structurally incapable of loading a payload,
    which the demo server guarantees by only injecting one when the flag is present.
    """
    params = StdioServerParameters(
        env=_forwarded_env(),
        command=sys.executable,
        args=[
            "-m", "warden.gateway", "--db", db_path, "--policy", policy_path,
            "--variant", variant.value, "--agent-id", "demo-agent", "--",
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
