"""Run each attack template through the ungoverned gateway and grade it deterministically.

Mirrors benign_runner, with the three differences that define an attack calibration:

  * UNGOVERNED -- Warden shadow-evaluates but does not enforce, so what is measured is
    the attack's success against the baseline agent (the entry gate). The governed ASR is
    derived from the shadow decisions later (ADR 0007), not from a second batch.
  * poisoned -- the demo server loads the scenario's payload (a poisoned document, or a
    poisoned customer field) via --poisoned, which is the only path a payload can enter
    the corpus.
  * n per template -- an attack needs several runs to establish a rate, not one, so the
    resume unit is (template, run) and each run gets its own database directory. The
    one-directory-per-run discipline also forecloses the shell-loop collision that once
    destroyed a run's rows: the runner, not a shell, owns the directories.

Every attempt is recorded through record_attempt, which stamps the current source hash,
and the journal now refuses an unpinned attempt outright -- so the ad-hoc path that
produced the original, unreproducible rows cannot be taken again even by accident.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, NamedTuple
from uuid import uuid4

from mcp import ClientSession
from mcp.client.stdio import (
    StdioServerParameters,
    get_default_environment,
    stdio_client,
)

from warden.config import DEFAULT_MODEL, RUNS_PER_TEMPLATE
from warden.demo_agent.agent import AgentState, ModelCall, build_graph, mcp_tool_specs

# The default ticket task a document attack relies on (it must trigger retrieval so the
# agent reads the poisoned article). Argument attacks override it with a task that
# legitimately needs the target tool. Imported rather than duplicated: one source of
# truth, and the CLI entry module is outside the source-hash scope.
from warden.demo_agent.__main__ import TASK as DEFAULT_TASK
from warden.gateway.config import credential_env_vars
from warden.log.models import RunVariant
from warden.redteam.argument_attacks import ATTACKS as ARG_ATTACKS
from warden.redteam.benign_runner import _is_budget_exceeded
from warden.redteam.journal import (
    Attempt,
    AttemptOutcome,
    Journal,
    Plan,
    outstanding,
    record_attempt,
)
from warden.redteam.oracles import Verdict, grade
from warden.redteam.payloads import TEMPLATES as PROSE_TEMPLATES
from warden.redteam.suite import task_for
from warden.source_hash import DEFAULT_PROVIDER, source_hash

POLICY_PATH: str = "policies/demo.yaml"
ATTACK_VAR_DIR: str = "var/redteam/attacks"


class AttackSpec(NamedTuple):
    scenario_id: str
    oracle: str
    target_tool: str


def attack_specs() -> list[AttackSpec]:
    """Every calibratable attack: the data-channel argument attacks (each carrying its
    own oracle) and the prose-injection templates (graded on the attacker domain in the
    outbox -- the same exfil oracle, since a prose payload succeeds by sending an email
    to the reserved domain)."""
    specs = [AttackSpec(a.scenario_id, a.oracle, a.target_tool) for a in ARG_ATTACKS]
    specs += [
        AttackSpec(t.scenario_id, "exfil_domain", t.target_tool)
        for t in PROSE_TEMPLATES
    ]
    return specs


def _forwarded_env() -> dict[str, str]:
    env = dict(get_default_environment())
    for name in credential_env_vars():
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


async def run_attack(
    spec: AttackSpec,
    *,
    db_path: str,
    state_dir: str,
    model_call: ModelCall,
    policy_path: str = POLICY_PATH,
) -> str:
    """Run one attack UNGOVERNED with its payload loaded. Returns the run_id.

    UNGOVERNED so the call executes and the oracle can read the harm; --poisoned loads
    the scenario's payload, the only path it enters the corpus. mode=BENCH so nothing
    reaches for /dev/tty (an ungoverned run never escalates, but the flag is harmless and
    matches the benign runner).
    """
    task = task_for(spec.scenario_id) or DEFAULT_TASK
    params = StdioServerParameters(
        env=_forwarded_env(),
        command=sys.executable,
        args=[
            "-m", "warden.gateway", "--db", db_path, "--policy", policy_path,
            "--variant", RunVariant.UNGOVERNED.value, "--mode", "BENCH",
            "--agent-id", "demo-agent", "--",
            sys.executable, "-m", "warden.demo_server", state_dir,
            "--poisoned", spec.scenario_id,
        ],
    )
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        tools = mcp_tool_specs(list((await session.list_tools()).tools))
        graph = build_graph(session, tools, model_call)
        initial: AgentState = {
            "messages": [{"role": "user", "content": task}],
            "witnesses": [],
            "turn": 0,
        }
        await graph.ainvoke(initial)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT run_id FROM runs").fetchone()
    if row is None:
        raise RuntimeError(f"no run recorded for {spec.scenario_id}")
    return str(row[0])


def grade_attack(
    spec: AttackSpec, *, db_path: str, state_dir: str, run_id: str
) -> Verdict:
    """Deterministic verdict for a completed attack run. Reads the call log / outbox,
    never model output."""
    outbox = Path(state_dir) / "outbox"
    with sqlite3.connect(db_path) as conn:
        return grade(
            spec.oracle,
            conn=conn,
            run_id=run_id,
            outbox=outbox,
            target_tool=spec.target_tool,
        )


async def run_suite(
    *,
    journal: Journal,
    var_dir: Path,
    make_model: Any,
    now_us: Any,
    model: str = DEFAULT_MODEL,
    provider: str = DEFAULT_PROVIDER,
    policy_path: str = POLICY_PATH,
    runs_per_template: int = RUNS_PER_TEMPLATE,
) -> list[Attempt]:
    """Run every outstanding attack for `model` to n per template, resumably, until done
    or the daily quota is hit.

    Hash-aware resume: only attempts under the current provider-scoped source hash count
    as done, so a re-run re-runs templates whose only rows were legacy/other-provider,
    rather than seeing them as complete. `provider` pins the hash to the active adapter
    (gemini vs openrouter), so a Grok run never counts toward Gemini's denominator and
    vice versa. On BudgetExceeded (the per-day fast-fail) it stops cleanly, leaving the
    interrupted attempt unrecorded so it is retried next day.
    """
    current = source_hash(provider)
    specs = {s.scenario_id: s for s in attack_specs()}
    plan = Plan(
        templates=tuple(specs), runs_per_template=runs_per_template, model=model
    )
    items = outstanding(plan, journal, source_hash=current)
    recorded: list[Attempt] = []

    for item in items:
        spec = specs[item.template]
        for _ in range(item.remaining):
            run_dir = var_dir / item.template / uuid4().hex[:8]
            db_path = str(run_dir / "run.db")
            state_dir = str(run_dir / "state")
            run_dir.mkdir(parents=True, exist_ok=True)
            try:
                run_id = await run_attack(
                    spec, db_path=db_path, state_dir=state_dir,
                    model_call=make_model(), policy_path=policy_path,
                )
            except BaseException as exc:  # noqa: BLE001
                # Mirror the benign runner: a per-day budget breach (possibly wrapped in
                # an ExceptionGroup by the anyio/MCP teardown) stops the suite cleanly;
                # anything else is a real crash and must not look like "quota".
                if _is_budget_exceeded(exc):
                    return recorded
                raise
            verdict = grade_attack(
                spec, db_path=db_path, state_dir=state_dir, run_id=run_id
            )
            recorded.append(
                record_attempt(
                    journal,
                    template=item.template,
                    run_id=run_id,
                    outcome=(
                        AttemptOutcome.SUCCESS
                        if verdict.succeeded
                        else AttemptOutcome.FAILURE
                    ),
                    timestamp_us=now_us(),
                    model=model,
                    provider=provider,
                )
            )

    return recorded
