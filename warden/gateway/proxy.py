"""Governed MCP proxy: the request path.

Run setup lives in warden.gateway.session; the ordering and its guarantees live in
warden.gateway.wrapper. This module is only what happens per tool call.

stdout is the JSON-RPC channel. Every diagnostic goes to stderr, one JSON object per
line -- a stray print() to stdout corrupts the protocol stream.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Mapping

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from warden.errors import BudgetExceeded, PolicyDenied, WardenError
from warden.gateway.approval import make_approver
from warden.gateway.drift import DEFAULT_TTL_US, DriftFinding
from warden.gateway.session import GatewaySession, open_session
from warden.gateway.wrapper import decide, enforce, monotonic_us
from warden.log.models import (
    CallId,
    ExecutionOutcome,
    RunMode,
    RunVariant,
    new_call_id,
)
from warden.log.writer import complete_call, finish_run, record_decision
from warden.policy.decision import (
    ClassifiedTool,
    ToolCallRequest,
    UnclassifiedTool,
    UnknownTool,
)
from warden.policy.labels import TaintSet
from warden.policy.rule_ids import RULE_ID_BUDGET_EXCEEDED
from warden.registry.models import canonical_hash


def log_line(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}), file=sys.stderr, flush=True)


def now_us() -> int:
    return time.time_ns() // 1_000


@dataclass
class ProxyConfig:
    upstream_command: str
    upstream_args: list[str]
    db_path: str
    policy_path: str
    server_name: str = "demo"
    agent_id: str = "demo-agent"
    variant: RunVariant = RunVariant.GOVERNED
    mode: RunMode = RunMode.LIVE
    scenario_id: str | None = None
    drift_ttl_us: int = DEFAULT_TTL_US
    credential_spec: Mapping[str, Mapping[str, str]] = field(default_factory=dict)


def resolve_tool(
    name: str, session: GatewaySession, agent_id: str
) -> ToolCallRequest:
    """Registry lookup. Unknown and unclassified are distinct deny stories."""
    if name not in session.accepted:
        return ToolCallRequest(tool=name, agent=agent_id, resolution=UnknownTool())
    classification = session.policy.classification.get(name)
    if classification is None:
        return ToolCallRequest(
            tool=name, agent=agent_id, resolution=UnclassifiedTool(tool=name)
        )
    return ToolCallRequest(
        tool=name,
        agent=agent_id,
        resolution=ClassifiedTool(
            tool=name,
            risk_level=classification.risk_level,
            side_effect=classification.side_effect,
        ),
    )


async def serve(config: ProxyConfig) -> None:
    conn = sqlite3.connect(config.db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    async with AsyncExitStack() as stack:
        session = await open_session(
            stack,
            conn,
            upstream_command=config.upstream_command,
            upstream_args=config.upstream_args,
            policy_path=config.policy_path,
            server_name=config.server_name,
            agent_id=config.agent_id,
            variant=config.variant,
            mode=config.mode,
            drift_ttl_us=config.drift_ttl_us,
            credential_spec=config.credential_spec,
            now_us=now_us,
            log=log_line,
        )
        approve = make_approver(config.mode, log_line)
        result_counter = 0
        attempted_calls = 0

        async def on_list_tools(
            _ctx: Any, _params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=session.forwarded)

        async def on_call_tool(
            _ctx: Any, params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            nonlocal result_counter, attempted_calls
            arguments: dict[str, Any] = dict(params.arguments or {})
            request = resolve_tool(params.name, session, config.agent_id)

            async def verify_schema() -> DriftFinding:
                return await session.guard.verify(params.name, now_us=now_us())

            def resolve_taint() -> TaintSet:
                return session.accumulator.current()

            # Counts every call the agent attempts, executed or not -- the budget is a
            # volume cap, and a run that hammers a denied tool is still hammering.
            calls_so_far = attempted_calls
            attempted_calls += 1

            decision, taint, timing = await decide(
                request,
                session.policy,
                resolve_taint=resolve_taint,
                verify_schema=verify_schema,
                approve=approve,
                variant=config.variant,
                monotonic_us=monotonic_us,
                calls_so_far=calls_so_far,
            )

            # args_hash BEFORE injection: hashing credential-bearing arguments would
            # make the log secret-derived, and would break determinism across
            # credential rotation in a way that reads as flakiness, not a bug.
            args_hash = canonical_hash(arguments)
            call_id: CallId = new_call_id()

            record_decision(
                conn,
                call_id=call_id,
                run_id=session.run_id,
                scenario_id=config.scenario_id,
                tool=params.name,
                args_hash=args_hash,
                decision=decision,
                input_taint=taint,
                taint_over_approximated=session.accumulator.over_approximated(),
                decision_latency_us=timing.decision_us,
                approval_wait_us=timing.approval_us,
                now_us=now_us(),
            )
            commit_started = monotonic_us()
            conn.commit()
            commit_us = monotonic_us() - commit_started

            log_line(
                "policy_decision",
                run_id=session.run_id,
                call_id=call_id,
                tool=params.name,
                args_hash=args_hash,
                rule_id=decision.rule_id,
                policy_outcome=decision.outcome.value,
                risk_level=(
                    None if decision.risk_level is None else decision.risk_level.value
                ),
                side_effect=(
                    None if decision.side_effect is None else decision.side_effect.value
                ),
                matched_taint=sorted(label.kind for label in decision.matched_taint),
                variant=config.variant.value,
                decision_latency_us=timing.decision_us,
                approval_wait_us=timing.approval_us,
                commit_latency_us=commit_us,
            )

            if not enforce(decision, config.variant):
                complete_call(
                    conn,
                    call_id,
                    execution_outcome=ExecutionOutcome.NOT_RUN,
                    latency_ms=None,
                    result_seq=None,
                    commit_latency_us=commit_us,
                )
                conn.commit()
                # The caller sees a fixed, argument-less refusal and nothing else.
                # No rule id, no risk level, no description: anything derived from the
                # policy teaches an injected prompt how to probe it. A budget breach
                # gets the distinct BudgetExceeded message -- "you have made too many
                # calls" is a rate signal, not policy shape, so it is safe to surface
                # and lets an agent tell a cap from a per-call denial.
                refusal: WardenError = (
                    BudgetExceeded()
                    if decision.rule_id == RULE_ID_BUDGET_EXCEEDED
                    else PolicyDenied()
                )
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=str(refusal))],
                    is_error=True,
                )

            injected = session.credentials.inject(params.name, arguments)
            started = time.perf_counter()
            try:
                result = await session.upstream.call_tool(params.name, injected)
                latency_ms = int((time.perf_counter() - started) * 1000)
                outcome = (
                    ExecutionOutcome.ERROR if result.is_error else ExecutionOutcome.OK
                )
            except Exception as exc:
                latency_ms = int((time.perf_counter() - started) * 1000)
                outcome = ExecutionOutcome.ERROR
                result = types.CallToolResult(
                    content=[types.TextContent(type="text", text=str(exc))],
                    is_error=True,
                )

            result_counter += 1
            complete_call(
                conn,
                call_id,
                execution_outcome=outcome,
                latency_ms=latency_ms,
                result_seq=result_counter,
                commit_latency_us=commit_us,
            )
            conn.commit()

            # Taint accrues only from a call that produced output. An ERROR result
            # still taints -- the error string reaches the model -- but the label is
            # an over-approximation, marked so its cost can be measured.
            session.accumulator.observe_result(
                params.name, failed=outcome is not ExecutionOutcome.OK
            )
            return result

        server: Server[object] = Server(
            "warden-gateway",
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )
        async with stdio_server() as (client_read, client_write):
            await server.run(
                client_read, client_write, server.create_initialization_options()
            )

    finish_run(conn, session.run_id, now_us=now_us())
    conn.commit()
    conn.close()
    log_line("run_finished", run_id=session.run_id)
