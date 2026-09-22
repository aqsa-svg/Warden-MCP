"""Gateway run setup: connect upstream, ingest, project schemas, open the run.

Split out of proxy.py so the I/O shell -- the part a reader opens first -- is only the
request path. Everything here happens once, before any tool call is served.
"""

from __future__ import annotations

import hashlib
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from sqlite3 import Connection
from typing import Any, Callable, Mapping

import mcp.types as types
import yaml
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from warden.gateway.credentials import (
    CredentialStore,
    assert_projection_is_subset,
    project_schema,
)
from warden.gateway.drift import SchemaGuard
from warden.log.models import RunId, RunMode, RunVariant, new_run_id
from warden.log.writer import start_run
from warden.policy.schema import PolicyConfig
from warden.registry.ingest import ingest_tools
from warden.registry.models import ToolAdvertisement, canonical_hash
from warden.taint.resolver import TaintAccumulator

Logger = Callable[..., None]


@dataclass
class GatewaySession:
    """Everything the request path needs, resolved once at startup."""

    upstream: ClientSession
    run_id: RunId
    policy: PolicyConfig
    policy_hash: str
    accepted: frozenset[str]
    forwarded: list[types.Tool]
    guard: SchemaGuard
    credentials: CredentialStore
    accumulator: TaintAccumulator


def load_policy(policy_path: str) -> tuple[PolicyConfig, str]:
    """Parse the policy and hash its raw bytes.

    The hash is over the file as written, not over the parsed model: "which policy
    produced these decisions" is a question about the file under version control.
    """
    raw = Path(policy_path).read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return PolicyConfig.model_validate(yaml.safe_load(raw)), digest


async def open_session(
    stack: AsyncExitStack,
    conn: Connection,
    *,
    upstream_command: str,
    upstream_args: list[str],
    policy_path: str,
    server_name: str,
    agent_id: str,
    variant: RunVariant,
    mode: RunMode,
    drift_ttl_us: int,
    credential_spec: Mapping[str, Mapping[str, str]],
    now_us: Callable[[], int],
    log: Logger,
) -> GatewaySession:
    policy, policy_hash = load_policy(policy_path)
    # require=True: a gateway that cannot resolve a declared credential must not
    # start. Deferring the failure to call time turns a configuration error into an
    # unexplainable upstream rejection mid-run.
    credentials = CredentialStore.from_env(credential_spec, require=True)
    run_id = new_run_id()

    read, write = await stack.enter_async_context(
        stdio_client(
            StdioServerParameters(command=upstream_command, args=upstream_args)
        )
    )
    upstream = await stack.enter_async_context(ClientSession(read, write))
    await upstream.initialize()

    listed = await upstream.list_tools()
    ingested = ingest_tools(
        conn,
        server_name,
        [
            ToolAdvertisement(t.name, t.description or "", t.input_schema or {})
            for t in listed.tools
        ],
        now_us=now_us(),
    )
    conn.commit()
    accepted = frozenset(t.tool_name for t in ingested.accepted)

    # The agent-facing schema is upstream minus the credential parameters. The
    # registry pins the UPSTREAM hash; the projection is a derived value, so it gets
    # no hash of its own -- only the subset invariant, which catches a projection
    # that adds or retypes anything.
    forwarded: list[types.Tool] = []
    for tool in listed.tools:
        if tool.name not in accepted:
            continue
        upstream_schema: dict[str, Any] = tool.input_schema or {}
        projected = project_schema(
            upstream_schema, credentials.parameters_for(tool.name)
        )
        assert_projection_is_subset(upstream_schema, projected)
        forwarded.append(tool.model_copy(update={"input_schema": projected}))

    async def discover() -> dict[str, str]:
        fresh = await upstream.list_tools()
        return {t.name: canonical_hash(t.input_schema or {}) for t in fresh.tools}

    guard = SchemaGuard(
        {t.tool_name: t.schema_hash for t in ingested.accepted},
        discover,
        ttl_us=drift_ttl_us,
        pinned_at_us=now_us(),
    )

    start_run(
        conn,
        run_id=run_id,
        mode=mode,
        variant=variant,
        agent_id=agent_id,
        policy_hash=policy_hash,
        policy_path=policy_path,
        git_sha=None,
        notes=None,
        now_us=now_us(),
    )
    conn.commit()
    log(
        "run_started",
        run_id=run_id,
        variant=variant.value,
        mode=mode.value,
        policy_hash=policy_hash,
        tools=sorted(accepted),
        credential_tools=sorted(
            name for name in accepted if credentials.parameters_for(name)
        ),
        rejected=[r.raw_name for r in ingested.rejected],
        drifted=list(ingested.drifted),
    )

    return GatewaySession(
        upstream=upstream,
        run_id=run_id,
        policy=policy,
        policy_hash=policy_hash,
        accepted=accepted,
        forwarded=forwarded,
        guard=guard,
        credentials=credentials,
        accumulator=TaintAccumulator(policy.retrieval_tools),
    )
