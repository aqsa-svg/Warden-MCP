"""End-to-end credential isolation.

Not a review convention -- a test. It drives a real gateway over stdio with a sentinel
credential, then scans the raw SQLite file bytes, all gateway stderr, and every demo
state file for that sentinel.

Raw file bytes rather than column values: SQLite retains freed pages, so a secret that
was written and later deleted would still be in the file. Scanning the bytes is the
stronger check.

The UNGOVERNED case is what makes the result meaningful. In a GOVERNED run send_email
is denied, so nothing is ever injected and a clean scan proves little. A shadow run
logs the same DENY and executes anyway, so the credential really is injected, really
reaches the upstream server, and must still appear nowhere in the audit trail.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import (
    StdioServerParameters,
    get_default_environment,
    stdio_client,
)

SENTINEL = "WARDEN-CANARY-b7f2e91a4c8d-DO-NOT-LOG"
CALLS: list[tuple[str, dict[str, Any]]] = [
    ("search_docs", {"query": "report delivery"}),
    ("send_email", {"to": "dana@example.com", "subject": "hi", "body": "x"}),
]


async def drive(variant: str, tmp: Path) -> tuple[Path, Path, Path, list[str]]:
    db = tmp / f"{variant}.db"
    state = tmp / f"{variant}_state"
    stderr_path = tmp / f"{variant}.stderr"

    env = dict(get_default_environment())
    env["DEMO_EMAIL_API_KEY"] = SENTINEL
    params = StdioServerParameters(
        env=env,
        command=sys.executable,
        args=[
            "-m", "warden.gateway", "--db", str(db),
            "--policy", "policies/demo.yaml", "--variant", variant, "--",
            sys.executable, "-m", "warden.demo_server", str(state),
        ],
    )
    with open(stderr_path, "w+", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                schema = next(
                    t.input_schema or {} for t in listed.tools if t.name == "send_email"
                )
                agent_params = sorted((schema.get("properties") or {}).keys())
                for name, args in CALLS:
                    await session.call_tool(name, args)
    return db, state, stderr_path, agent_params


def scan_for_sentinel(db: Path, state: Path, stderr_path: Path) -> list[str]:
    found: list[str] = []
    if SENTINEL.encode() in db.read_bytes():
        found.append("sqlite file bytes")
    if SENTINEL in stderr_path.read_text(encoding="utf-8", errors="replace"):
        found.append("gateway stderr")
    for path in state.rglob("*"):
        if path.is_file() and SENTINEL.encode() in path.read_bytes():
            found.append(f"state file {path.name}")
    return found


@pytest.mark.parametrize("variant", ["GOVERNED", "UNGOVERNED"])
def test_credential_never_reaches_the_audit_trail(
    variant: str, tmp_path: Path
) -> None:
    db, state, stderr_path, agent_params = asyncio.run(drive(variant, tmp_path))

    assert "api_key" not in agent_params, (
        "the credential parameter was advertised to the agent; it must be stripped "
        "from the projected schema so the model never learns it exists"
    )
    assert agent_params == ["body", "subject", "to"]

    leaks = scan_for_sentinel(db, state, stderr_path)
    assert not leaks, f"credential value found in: {leaks}"


def test_shadow_run_injects_the_credential_for_real(tmp_path: Path) -> None:
    """Proves the clean scan above is not vacuous.

    An UNGOVERNED run logs DENY and executes anyway, so the credential is genuinely
    injected and the upstream server genuinely receives it -- recorded as a header
    that says only WHETHER it arrived, never its value.
    """
    db, state, _, _ = asyncio.run(drive("UNGOVERNED", tmp_path))

    outbox = sorted((state / "outbox").glob("*.eml"))
    assert outbox, "shadow run should have executed send_email despite the DENY"
    assert "X-Warden-Auth: present" in outbox[0].read_text(encoding="utf-8")

    rows = dict(
        sqlite3.connect(db).execute(
            "SELECT tool, policy_outcome || '/' || execution_outcome FROM call_log"
        )
    )
    assert rows["send_email"] == "DENY/OK", (
        "the shadow run must record what the policy would have done while the call "
        "still executes"
    )


def test_gateway_refuses_to_start_without_a_declared_credential(
    tmp_path: Path
) -> None:
    """A gateway that cannot resolve a declared credential must not start.

    Deferring the failure to call time turns a configuration error into an
    unexplainable upstream rejection in the middle of a run.
    """
    env = dict(get_default_environment())
    env.pop("DEMO_EMAIL_API_KEY", None)

    async def attempt() -> None:
        params = StdioServerParameters(
            env=env,
            command=sys.executable,
            args=[
                "-m", "warden.gateway", "--db", str(tmp_path / "x.db"),
                "--policy", "policies/demo.yaml", "--",
                sys.executable, "-m", "warden.demo_server", str(tmp_path / "s"),
            ],
        )
        with open(tmp_path / "err.txt", "w+", encoding="utf-8") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

    with pytest.raises(BaseException):
        asyncio.run(attempt())
    assert "DEMO_EMAIL_API_KEY" in (tmp_path / "err.txt").read_text(
        encoding="utf-8", errors="replace"
    )


def test_credential_env_is_not_inherited_by_spawned_servers() -> None:
    """MCP's stdio_client passes a minimal allowlist environment rather than the
    parent's, so secrets do not leak into spawned servers by default. Warden relies
    on that: credentials are handed to the gateway explicitly and never forwarded on
    to the upstream server, which receives them only inside call arguments."""
    os.environ["WARDEN_LEAK_PROBE"] = SENTINEL
    try:
        assert "WARDEN_LEAK_PROBE" not in get_default_environment()
        assert "DEMO_EMAIL_API_KEY" not in get_default_environment()
    finally:
        os.environ.pop("WARDEN_LEAK_PROBE", None)
