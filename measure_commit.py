"""Measure the audit-commit latency on the current filesystem, no model required.

Drives the real gateway over stdio with a scripted model making N read-only calls, so
the two-phase write path (record_decision -> commit -> complete_call -> commit) runs
exactly as in production. Reports decision-path and commit-path latency separately, as
the README does, with the filesystem named.
"""
import asyncio
import sqlite3
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client

from warden.demo_agent.agent import build_graph, mcp_tool_specs

N_CALLS = 20


def blk(**kw):
    return SimpleNamespace(model_dump=lambda kw=kw: dict(kw), **kw)


def scripted(messages, tools):
    n = sum(1 for m in messages if m["role"] == "assistant")
    if n < N_CALLS:
        return SimpleNamespace(content=[blk(
            type="tool_use", id=f"t{n}", name="search_docs",
            input={"query": "report delivery"})])
    return SimpleNamespace(content=[blk(type="text", text="done")])


async def main() -> None:
    import os
    base = Path.home() / "warden" / "var" / "fsbench"
    base.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="run_", dir=str(base)))
    db, state = tmp / "run.db", tmp / "state"
    env = dict(get_default_environment())
    env["DEMO_EMAIL_API_KEY"] = "demo-value"
    params = StdioServerParameters(
        env=env, command=sys.executable,
        args=["-m", "warden.gateway", "--db", str(db), "--policy",
              "policies/demo.yaml", "--variant", "GOVERNED", "--",
              sys.executable, "-m", "warden.demo_server", str(state)])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            g = build_graph(s, mcp_tool_specs(list((await s.list_tools()).tools)), scripted)
            await g.ainvoke({"messages": [{"role": "user", "content": "search"}],
                             "witnesses": [], "turn": 0})

    conn = sqlite3.connect(db)
    fs = subprocess.run(["stat", "-f", "-c", "%T", str(tmp)],
                        capture_output=True, text=True).stdout.strip()
    rows = conn.execute(
        "SELECT decision_latency_us, commit_latency_us FROM call_log "
        "WHERE commit_latency_us IS NOT NULL ORDER BY ts_us").fetchall()
    decisions = [r[0] for r in rows]
    commits = [r[1] for r in rows]

    def summ(xs):
        xs = sorted(xs)
        p95 = xs[min(len(xs) - 1, int(len(xs) * 0.95))]
        return f"n={len(xs)} median={statistics.median(xs):.0f}us p95={p95}us max={max(xs)}us"

    print(f"filesystem: {fs}")
    print(f"decision path: {summ(decisions)}")
    print(f"audit commit : {summ(commits)}")
    warm_d = decisions[1:]
    warm_c = commits[1:]
    print(f"warm decision (drop first): median={statistics.median(warm_d):.0f}us")
    print(f"warm commit   (drop first): median={statistics.median(warm_c):.0f}us")


asyncio.run(main())
