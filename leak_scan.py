"""Re-establish the credential-isolation guarantee on the current filesystem.

Runs the gateway UNGOVERNED (so send_email executes despite the exfil DENY and the
credential is really injected), calls it directly over MCP, then scans the raw SQLite
file bytes, the gateway stderr, and every state file for the sentinel credential. Raw
bytes rather than column values: SQLite retains freed pages, so a value written and
deleted would still be found.
"""
import asyncio
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client

SENTINEL = "WARDEN-CANARY-leak-scan-9f3a2b71-DO-NOT-LOG"


async def main() -> None:
    base = Path.home() / "warden" / "var" / "leakscan"
    base.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="run_", dir=str(base)))
    db, state, err = tmp / "run.db", tmp / "state", tmp / "gw.stderr"
    env = dict(get_default_environment())
    env["DEMO_EMAIL_API_KEY"] = SENTINEL
    params = StdioServerParameters(
        env=env, command=sys.executable,
        args=["-m", "warden.gateway", "--db", str(db), "--policy",
              "policies/demo.yaml", "--variant", "UNGOVERNED", "--",
              sys.executable, "-m", "warden.demo_server", str(state)])
    with open(err, "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = {t.name: t for t in (await s.list_tools()).tools}
                se = tools["send_email"].input_schema or {}
                params_shown = sorted((se.get("properties") or {}).keys())
                await s.call_tool("send_email", {
                    "to": "dana@example.com", "subject": "hi", "body": "x"})

    leaks = []
    if SENTINEL.encode() in db.read_bytes():
        leaks.append("sqlite file bytes")
    if SENTINEL in err.read_text(encoding="utf-8", errors="replace"):
        leaks.append("gateway stderr")
    for p in state.rglob("*"):
        if p.is_file() and SENTINEL.encode() in p.read_bytes():
            leaks.append(f"state:{p.name}")

    outbox = list((state / "outbox").glob("*.eml"))
    injected = outbox and "X-Warden-Auth: present" in outbox[0].read_text()
    print(f"agent-facing send_email params: {params_shown}")
    print(f"api_key stripped from schema: {'api_key' not in params_shown}")
    print(f"credential actually injected (outbox authed): {bool(injected)}")
    print(f"LEAK SCAN: {'*** FOUND IN ' + ', '.join(leaks) + ' ***' if leaks else 'clean (db bytes, stderr, state files)'}")


asyncio.run(main())
