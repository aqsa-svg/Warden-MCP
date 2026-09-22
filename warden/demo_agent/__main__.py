"""Run the demo agent against the gateway proxy.

  python -m warden.demo_agent --db var/warden.db --state var/demo_state

Reads GEMINI_API_KEY (or GOOGLE_API_KEY) from the environment, then .env.
.env is gitignored; .env.example is the committed blank template.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any

from dotenv import load_dotenv
from google import genai
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcp.client.stdio import get_default_environment

from warden.demo_agent.agent import SYSTEM, AgentState, build_graph, mcp_tool_specs
from warden.gateway.config import credential_env_vars
from warden.demo_agent.gemini import DEFAULT_MODEL, gemini_model
from warden.redteam.suite import task_for
from warden.demo_agent.provenance import render

TASK = (
    "Customer CUS-1001 has reported a problem. Look up their record, find the "
    "knowledge base article that explains the issue, and open a support ticket "
    "for them that references the article id."
)


async def run(
    db: str, state: str, model: str, policy: str, variant: str,
    poisoned: str | None, task: str | None,
) -> int:
    # stdio_client scrubs the environment by default, so the gateway's credentials
    # must be handed to it explicitly. Note what is NOT forwarded: the gateway passes
    # nothing to the upstream server, which receives secrets only inside call
    # arguments, after the authorization decision.
    forwarded_env = dict(get_default_environment())
    for name in credential_env_vars():
        value = os.environ.get(name)
        if value:
            forwarded_env[name] = value

    params = StdioServerParameters(
        env=forwarded_env,
        command=sys.executable,
        args=[
            "-m", "warden.gateway", "--db", db, "--policy", policy,
            "--variant", variant, "--agent-id", "demo-agent", "--",
            sys.executable, "-m", "warden.demo_server", state,
            *(["--poisoned", poisoned] if poisoned else []),
        ],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = mcp_tool_specs(list(listed.tools))
            graph = build_graph(
                session,
                tools,
                gemini_model(
                    genai.Client(), SYSTEM, model,
                    on_retry=lambda n, delay: print(
                        f"[rate limited] attempt {n}, sleeping {delay:.0f}s",
                        file=sys.stderr, flush=True),
                ),
            )
            initial: AgentState = {
                "messages": [{"role": "user", "content": task or TASK}],
                "witnesses": [],
                "turn": 0,
            }
            final: dict[str, Any] = await graph.ainvoke(initial)

    for message in final["messages"]:
        content = message.get("content")
        if message["role"] == "assistant" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    print(block["text"])

    print("\n--- context provenance at tool-call time ---")
    print(render(final["witnesses"]))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden-demo-agent")
    parser.add_argument("--db", default="var/warden.db")
    parser.add_argument("--state", default="var/demo_state")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--policy", default="policies/demo.yaml")
    parser.add_argument("--variant", default="GOVERNED",
                        choices=["GOVERNED", "UNGOVERNED"])
    parser.add_argument("--poisoned", default=None,
                        help="Red-team scenario id to load into the corpus.")
    parser.add_argument("--task", default=None,
                        help="Override the agent task (default: per-scenario or built-in).")
    args = parser.parse_args(argv)

    load_dotenv()

    # The gateway fails closed on an unresolved declared credential, which is
    # correct -- but it does so in a subprocess, where the client only sees
    # "Connection closed". Check here so the message is actionable.
    absent = [name for name in credential_env_vars() if not os.environ.get(name)]
    if absent:
        parser.error(
            "the gateway declares credentials that are not set: "
            + ", ".join(absent)
            + ". Add them to .env (any non-empty value works for the demo -- they "
            "exist to prove Warden holds the secret, strips it from the schema the "
            "agent sees, and injects it after the authorization decision)."
        )

    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        parser.error(
            "no Gemini credentials found. Copy .env.example to .env and set "
            "GEMINI_API_KEY, or export it in your shell. "
            "Get a key at https://aistudio.google.com/apikey"
        )
    task = args.task or task_for(args.poisoned)
    return asyncio.run(
        run(args.db, args.state, args.model, args.policy, args.variant,
            args.poisoned, task)
    )


if __name__ == "__main__":
    sys.exit(main())
