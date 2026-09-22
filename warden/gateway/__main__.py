"""Run the gateway proxy over stdio.

  python -m warden.gateway --db var/warden.db -- python -m warden.demo_server var/demo

Everything after `--` is the upstream server command.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from warden.db import open_db
from warden.gateway.proxy import ProxyConfig, serve
from warden.gateway.config import CREDENTIAL_SPEC
from warden.log.models import RunMode, RunVariant

DEFAULT_DB = "var/warden.db"
DEFAULT_POLICY = "policies/demo.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden-gateway")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--server-name", default="demo")
    parser.add_argument("--agent-id", default="demo-agent")
    parser.add_argument(
        "--variant", default=RunVariant.GOVERNED.value,
        choices=[v.value for v in RunVariant],
        help="GOVERNED enforces decisions; UNGOVERNED logs them and does not act.")
    parser.add_argument(
        "--mode", default=RunMode.LIVE.value, choices=[m.value for m in RunMode])
    parser.add_argument("--scenario-id", default=None)
    parser.add_argument("upstream", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    upstream = [a for a in args.upstream if a != "--"]
    if not upstream:
        parser.error("an upstream command is required after --")

    open_db(args.db).close()  # create schema before the proxy opens its own handle
    asyncio.run(
        serve(
            ProxyConfig(
                upstream_command=upstream[0],
                upstream_args=upstream[1:],
                db_path=args.db,
                policy_path=args.policy,
                server_name=args.server_name,
                agent_id=args.agent_id,
                variant=RunVariant(args.variant),
                mode=RunMode(args.mode),
                scenario_id=args.scenario_id,
                credential_spec=CREDENTIAL_SPEC,
            )
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
