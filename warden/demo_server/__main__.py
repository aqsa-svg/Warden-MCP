"""Run the demo MCP server over stdio.

  python -m warden.demo_server <state_dir> [--poisoned <scenario_id>]

Without --poisoned the corpus is clean. A benign scenario cannot load a payload by
accident: there is no mutable module-level list to inject into, so the only way a
poisoned document enters the corpus is this flag.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from warden.demo_server.server import main
from warden.redteam.suite import corpus_mods_for, customer_overrides_for

DEFAULT_STATE_DIR = Path("var/demo_state")


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden-demo-server")
    parser.add_argument("state_dir", nargs="?", default=str(DEFAULT_STATE_DIR))
    parser.add_argument(
        "--poisoned",
        default=None,
        help="Red-team scenario id whose payload to load into the corpus.",
    )
    args = parser.parse_args(argv)
    mods = corpus_mods_for(args.poisoned)
    main(
        Path(args.state_dir),
        mods.appends,
        mods.replacements,
        customer_overrides_for(args.poisoned),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
