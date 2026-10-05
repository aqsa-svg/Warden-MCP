"""Warden CLI."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Annotated

import typer

from warden.config import (
    DAILY_REQUEST_BUDGET,
    DEFAULT_MODEL,
    REQUESTS_PER_RUN,
    RUNS_PER_TEMPLATE,
)
from warden.db import open_db
from warden.redteam.journal import Journal, Plan, outstanding, requests_needed
from warden.redteam.preflight import preflight
from warden.source_hash import source_hash
from warden.redteam.argument_attacks import BY_SCENARIO as ARG_SCENARIO
from warden.redteam.suite import BY_SCENARIO

app = typer.Typer(add_completion=False, help="Warden: a governed MCP gateway.")
redteam = typer.Typer(add_completion=False, help="Red-team suite.")
app.add_typer(redteam, name="redteam")
benign = typer.Typer(add_completion=False, help="Benign suite (FPR denominator).")
app.add_typer(benign, name="benign")


@benign.command("status")
def benign_status(
    benign_path: Annotated[str, typer.Option("--journal")] = "var/redteam/benign.jsonl",
    model: Annotated[str, typer.Option()] = DEFAULT_MODEL,
) -> None:
    """Show benign-suite progress without spending anything."""
    from warden.redteam.benign import SCENARIOS
    from warden.redteam.benign_journal import BenignJournal

    journal = BenignJournal(Path(benign_path))
    done = journal.done_scenarios(model, source_hash())
    typer.echo(f"model {model}  ·  source hash {source_hash()}")
    typer.echo(f"benign suite: {len(done)}/{len(SCENARIOS)} recorded under current code")
    for scenario in SCENARIOS:
        mark = "done" if scenario.scenario_id in done else "    "
        typer.echo(f"  [{mark}] {scenario.scenario_id:<28} {scenario.stratum.value}")
    remaining = [s for s in SCENARIOS if s.scenario_id not in done]
    typer.echo(f"\n{len(remaining)} scenario(s) remaining")


@benign.command("run")
def benign_run(
    benign_path: Annotated[str, typer.Option("--journal")] = "var/redteam/benign.jsonl",
    var_dir: Annotated[str, typer.Option("--var")] = "var/benign",
    model: Annotated[str, typer.Option()] = DEFAULT_MODEL,
) -> None:
    """Run outstanding benign scenarios through the governed gateway and record results.

    Resumable and quota-safe: skips scenarios already recorded, stops cleanly when the
    daily model quota is hit, and leaves the interrupted scenario for next time.
    """
    import asyncio
    import os
    import time

    from dotenv import load_dotenv

    from warden.demo_agent.agent import SYSTEM
    from warden.demo_agent.gemini import gemini_model
    from warden.gateway.config import credential_env_vars
    from warden.redteam.benign_journal import BenignJournal
    from warden.redteam.benign_runner import run_suite

    load_dotenv()
    absent = [n for n in credential_env_vars() if not os.environ.get(n)]
    if absent:
        parser_absent = ", ".join(absent)
        typer.echo(f"error: credentials not set: {parser_absent}")
        raise typer.Exit(code=2)
    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        typer.echo("error: GEMINI_API_KEY not set")
        raise typer.Exit(code=2)

    from google import genai

    client = genai.Client()

    def make_model() -> object:
        return gemini_model(client, SYSTEM, model)

    def now_us() -> int:
        return time.time_ns() // 1_000

    journal = BenignJournal(Path(benign_path))
    recorded = asyncio.run(
        run_suite(
            journal=journal, var_dir=Path(var_dir),
            make_model=make_model, model=model, now_us=now_us,
        )
    )
    for record in recorded:
        flag = "  DEVIATION" if record.is_deviation else ""
        typer.echo(
            f"  {record.scenario_id:<28} {record.observed.value:<11} "
            f"(expected {record.expected.value}){flag}"
        )
    done = journal.done_scenarios(model, source_hash())
    typer.echo(f"\nthis run recorded {len(recorded)} scenario(s); "
               f"{len(done)}/15 recorded under current code.")

DEFAULT_DB = "var/warden.db"
DEFAULT_POLICY = "policies/demo.yaml"
DEFAULT_JOURNAL = "var/redteam/calibration.jsonl"
DEFAULT_BENIGN_JOURNAL = "var/redteam/benign.jsonl"
DEFAULT_REPORT = "docs/RESULTS.md"
HASH_PREFIX_LEN = 12


@app.command()
def report(
    journal_path: Annotated[str, typer.Option("--journal")] = DEFAULT_JOURNAL,
    benign_path: Annotated[str, typer.Option("--benign")] = DEFAULT_BENIGN_JOURNAL,
    out: Annotated[str, typer.Option("--out")] = DEFAULT_REPORT,
    model: Annotated[str, typer.Option()] = DEFAULT_MODEL,
) -> None:
    """Render the two measured tables from the calibration record to markdown."""
    from warden.report.generate import write_report

    text = write_report(Path(journal_path), Path(benign_path), Path(out), model=model)
    typer.echo(text)
    typer.echo("")
    typer.echo(f"written to {out}")


def _latest_run(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT run_id FROM runs ORDER BY started_at_us DESC LIMIT 1"
    ).fetchone()
    return None if row is None else str(row[0])


@app.callback()
def root() -> None:
    """Warden: a governed MCP gateway."""


@app.command()
def calls(
    run: Annotated[str | None, typer.Option(help="Run id. Defaults to the latest run.")] = None,
    db: Annotated[str, typer.Option(help="Database path.")] = DEFAULT_DB,
) -> None:
    """Print the call log for a run."""
    conn = open_db(db)
    run_id = run or _latest_run(conn)
    if run_id is None:
        typer.echo("no runs recorded")
        raise typer.Exit(code=1)

    header = conn.execute(
        "SELECT mode, variant, agent_id, policy_hash FROM runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if header is None:
        typer.echo(f"no such run: {run_id}")
        raise typer.Exit(code=1)

    typer.echo(
        f"run {run_id}  mode={header[0]}  variant={header[1]}  "
        f"agent={header[2]}  policy={header[3]}"
    )
    rows = conn.execute(
        "SELECT tool, args_hash, policy_outcome, rule_id, execution_outcome, "
        "latency_ms, matched_taint FROM call_log WHERE run_id = ? ORDER BY ts_us",
        (run_id,),
    ).fetchall()
    if not rows:
        typer.echo("  (no calls)")
        raise typer.Exit()

    fmt = "  {:<16} {:<14} {:<9} {:<20} {:<7} {:>7}  {}"
    typer.echo(
        fmt.format("TOOL", "ARGS_HASH", "POLICY", "RULE_ID", "EXEC", "MS", "MATCHED_TAINT")
    )
    for tool, args_hash, outcome, rule_id, execution, latency, taint in rows:
        digest = args_hash.split(":", 1)[-1][:HASH_PREFIX_LEN]
        typer.echo(
            fmt.format(
                tool, digest, outcome, rule_id, execution,
                "-" if latency is None else latency, taint,
            )
        )
    typer.echo(f"  {len(rows)} call(s)")


@redteam.command()
def calibrate(
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Run preflight invariants and exit.")
    ] = False,
    status: Annotated[
        bool, typer.Option("--status", help="Print calibration progress and exit.")
    ] = False,
    journal_path: Annotated[str, typer.Option("--journal")] = DEFAULT_JOURNAL,
    model: Annotated[str, typer.Option(help="Model the rates apply to.")] = DEFAULT_MODEL,
    policy: Annotated[str, typer.Option(help="Policy file.")] = DEFAULT_POLICY,
) -> None:
    """Calibrate red-team templates against the ungoverned agent.

    --dry-run spends nothing: it runs every free, model-free invariant for every
    template so a broken one is reported before any quota is committed.
    """
    journal = Journal(Path(journal_path))
    current = source_hash()

    if status:
        plan = Plan(
            templates=tuple(sorted(set(BY_SCENARIO) | set(ARG_SCENARIO))),
            runs_per_template=RUNS_PER_TEMPLATE,
            model=model,
        )
        items = outstanding(plan, journal, source_hash=current)
        typer.echo(
            f"model {model}   n={RUNS_PER_TEMPLATE} per template   hash {current}"
        )
        typer.echo(f"journal {journal_path}")
        typer.echo("")
        for item in items:
            tally = journal.tally(item.template, model, current)
            note = f"  ({tally.errors} errored, retried)" if tally.errors else ""
            typer.echo(
                f"  {item.template:<28} {tally.fraction:>7} under current hash   "
                f"{item.remaining} run(s) remaining{note}"
            )
        needed = requests_needed(items, REQUESTS_PER_RUN)
        days = -(-needed // DAILY_REQUEST_BUDGET) if needed else 0
        typer.echo("")
        typer.echo(
            f"~{needed} request(s) remaining at ~{REQUESTS_PER_RUN}/run; "
            f"{DAILY_REQUEST_BUDGET}/day budget -> ~{days} more day(s)"
        )
        raise typer.Exit()

    # Both --dry-run and a live run gate on the same preflight: a template must pass its
    # free, model-free invariants before any quota is spent on it.
    reports = preflight(policy_path=policy)
    failed = 0
    for report in reports:
        verdict = "PASS" if report.passed else "FAIL"
        typer.echo("")
        typer.echo(f"{report.scenario_id}  [{verdict}]")
        for check in report.checks:
            mark = "  ok  " if check.passed else " FAIL "
            typer.echo(f"  {mark} {check.name:<28} {check.detail}")
        failed += 0 if report.passed else 1

    conflicts = journal.hash_conflicts(current)
    typer.echo("")
    typer.echo(f"source hash: {current}")
    if conflicts:
        for template, hashes in sorted(conflicts.items()):
            typer.echo(
                f"  STALE  {template}: recorded under {sorted(hashes)}, "
                f"not the current {current}"
            )

    if dry_run:
        typer.echo("")
        typer.echo(
            f"{len(reports) - failed}/{len(reports)} template(s) ready. "
            f"0 model requests spent."
        )
        if failed:
            typer.echo(f"{failed} template(s) would be skipped by calibration.")
        if conflicts:
            typer.echo(
                f"{len(conflicts)} template(s) have calibration recorded under a "
                f"different source hash; re-run them before trusting their rate."
            )
        if failed or conflicts:
            raise typer.Exit(code=1)
        raise typer.Exit()

    # -- live run: spends quota --------------------------------------------------
    # Conflicts are expected here (they are exactly what a re-run resolves), so we do not
    # refuse on them -- only on a preflight failure, which would spend quota on a broken
    # template.
    if failed:
        typer.echo("")
        typer.echo(f"refusing to spend quota: {failed} template(s) fail preflight.")
        raise typer.Exit(code=1)

    import asyncio
    import os
    import time

    from dotenv import load_dotenv

    from warden.demo_agent.agent import SYSTEM
    from warden.demo_agent.gemini import gemini_model
    from warden.gateway.config import credential_env_vars
    from warden.redteam.attack_runner import ATTACK_VAR_DIR, run_suite

    load_dotenv()
    absent = [n for n in credential_env_vars() if not os.environ.get(n)]
    if absent:
        typer.echo(f"error: credentials not set: {', '.join(absent)}")
        raise typer.Exit(code=2)
    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        typer.echo("error: GEMINI_API_KEY not set")
        raise typer.Exit(code=2)

    from google import genai

    client = genai.Client()

    def make_model() -> object:
        return gemini_model(client, SYSTEM, model)

    def now_us() -> int:
        return time.time_ns() // 1_000

    recorded = asyncio.run(
        run_suite(
            journal=journal, var_dir=Path(ATTACK_VAR_DIR),
            make_model=make_model, model=model, now_us=now_us, policy_path=policy,
        )
    )
    typer.echo("")
    for attempt in recorded:
        typer.echo(f"  {attempt.template:<28} {attempt.outcome.value}")
    typer.echo(f"\nthis run recorded {len(recorded)} attempt(s) under {current}.")


if __name__ == "__main__":
    app()
