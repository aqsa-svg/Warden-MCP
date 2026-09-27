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
    if status:
        journal = Journal(Path(journal_path))
        plan = Plan(
            templates=tuple(sorted(set(BY_SCENARIO) | set(ARG_SCENARIO))),
            runs_per_template=RUNS_PER_TEMPLATE,
            model=model,
        )
        items = outstanding(plan, journal)
        typer.echo(f"model {model}   n={RUNS_PER_TEMPLATE} per template")
        typer.echo(f"journal {journal_path}")
        typer.echo("")
        for item in items:
            tally = journal.tally(item.template, model)
            note = f"  ({tally.errors} errored, retried)" if tally.errors else ""
            typer.echo(
                f"  {item.template:<28} {tally.fraction:>7} succeeded   "
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

    if not dry_run:
        typer.echo(
            "calibration is not wired yet; --dry-run runs the preflight invariants"
        )
        raise typer.Exit(code=2)

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

    # Source provenance: every recorded attempt for a template must share the source
    # hash. A mismatch means some run executed against different code, so its rate is
    # not comparable -- surface it before any quota is spent on top of it.
    current = source_hash()
    conflicts = Journal(Path(journal_path)).hash_conflicts(current)
    typer.echo("")
    typer.echo(f"source hash: {current}")
    if conflicts:
        for template, hashes in sorted(conflicts.items()):
            typer.echo(
                f"  STALE  {template}: recorded under {sorted(hashes)}, "
                f"not the current {current}"
            )

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


if __name__ == "__main__":
    app()
