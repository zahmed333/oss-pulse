"""`oss-pulse` command line. Every pipeline step is runnable on its own (for debugging
and backfills) and composable (`demo` runs the whole thing end to end)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb
import typer

from oss_pulse.config import get_settings
from oss_pulse.ingest import gharchive, pypi, synthetic
from oss_pulse.transform import run_dbt

app = typer.Typer(help="OSS Pulse: open-source ecosystem health lakehouse.", no_args_is_help=True)
ingest_app = typer.Typer(help="Land source data in the bronze layer.", no_args_is_help=True)
app.add_typer(ingest_app, name="ingest")


def _hour(value: str) -> datetime:
    """Accepts 2024-01-01, 2024-01-01T05 or full ISO timestamps (UTC)."""
    if len(value) == 13:  # YYYY-MM-DDTHH
        value += ":00"
    return gharchive.floor_hour(datetime.fromisoformat(value))


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    )


@ingest_app.command("gharchive")
def ingest_gharchive(
    start: str = typer.Option(..., help="First hour (UTC), e.g. 2024-06-01T00"),
    end: str = typer.Option(..., help="Exclusive end hour (UTC)"),
    local: bool = typer.Option(False, help="Only use files already in the raw zone"),
) -> None:
    """Ingest GH Archive hours in [start, end) into bronze Parquet partitions."""
    settings = get_settings()
    hours = gharchive.hour_range(_hour(start), _hour(end))
    totals = {"written": 0, "rejected": 0, "duplicate": 0}
    for hour in hours:
        res = (gharchive.ingest_local_hour if local else gharchive.ingest_hour)(settings, hour)
        totals["written"] += res.rows_written
        totals["rejected"] += res.rows_rejected
        totals["duplicate"] += res.rows_duplicate
    typer.echo(f"ingested {len(hours)} hour(s): {totals}")


@ingest_app.command("pypi")
def ingest_pypi() -> None:
    """Snapshot PyPI release history for all tracked packages."""
    typer.echo(f"wrote {pypi.ingest_pypi(get_settings())}")


@ingest_app.command("reference")
def ingest_reference() -> None:
    """Publish tracked_projects.yml as a bronze reference table."""
    typer.echo(f"wrote {pypi.write_reference(get_settings())}")


@app.command("synthetic")
def make_synthetic(
    start: str = typer.Option(...), end: str = typer.Option(...), seed: int = 42
) -> None:
    """Generate GH Archive/PyPI-format files in the raw zone (offline mode)."""
    settings = get_settings()
    files = synthetic.generate_gharchive(settings, _hour(start), _hour(end), seed=seed)
    synthetic.generate_pypi(settings, _hour(end), seed=seed)
    typer.echo(f"generated {len(files)} archive file(s) in {settings.raw_dir}")


@app.command("transform")
def transform(
    select: str = typer.Option(None, help="dbt selector"),
    full_refresh: bool = typer.Option(False, "--full-refresh"),
) -> None:
    """Run `dbt build` (models + tests) against the DuckDB warehouse."""
    args = ["build"]
    if select:
        args += ["--select", select]
    if full_refresh:
        args.append("--full-refresh")
    if not run_dbt(get_settings(), args):
        raise typer.Exit(code=1)


@app.command("report")
def report(limit: int = 15) -> None:
    """Print the latest repo health leaderboard from the gold layer."""
    settings = get_settings()
    # not read_only: in `demo`, dbt-duckdb still holds an in-process read-write handle
    con = duckdb.connect(str(settings.warehouse_path))
    con.sql(
        f"""
        select repo_name, as_of_date, health_score, stars_in_window, prs_merged_in_window,
               median_hours_to_merge, median_hours_to_first_response, bus_factor,
               days_since_last_release
        from main_marts.mart_repo_health
        where as_of_date = (select max(as_of_date) from main_marts.mart_repo_health)
        order by health_score desc
        limit {int(limit)}
        """
    ).show(max_width=200)


@app.command("check")
def check(
    dependency_file: Path = typer.Argument(
        Path("pyproject.toml"),
        exists=True,
        dir_okay=False,
        help="pyproject.toml or requirements.txt",
    ),
    days: int = typer.Option(90, help="Activity window in days"),
    fail_on: str = typer.Option(
        "never", help="Exit 1 if any dependency is at/above: critical | high | medium | never"
    ),
    internal: list[str] = typer.Option(
        [], "--internal", help="Private package name to guard against dependency confusion"
    ),
    scan_artifacts: bool = typer.Option(True, help="Scan release sdists/wheels for malware"),
    strict: bool = typer.Option(False, help="Fail if any data source could not be checked"),
    markdown: Path = typer.Option(None, help="Also write the Markdown report here"),
    json_out: Path = typer.Option(None, "--json", help="Also write the JSON report here"),
    include_optional: bool = typer.Option(True, help="Include extras and dependency groups"),
    data_dir: Path = typer.Option(Path(".oss-pulse"), help="Local lakehouse for this check"),
) -> None:
    """Assess supply-chain risk of your project's dependencies."""
    from oss_pulse.check import SEVERITY, render_json, render_markdown, run_check

    _validate_fail_on(fail_on)
    result = run_check(
        dependency_file,
        data_dir.resolve(),
        days=days,
        include_optional=include_optional,
        internal=internal,
        scan_artifacts=scan_artifacts,
    )
    md = render_markdown(result)
    typer.echo(md)
    if markdown:
        markdown.write_text(md)
    if json_out:
        json_out.write_text(render_json(result))
    if strict and result.degraded:
        typer.echo("failing (--strict): some signals could not be collected", err=True)
        raise typer.Exit(code=2)
    if fail_on != "never" and result.worst() >= SEVERITY[fail_on]:
        typer.echo(f"failing: at least one dependency is at or above '{fail_on}' risk", err=True)
        raise typer.Exit(code=1)


@app.command("scan")
def scan(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        file_okay=False,
        help="Repository or folder to inspect (nothing is executed)",
    ),
    fail_on: str = typer.Option("never", help="critical | high | medium | never"),
    ignore_file: Path = typer.Option(
        None,
        exists=True,
        dir_okay=False,
        help="Your own list of reviewed paths or rule ids to suppress. A file inside the "
        "scanned folder is never applied unless you pass it here.",
    ),
    markdown: Path = typer.Option(None, help="Also write the Markdown report here"),
    json_out: Path = typer.Option(None, "--json", help="Also write the JSON report here"),
) -> None:
    """Inspect an untrusted repository BEFORE opening or installing it.

    Catches auto-run VS Code tasks, npm install hooks, malicious setup.py/.pth files,
    obfuscated or hidden payloads, credential/wallet stealers, exfiltration endpoints,
    typosquatted dependencies and unsafe GitHub Actions workflows.
    """
    from oss_pulse.scan import render_scan_json, render_scan_markdown, run_scan
    from oss_pulse.supplychain.findings import SEVERITY_RANK

    _validate_fail_on(fail_on)
    result = run_scan(path, ignore_file=ignore_file)
    md = render_scan_markdown(result)
    typer.echo(md)
    if markdown:
        markdown.write_text(md)
    if json_out:
        json_out.write_text(render_scan_json(result))
    if fail_on != "never" and any(
        SEVERITY_RANK[f.severity] >= SEVERITY_RANK[fail_on] for f in result.findings
    ):
        typer.echo(f"failing: findings at or above '{fail_on}'", err=True)
        raise typer.Exit(code=1)


@app.command("rules")
def rules() -> None:
    """List every detection rule, why it matters and which real attack used it."""
    from oss_pulse.supplychain.rules import RULES

    for r in RULES.values():
        typer.echo(f"{r.id:<20} {r.severity:<9} {r.category:<20} {r.title}")
        typer.echo(f"{'':<20} {r.why}")
        if r.seen_in:
            typer.echo(f"{'':<20} seen in: {r.seen_in}")
        typer.echo("")


def _validate_fail_on(value: str) -> None:
    if value not in {"critical", "high", "medium", "never"}:
        raise typer.BadParameter("--fail-on must be one of: critical, high, medium, never")


@app.command("demo")
def demo(days: int = 3, seed: int = 42) -> None:
    """Offline end-to-end run: synthetic data -> bronze -> dbt build -> report."""
    settings = get_settings()
    end = gharchive.floor_hour(datetime.now(UTC)).replace(hour=0)
    start = end - timedelta(days=days)
    synthetic.generate_gharchive(settings, start, end, seed=seed)
    synthetic.generate_pypi(settings, end, seed=seed)
    for hour in gharchive.hour_range(start, end):
        gharchive.ingest_local_hour(settings, hour)
    pypi.write_reference(settings)
    pypi.ingest_pypi(settings, snapshot=end.date())
    if not run_dbt(settings, ["build"]):
        raise typer.Exit(code=1)
    report()


if __name__ == "__main__":
    app()
