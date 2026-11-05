"""Commands for the GH Archive ecosystem-health lakehouse. Not needed for scan or check."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import duckdb
import typer

from oss_pulse.config import get_settings
from oss_pulse.ingest import gharchive, pypi, synthetic
from oss_pulse.transform import run_dbt

lakehouse = typer.Typer()
ingest_app = typer.Typer(help="Land source data in the bronze layer.", no_args_is_help=True)
lakehouse.add_typer(ingest_app, name="ingest")


def _hour(value: str) -> datetime:
    """Accepts 2024-01-01, 2024-01-01T05 or full ISO timestamps (UTC)."""
    if len(value) == 13:  # YYYY-MM-DDTHH
        value += ":00"
    return gharchive.floor_hour(datetime.fromisoformat(value))


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


@lakehouse.command("synthetic")
def make_synthetic(
    start: str = typer.Option(...), end: str = typer.Option(...), seed: int = 42
) -> None:
    """Generate GH Archive/PyPI-format files in the raw zone (offline mode)."""
    settings = get_settings()
    files = synthetic.generate_gharchive(settings, _hour(start), _hour(end), seed=seed)
    synthetic.generate_pypi(settings, _hour(end), seed=seed)
    typer.echo(f"generated {len(files)} archive file(s) in {settings.raw_dir}")


@lakehouse.command("transform")
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


@lakehouse.command("report")
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


@lakehouse.command("demo")
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
