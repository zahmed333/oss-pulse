"""End-to-end: synthetic raw files -> bronze -> dbt build -> gold assertions.

Runs fully offline in ~15s and is what CI executes on every push."""

from datetime import UTC, datetime, timedelta

import duckdb
import pytest

from oss_pulse.ingest import gharchive, pypi, synthetic
from oss_pulse.transform import run_dbt

END = datetime(2026, 3, 10, tzinfo=UTC)
START = END - timedelta(days=9)


@pytest.fixture(scope="module")
def warehouse(tmp_path_factory):
    from oss_pulse.config import PROJECT_ROOT, Settings

    s = Settings(
        data_dir=tmp_path_factory.mktemp("e2e") / "data",
        projects_file=PROJECT_ROOT / "tracked_projects.yml",
    )
    synthetic.generate_gharchive(s, START, END, seed=7)
    synthetic.generate_pypi(s, END, seed=7)
    for hour in gharchive.hour_range(START, END):
        gharchive.ingest_local_hour(s, hour)
    pypi.write_reference(s)
    pypi.ingest_pypi(s, snapshot=END.date())
    assert run_dbt(s, ["build"]), "dbt build failed"
    return s


def q(s, sql):
    # dbt-duckdb keeps an in-process read-write handle open; match its configuration
    con = duckdb.connect(str(s.warehouse_path))
    try:
        return con.sql(sql).fetchall()
    finally:
        con.close()


def test_health_mart_is_dense(warehouse):
    n_repos = len(warehouse.tracked_projects())
    [(rows, days)] = q(
        warehouse, "select count(*), count(distinct as_of_date) from main_marts.mart_repo_health"
    )
    assert days == 9
    assert rows == n_repos * days


def test_reconciliation_is_clean(warehouse):
    [(bad,)] = q(
        warehouse,
        "select count(*) from main_audit.audit_ingestion_reconciliation where row_count_diff <> 0",
    )
    assert bad == 0


def test_only_tracked_repos_reach_silver(warehouse):
    [(n,)] = q(
        warehouse, "select count(*) from main_marts.fct_github_events where repo_key like 'noise%'"
    )
    assert n == 0


def test_incremental_rerun_after_reingest_is_stable(warehouse):
    before = q(
        warehouse, "select count(*), count(distinct event_id) from main_marts.fct_github_events"
    )
    gharchive.ingest_local_hour(warehouse, END - timedelta(hours=1))  # re-land the last hour
    assert run_dbt(warehouse, ["build", "--select", "fct_github_events+"])
    after = q(
        warehouse, "select count(*), count(distinct event_id) from main_marts.fct_github_events"
    )
    assert before == after
    assert after[0][0] == after[0][1], "incremental load produced duplicates"
