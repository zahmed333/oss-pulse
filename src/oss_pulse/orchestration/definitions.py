"""Dagster definitions: the lakehouse as software-defined assets.

    gharchive_bronze (hourly partitions) ─┐
    pypi_bronze (daily)                   ├─► dbt models (staging → marts) ─► asset checks
    tracked_projects_reference            ┘

* Hourly partitions map 1:1 to GH Archive files, so backfills are just
  "materialize partitions X..Y" in the UI - and each one is idempotent.
* dbt models appear as individual assets with lineage, and dbt tests become
  Dagster asset checks.
* `OSS_PULSE_SOURCE=synthetic` runs the whole graph offline.

Run locally:  dagster dev   (then open http://localhost:3000)

Note: no `from __future__ import annotations` here - Dagster inspects the
runtime type of the `context` annotation.
"""

import os
from datetime import UTC, datetime, timedelta

from dagster import (
    AssetExecutionContext,
    AssetKey,
    AutomationCondition,
    DailyPartitionsDefinition,
    Definitions,
    HourlyPartitionsDefinition,
    MaterializeResult,
    MetadataValue,
    RetryPolicy,
    asset,
    build_schedule_from_partitioned_job,
    define_asset_job,
)
from dagster_dbt import DagsterDbtTranslator, DbtCliResource, DbtProject, dbt_assets

from oss_pulse.config import get_settings
from oss_pulse.ingest import gharchive, pypi, synthetic
from oss_pulse.transform import dbt_env

settings = get_settings()
dbt_env(settings)
SOURCE = os.getenv("OSS_PULSE_SOURCE", "gharchive")  # or "synthetic"

hourly = HourlyPartitionsDefinition(start_date=os.getenv("OSS_PULSE_START", "2026-10-01-00:00"))
daily = DailyPartitionsDefinition(start_date=os.getenv("OSS_PULSE_START_DAY", "2026-10-01"))


@asset(
    key=AssetKey(["bronze", "gharchive_events"]),
    partitions_def=hourly,
    group_name="bronze",
    compute_kind="python",
    retry_policy=RetryPolicy(max_retries=3, delay=60),
    description="One GH Archive hour -> one bronze Parquet partition (idempotent).",
)
def gharchive_bronze(context: AssetExecutionContext) -> MaterializeResult:
    hour = datetime.strptime(context.partition_key, "%Y-%m-%d-%H:%M").replace(tzinfo=UTC)
    if SOURCE == "synthetic":
        synthetic.generate_gharchive(settings, hour, hour + timedelta(hours=1), seed=hour.day)
        path = settings.raw_dir / "gharchive" / gharchive.archive_filename(hour)
        res = gharchive.ingest_file(settings, hour, path)
    else:
        res = gharchive.ingest_hour(settings, hour)
    return MaterializeResult(
        metadata={
            "rows_written": res.rows_written,
            "rows_rejected": res.rows_rejected,
            "rows_duplicate": res.rows_duplicate,
            "reject_rate": res.rows_rejected / max(res.rows_read, 1),
            "partition_path": MetadataValue.path(res.partition_path),
        }
    )


@asset(
    key=AssetKey(["bronze", "pypi_releases"]),
    partitions_def=daily,
    group_name="bronze",
    compute_kind="python",
    description="Daily snapshot of PyPI release history for tracked packages.",
)
def pypi_bronze(context: AssetExecutionContext) -> MaterializeResult:
    day = datetime.strptime(context.partition_key, "%Y-%m-%d").replace(tzinfo=UTC)
    if SOURCE == "synthetic":
        synthetic.generate_pypi(settings, day)
    path = pypi.ingest_pypi(settings, snapshot=day.date())
    return MaterializeResult(metadata={"path": MetadataValue.path(str(path))})


@asset(
    key=AssetKey(["bronze", "tracked_projects"]),
    group_name="bronze",
    compute_kind="python",
    description="tracked_projects.yml published as a reference table.",
)
def tracked_projects_reference() -> MaterializeResult:
    return MaterializeResult(
        metadata={"path": MetadataValue.path(str(pypi.write_reference(settings)))}
    )


# ----------------------------------------------------------------------------- dbt

# The manifest lives where `oss-pulse transform` / `demo` write it (Settings.dbt_work_dir),
# not in transform/target, so the CLI and Dagster share one build and nothing is written
# into the project directory.
dbt_project = DbtProject(
    project_dir=settings.dbt_project_dir,
    profiles_dir=settings.dbt_project_dir,
    target_path=settings.dbt_work_dir / "target",
)
dbt_project.prepare_if_dev()


class Translator(DagsterDbtTranslator):
    def get_asset_key(self, dbt_resource_props):  # map dbt sources onto our bronze assets
        if dbt_resource_props["resource_type"] == "source":
            return AssetKey(["bronze", dbt_resource_props["name"]])
        return super().get_asset_key(dbt_resource_props)

    def get_group_name(self, dbt_resource_props):
        fqn = dbt_resource_props.get("fqn", [])
        return fqn[1] if len(fqn) > 2 else "dbt"

    def get_automation_condition(self, dbt_resource_props):
        return AutomationCondition.eager()


@dbt_assets(manifest=dbt_project.manifest_path, dagster_dbt_translator=Translator())
def lakehouse_dbt(context: AssetExecutionContext, dbt: DbtCliResource):
    # One target dir per run, under the data dir like every other dbt invocation.
    target = settings.dbt_work_dir / "dagster" / context.run_id[:8]
    yield from dbt.cli(["build"], context=context, target_path=target).stream()


ingest_hourly = define_asset_job(
    "ingest_gharchive_hourly",
    selection=[AssetKey(["bronze", "gharchive_events"])],
    partitions_def=hourly,
)

defs = Definitions(
    assets=[gharchive_bronze, pypi_bronze, tracked_projects_reference, lakehouse_dbt],
    jobs=[ingest_hourly],
    schedules=[
        # GH Archive publishes an hour shortly after it closes; run 15 min past each hour.
        build_schedule_from_partitioned_job(ingest_hourly, minute_of_hour=15),
    ],
    resources={"dbt": DbtCliResource(project_dir=dbt_project)},
)
