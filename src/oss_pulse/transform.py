"""Thin wrapper around dbt's programmatic runner so the CLI, tests and the orchestrator
all invoke dbt the same way (same project dir, profiles dir and data-dir env var).

dbt's build output and logs go under the data directory, never into the project
directory: an installed package may be read-only, and `check` must not leave
files behind in site-packages. Anonymous usage stats are off; see docs/PRIVACY.md."""

from __future__ import annotations

import os

from oss_pulse.config import Settings


def dbt_env(settings: Settings) -> None:
    os.environ["OSS_PULSE_DATA_DIR"] = str(settings.data_dir.resolve())
    settings.data_dir.mkdir(parents=True, exist_ok=True)


def run_dbt(settings: Settings, args: list[str], quiet: bool = False) -> bool:
    from dbt.cli.main import dbtRunner

    from oss_pulse.ingest.layout import ensure_bronze_layout

    dbt_env(settings)
    ensure_bronze_layout(settings)
    project = str(settings.dbt_project_dir)
    work = settings.dbt_work_dir
    flags = ["--quiet"] if quiet else []
    result = dbtRunner().invoke(
        [
            *flags,
            "--no-send-anonymous-usage-stats",
            "--log-path",
            str(work / "logs"),
            *args,
            "--project-dir",
            project,
            "--profiles-dir",
            project,
            "--target-path",
            str(work / "target"),
        ]
    )
    return bool(result.success)
