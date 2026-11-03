"""Thin wrapper around dbt's programmatic runner so the CLI, tests and the orchestrator
all invoke dbt the same way (same project dir, profiles dir and data-dir env var)."""

from __future__ import annotations

import os

from oss_pulse.config import Settings


def dbt_env(settings: Settings) -> None:
    os.environ["OSS_PULSE_DATA_DIR"] = str(settings.data_dir.resolve())
    settings.data_dir.mkdir(parents=True, exist_ok=True)


def run_dbt(settings: Settings, args: list[str]) -> bool:
    from dbt.cli.main import dbtRunner

    dbt_env(settings)
    project = str(settings.dbt_project_dir)
    result = dbtRunner().invoke([*args, "--project-dir", project, "--profiles-dir", project])
    return bool(result.success)
