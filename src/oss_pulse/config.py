"""Central configuration. Everything is overridable via environment variables so the
same code runs locally, in CI, and in a container without edits."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from oss_pulse import endpoints

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parents[1]


def _shipped(in_package: str, in_checkout: str) -> Path:
    """Files the wheel carries inside the package; a source checkout keeps them at the root."""
    packaged = PACKAGE_DIR / in_package
    return packaged if packaged.exists() else PROJECT_ROOT / in_checkout


@dataclass(frozen=True)
class TrackedProject:
    repo: str
    pypi: str | None = None


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(
        default_factory=lambda: Path(os.getenv("OSS_PULSE_DATA_DIR", PROJECT_ROOT / "data"))
    )
    gharchive_base_url: str = field(
        default_factory=lambda: os.getenv("OSS_PULSE_GHARCHIVE_URL", "https://data.gharchive.org")
    )
    pypi_base_url: str = field(default_factory=lambda: endpoints.url("pypi"))
    projects_file: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "OSS_PULSE_PROJECTS_FILE", _shipped("tracked_projects.yml", "tracked_projects.yml")
            )
        )
    )
    dbt_project_dir: Path = field(default_factory=lambda: _shipped("dbt_project", "transform"))

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def bronze_dir(self) -> Path:
        return self.data_dir / "bronze"

    @property
    def warehouse_path(self) -> Path:
        return self.data_dir / "warehouse.duckdb"

    @property
    def dbt_work_dir(self) -> Path:
        """dbt's target/ and logs/. Never inside the dbt project: an installed package may be
        read-only, and the CLI, the tests and Dagster must all find the same manifest."""
        return self.data_dir / "dbt"

    def tracked_projects(self) -> list[TrackedProject]:
        with open(self.projects_file) as fh:
            doc = yaml.safe_load(fh)
        return [TrackedProject(repo=p["repo"], pypi=p.get("pypi")) for p in doc["projects"]]


def get_settings() -> Settings:
    return Settings()
