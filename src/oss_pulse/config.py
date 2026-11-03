"""Central configuration. Everything is overridable via environment variables so the
same code runs locally, in CI, and in a container without edits."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class TrackedProject:
    repo: str  # "owner/name" on GitHub
    pypi: str | None = None


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(
        default_factory=lambda: Path(os.getenv("OSS_PULSE_DATA_DIR", PROJECT_ROOT / "data"))
    )
    gharchive_base_url: str = field(
        default_factory=lambda: os.getenv("OSS_PULSE_GHARCHIVE_URL", "https://data.gharchive.org")
    )
    pypi_base_url: str = field(
        default_factory=lambda: os.getenv("OSS_PULSE_PYPI_URL", "https://pypi.org/pypi")
    )
    projects_file: Path = field(
        default_factory=lambda: Path(
            os.getenv("OSS_PULSE_PROJECTS_FILE", PROJECT_ROOT / "tracked_projects.yml")
        )
    )
    dbt_project_dir: Path = PROJECT_ROOT / "transform"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def bronze_dir(self) -> Path:
        return self.data_dir / "bronze"

    @property
    def warehouse_path(self) -> Path:
        return self.data_dir / "warehouse.duckdb"

    def tracked_projects(self) -> list[TrackedProject]:
        with open(self.projects_file) as fh:
            doc = yaml.safe_load(fh)
        return [TrackedProject(repo=p["repo"], pypi=p.get("pypi")) for p in doc["projects"]]


def get_settings() -> Settings:
    return Settings()
