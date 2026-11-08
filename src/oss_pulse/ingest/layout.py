"""Guarantee every bronze source dbt reads exists, even when a source is unused.

The two ingestion paths are independent: an ecosystem run has no GitHub API snapshots,
and a dependency check has no GH Archive hours. DuckDB errors on a glob that matches
nothing, so we write zero-row files *with the real schema* for absent sources. Zero rows
means zero effect on any model, and the column types stay correct.
"""

from __future__ import annotations

from pathlib import Path

import pyarrow as pa

from oss_pulse.config import Settings
from oss_pulse.ingest.io import atomic_write_json, atomic_write_table
from oss_pulse.ingest.schema import (
    DEPENDENCIES,
    GHARCHIVE_EVENTS,
    GITHUB_REPOS,
    OSV_VULNERABILITIES,
    PYPI_RELEASES,
    SCORECARD_CHECKS,
    TRACKED_PROJECTS,
)

PLACEHOLDER = "_placeholder"


def _has_files(root: Path, pattern: str) -> bool:
    return root.exists() and any(root.glob(pattern))


def ensure_bronze_layout(settings: Settings) -> None:
    b = settings.bronze_dir
    empty = [  # (source root, placeholder partition, schema)
        ("gharchive", "event_date=1970-01-01/event_hour=00", GHARCHIVE_EVENTS),
        ("github_api", f"snapshot_date=1970-01-01/repo={PLACEHOLDER}", GHARCHIVE_EVENTS),
        ("github_repos", f"snapshot_date=1970-01-01/repo={PLACEHOLDER}", GITHUB_REPOS),
        ("pypi_releases", "snapshot_date=1970-01-01", PYPI_RELEASES),
        ("osv", "snapshot_date=1970-01-01", OSV_VULNERABILITIES),
        ("scorecard", "snapshot_date=1970-01-01", SCORECARD_CHECKS),
    ]
    for source, partition, schema in empty:
        if not _has_files(b / source, "**/*.parquet"):
            atomic_write_table(
                schema.empty_table(), b / source / partition / f"{PLACEHOLDER}.parquet"
            )

    from oss_pulse.supplychain.findings_store import FINDINGS

    if not _has_files(b / "findings", "**/*.parquet"):
        atomic_write_table(
            FINDINGS.empty_table(),
            b
            / "findings"
            / f"detector={PLACEHOLDER}"
            / "snapshot_date=1970-01-01"
            / f"{PLACEHOLDER}.parquet",
        )

    manifests = b / "_manifests" / "gharchive"
    if not _has_files(manifests, "**/manifest.json"):
        atomic_write_json(
            {
                "source_file": PLACEHOLDER,
                "rows_read": 0,
                "rows_written": 0,
                "rows_rejected": 0,
                "rows_duplicate": 0,
                "ingested_at": "1970-01-01T00:00:00+00:00",
            },
            manifests / "event_date=1970-01-01/event_hour=00/manifest.json",
        )
    for name, schema in {
        "tracked_projects": TRACKED_PROJECTS,
        "dependencies": DEPENDENCIES,
    }.items():
        path = b / "reference" / f"{name}.parquet"
        if not path.exists():
            atomic_write_table(pa.Table.from_pylist([], schema=schema), path)
