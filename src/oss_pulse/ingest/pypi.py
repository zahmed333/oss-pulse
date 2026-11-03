"""PyPI release history via the public JSON API (https://pypi.org/pypi/<pkg>/json).

Snapshot semantics: each run fully replaces `bronze/pypi_releases/snapshot_date=<d>/`.
Keeping dated snapshots (instead of overwriting one file) gives us free history of
yanks and late uploads, and makes backfills trivially reproducible.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pyarrow as pa

from oss_pulse.config import Settings
from oss_pulse.ingest.io import atomic_write_table
from oss_pulse.ingest.schema import PYPI_RELEASES, TRACKED_PROJECTS

log = logging.getLogger(__name__)


def releases_from_document(package: str, doc: dict, ingested_at: datetime) -> list[dict]:
    rows = []
    for version, files in (doc.get("releases") or {}).items():
        if not files:  # versions registered with no uploaded files
            continue
        uploads = [
            datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
            for f in files
            if f.get("upload_time_iso_8601")
        ]
        rows.append(
            {
                "package": package.lower(),
                "version": version,
                "uploaded_at": min(uploads) if uploads else None,
                "is_yanked": all(f.get("yanked", False) for f in files),
                "file_count": len(files),
                "total_size_bytes": sum(int(f.get("size") or 0) for f in files),
                "requires_python": next(
                    (f["requires_python"] for f in files if f.get("requires_python")), None
                ),
                "_ingested_at": ingested_at,
            }
        )
    return rows


def fetch_document(settings: Settings, package: str, client: httpx.Client) -> dict:
    local = settings.raw_dir / "pypi" / f"{package.lower()}.json"
    if local.exists():  # offline / synthetic mode
        return json.loads(local.read_text())
    resp = client.get(f"{settings.pypi_base_url.rstrip('/')}/{package}/json")
    resp.raise_for_status()
    return resp.json()


def ingest_pypi(settings: Settings, snapshot: date | None = None) -> Path:
    snapshot = snapshot or datetime.now(UTC).date()
    ingested_at = datetime.now(UTC)
    rows: list[dict] = []
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        for project in settings.tracked_projects():
            if not project.pypi:
                continue
            try:
                doc = fetch_document(settings, project.pypi, client)
            except httpx.HTTPError as exc:
                log.error("pypi fetch failed for %s: %s", project.pypi, exc)
                raise
            rows.extend(releases_from_document(project.pypi, doc, ingested_at))
    path = (
        settings.bronze_dir
        / "pypi_releases"
        / f"snapshot_date={snapshot:%Y-%m-%d}"
        / "part-0.parquet"
    )
    atomic_write_table(pa.Table.from_pylist(rows, schema=PYPI_RELEASES), path)
    log.info("pypi snapshot %s: %d releases", snapshot, len(rows))
    return path


def write_reference(settings: Settings) -> Path:
    """Materialise tracked_projects.yml as a bronze table so dbt can join on it."""
    rows = [
        {"repo_name": p.repo, "pypi_package": p.pypi.lower() if p.pypi else None}
        for p in settings.tracked_projects()
    ]
    path = settings.bronze_dir / "reference" / "tracked_projects.parquet"
    return atomic_write_table(pa.Table.from_pylist(rows, schema=TRACKED_PROJECTS), path)
