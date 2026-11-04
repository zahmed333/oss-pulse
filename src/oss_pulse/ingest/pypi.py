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
from packaging.utils import canonicalize_name

from oss_pulse.config import Settings, TrackedProject
from oss_pulse.ingest.io import atomic_write_json, atomic_write_table
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
                "package": canonicalize_name(package),
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


def fetch_document(
    settings: Settings, package: str, client: httpx.Client, day: date | None = None
) -> dict | None:
    """PyPI JSON for a package, cached in the raw zone per day. None if not on PyPI."""
    day = day or datetime.now(UTC).date()
    name = canonicalize_name(package)
    dated = settings.raw_dir / "pypi" / f"{day:%Y-%m-%d}" / f"{name}.json"
    for local in (dated, settings.raw_dir / "pypi" / f"{name}.json"):  # undated = synthetic
        if local.exists():
            return json.loads(local.read_text())
    resp = client.get(f"{settings.pypi_base_url.rstrip('/')}/{name}/json")
    if resp.status_code == 404:
        log.warning("%s is not on PyPI", name)
        return None
    resp.raise_for_status()
    atomic_write_json(resp.json(), dated)
    return resp.json()


def ingest_pypi(
    settings: Settings,
    snapshot: date | None = None,
    packages: list[str] | None = None,
    client: httpx.Client | None = None,
) -> Path:
    """Snapshot release history for `packages` (default: tracked_projects.yml)."""
    snapshot = snapshot or datetime.now(UTC).date()
    ingested_at = datetime.now(UTC)
    if packages is None:
        packages = [p.pypi for p in settings.tracked_projects() if p.pypi]
    rows: list[dict] = []
    http = client or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        for package in packages:
            doc = fetch_document(settings, package, http, snapshot)
            if doc is not None:
                rows.extend(releases_from_document(package, doc, ingested_at))
    finally:
        if client is None:
            http.close()
    path = (
        settings.bronze_dir
        / "pypi_releases"
        / f"snapshot_date={snapshot:%Y-%m-%d}"
        / "part-0.parquet"
    )
    atomic_write_table(pa.Table.from_pylist(rows, schema=PYPI_RELEASES), path)
    log.info("pypi snapshot %s: %d releases", snapshot, len(rows))
    return path


def write_reference(settings: Settings, projects: list[TrackedProject] | None = None) -> Path:
    """Publish the tracked project list (default: tracked_projects.yml) as a bronze table."""
    projects = settings.tracked_projects() if projects is None else projects
    rows = [
        {"repo_name": p.repo, "pypi_package": canonicalize_name(p.pypi) if p.pypi else None}
        for p in projects
    ]
    path = settings.bronze_dir / "reference" / "tracked_projects.parquet"
    return atomic_write_table(pa.Table.from_pylist(rows, schema=TRACKED_PROJECTS), path)
