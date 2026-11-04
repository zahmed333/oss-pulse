"""OpenSSF Scorecard (https://scorecard.dev): automated security-practice checks that
OpenSSF runs weekly on popular repos - e.g. Dangerous-Workflow, Branch-Protection,
Code-Review, Token-Permissions, Signed-Releases, Pinned-Dependencies.

A 404 is normal (the repo isn't in the weekly scan) and is recorded as "no data",
never as a failure.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pyarrow as pa

from oss_pulse.config import Settings
from oss_pulse.ingest.io import atomic_write_json, atomic_write_table
from oss_pulse.ingest.schema import SCORECARD_CHECKS

log = logging.getLogger(__name__)

SCORECARD_API = "https://api.securityscorecards.dev"


def scorecard_to_rows(repo: str, doc: dict, ingested_at: datetime) -> list[dict]:
    day = (doc.get("date") or "")[:10]
    return [
        {
            "repo_name": repo,
            "scorecard_date": date.fromisoformat(day) if day else None,
            "overall_score": doc.get("score"),
            "check_name": c["name"],
            "check_score": c.get("score"),
            "reason": c.get("reason"),
            "_ingested_at": ingested_at,
        }
        for c in doc.get("checks") or []
    ]


def fetch_scorecard(settings: Settings, repo: str, client: httpx.Client, day: date) -> dict | None:
    cached = settings.raw_dir / "scorecard" / f"{day:%Y-%m-%d}" / f"{repo.replace('/', '__')}.json"
    if cached.exists():
        return json.loads(cached.read_text()) or None
    resp = client.get(f"{SCORECARD_API}/projects/github.com/{repo}")
    doc = {} if resp.status_code == 404 else resp.raise_for_status().json()
    atomic_write_json(doc, cached)
    return doc or None


def ingest_scorecard(
    settings: Settings,
    repos: list[str],
    day: date | None = None,
    client: httpx.Client | None = None,
) -> Path:
    day = day or datetime.now(UTC).date()
    ingested_at = datetime.now(UTC)
    own = client is None
    client = client or httpx.Client(timeout=30.0)
    rows: list[dict] = []
    try:
        for repo in repos:
            try:
                doc = fetch_scorecard(settings, repo, client, day)
            except httpx.HTTPError as exc:  # optional enrichment: degrade, don't fail
                log.warning("scorecard unavailable for %s: %s", repo, exc)
                continue
            if doc:
                rows.extend(scorecard_to_rows(repo, doc, ingested_at))
    finally:
        if own:
            client.close()
    path = settings.bronze_dir / "scorecard" / f"snapshot_date={day:%Y-%m-%d}" / "part-0.parquet"
    atomic_write_table(pa.Table.from_pylist(rows, schema=SCORECARD_CHECKS), path)
    log.info("scorecard: %d checks across %d repos", len(rows), len(repos))
    return path
