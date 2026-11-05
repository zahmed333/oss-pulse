"""GH Archive ingestion: one hourly archive -> one bronze Parquet partition.

Design properties (the things a reviewer should look for):

* **Idempotent** - the unit of work is an archive hour; re-running an hour overwrites
  exactly one partition (`event_date=YYYY-MM-DD/event_hour=HH`) atomically.
* **Streaming / bounded memory** - a full GH Archive hour is ~200k events; we never
  hold it all as Python dicts, we flush Arrow record batches into a ParquetWriter.
* **Quarantine, don't crash** - malformed lines are written to a quarantine file with
  a reason, counted, and surfaced in a per-partition manifest that dbt reconciles.
* **Deduplicated** - GH Archive occasionally repeats event ids within an hour.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from oss_pulse.config import Settings
from oss_pulse.ingest.io import _tmp_sibling, atomic_write_json, atomic_write_lines
from oss_pulse.ingest.schema import GHARCHIVE_EVENTS

log = logging.getLogger(__name__)

BATCH_SIZE = 50_000
MAX_RETRIES = 4


class InvalidEvent(ValueError):
    """Raised when a record is missing fields required by the bronze contract."""


class ArchiveNotAvailable(RuntimeError):
    """The requested hour is not (yet) published by GH Archive."""


@dataclass(frozen=True)
class IngestResult:
    hour: datetime
    source_file: str
    rows_read: int
    rows_written: int
    rows_rejected: int
    rows_duplicate: int
    partition_path: str
    ingested_at: datetime


def floor_hour(ts: datetime) -> datetime:
    ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def hour_range(start: datetime, end: datetime) -> list[datetime]:
    """Hours in [start, end)."""
    cur, end = floor_hour(start), floor_hour(end)
    out = []
    while cur < end:
        out.append(cur)
        cur += timedelta(hours=1)
    return out


def archive_filename(hour: datetime) -> str:
    # GH Archive uses a non-zero-padded hour: 2024-01-01-0.json.gz ... 2024-01-01-23.json.gz
    return f"{hour:%Y-%m-%d}-{hour.hour}.json.gz"


def partition_dir(root: Path, hour: datetime) -> Path:
    return root / f"event_date={hour:%Y-%m-%d}" / f"event_hour={hour:%H}"


def download_hour(settings: Settings, hour: datetime, client: httpx.Client | None = None) -> Path:
    """Download an archive into the raw zone (cached: skipped if already present)."""
    name = archive_filename(hour)
    dest = settings.raw_dir / "gharchive" / name
    if dest.exists() and dest.stat().st_size > 0:
        log.info("raw cache hit %s", name)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"{settings.gharchive_base_url.rstrip('/')}/{name}"
    own_client = client is None
    client = client or httpx.Client(timeout=httpx.Timeout(30.0, read=120.0), follow_redirects=True)
    try:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with client.stream("GET", url) as resp:
                    if resp.status_code == 404:
                        raise ArchiveNotAvailable(f"{url} not published yet")
                    resp.raise_for_status()
                    tmp = _tmp_sibling(dest)
                    with open(tmp, "wb") as fh:
                        for chunk in resp.iter_bytes(chunk_size=1 << 20):
                            fh.write(chunk)
                    os.replace(tmp, dest)
                    log.info("downloaded %s (%.1f MB)", name, dest.stat().st_size / 1e6)
                    return dest
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                retriable = not isinstance(exc, httpx.HTTPStatusError) or (
                    exc.response.status_code >= 500 or exc.response.status_code == 429
                )
                if not retriable or attempt == MAX_RETRIES:
                    raise
                backoff = 2**attempt
                log.warning("download %s failed (%s), retry in %ss", name, exc, backoff)
                time.sleep(backoff)
    finally:
        if own_client:
            client.close()
    raise AssertionError("unreachable")


def _parse_ts(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def normalize_event(raw: dict, source_file: str, ingested_at: datetime) -> dict:
    """Map one GH Archive record onto the bronze contract (post-2015 event schema)."""
    try:
        actor, repo = raw["actor"], raw["repo"]
        record = {
            "event_id": str(raw["id"]),
            "event_type": str(raw["type"]),
            "created_at": _parse_ts(raw["created_at"]),
            "actor_id": int(actor["id"]),
            "actor_login": actor.get("login"),
            "repo_id": int(repo["id"]),
            "repo_name": repo.get("name"),
        }
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise InvalidEvent(f"{type(exc).__name__}: {exc}") from exc

    payload = raw.get("payload")
    record.update(
        org_login=(raw.get("org") or {}).get("login"),
        payload_action=payload.get("action") if isinstance(payload, dict) else None,
        payload=json.dumps(payload, separators=(",", ":")) if payload is not None else None,
        is_public=bool(raw.get("public", True)),
        _source_file=source_file,
        _ingested_at=ingested_at,
    )
    return record


def iter_archive(path: Path) -> Iterator[tuple[int, str]]:
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if line:
                yield lineno, line


def ingest_file(settings: Settings, hour: datetime, archive_path: Path) -> IngestResult:
    """Parse an archive file and (over)write its bronze partition + manifest."""
    hour = floor_hour(hour)
    ingested_at = datetime.now(UTC)
    source_file = archive_path.name

    out_dir = partition_dir(settings.bronze_dir / "gharchive", hour)
    out_path = out_dir / "part-0.parquet"
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = _tmp_sibling(out_path)

    seen: set[str] = set()
    rejects: list[str] = []
    buffer: list[dict] = []
    read = written = dupes = 0

    writer = pq.ParquetWriter(tmp_path, GHARCHIVE_EVENTS, compression="zstd")

    def flush() -> None:
        nonlocal written
        if buffer:
            writer.write_table(pa.Table.from_pylist(buffer, schema=GHARCHIVE_EVENTS))
            written += len(buffer)
            buffer.clear()

    try:
        for lineno, line in iter_archive(archive_path):
            read += 1
            try:
                record = normalize_event(json.loads(line), source_file, ingested_at)
            except (json.JSONDecodeError, InvalidEvent) as exc:
                rejects.append(json.dumps({"line": lineno, "reason": str(exc), "raw": line[:2000]}))
                continue
            if record["event_id"] in seen:
                dupes += 1
                continue
            seen.add(record["event_id"])
            buffer.append(record)
            if len(buffer) >= BATCH_SIZE:
                flush()
        flush()
        writer.close()
        os.replace(tmp_path, out_path)
    except BaseException:
        writer.close()
        tmp_path.unlink(missing_ok=True)
        raise

    quarantine = partition_dir(settings.bronze_dir / "_quarantine" / "gharchive", hour)
    if rejects:
        atomic_write_lines(rejects, quarantine / "rejects.jsonl")
    else:  # a clean re-run must clear stale rejects from a previous run
        (quarantine / "rejects.jsonl").unlink(missing_ok=True)

    result = IngestResult(
        hour=hour,
        source_file=source_file,
        rows_read=read,
        rows_written=written,
        rows_rejected=len(rejects),
        rows_duplicate=dupes,
        partition_path=str(out_path),
        ingested_at=ingested_at,
    )
    atomic_write_json(
        {**asdict(result), "hour": hour.isoformat(), "ingested_at": ingested_at.isoformat()},
        partition_dir(settings.bronze_dir / "_manifests" / "gharchive", hour) / "manifest.json",
    )
    log.info(
        "ingested %s: read=%d written=%d rejected=%d dupes=%d",
        source_file,
        read,
        written,
        len(rejects),
        dupes,
    )
    return result


def ingest_hour(
    settings: Settings, hour: datetime, client: httpx.Client | None = None
) -> IngestResult:
    """Download (if needed) and ingest a single hour from GH Archive."""
    path = download_hour(settings, floor_hour(hour), client=client)
    return ingest_file(settings, hour, path)


def ingest_local_hour(settings: Settings, hour: datetime) -> IngestResult:
    """Ingest an hour already present in the raw zone (e.g. produced by `synthetic`)."""
    path = settings.raw_dir / "gharchive" / archive_filename(floor_hour(hour))
    if not path.exists():
        raise FileNotFoundError(path)
    return ingest_file(settings, hour, path)
