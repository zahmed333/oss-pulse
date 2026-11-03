import gzip
import json
from datetime import UTC, datetime

import pyarrow.parquet as pq
import pytest

from oss_pulse.ingest import gharchive
from oss_pulse.ingest.schema import GHARCHIVE_EVENTS

HOUR = datetime(2026, 1, 5, 7, tzinfo=UTC)
NOW = datetime(2026, 1, 5, 8, tzinfo=UTC)


def event(i: int, **overrides) -> dict:
    ev = {
        "id": str(i),
        "type": "PullRequestEvent",
        "actor": {"id": 10, "login": "alice"},
        "repo": {"id": 20, "name": "duckdb/duckdb"},
        "payload": {"action": "opened", "number": 7},
        "public": True,
        "created_at": "2026-01-05T07:12:00Z",
        "org": {"id": 30, "login": "duckdb"},
    }
    ev.update(overrides)
    return ev


def write_archive(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def test_archive_filename_is_not_zero_padded():
    assert gharchive.archive_filename(HOUR) == "2026-01-05-7.json.gz"


def test_hour_range_is_half_open():
    hours = gharchive.hour_range(HOUR, datetime(2026, 1, 5, 10, 30, tzinfo=UTC))
    assert [h.hour for h in hours] == [7, 8, 9]


def test_normalize_event_maps_contract():
    rec = gharchive.normalize_event(event(1), "f.json.gz", NOW)
    assert set(rec) == set(GHARCHIVE_EVENTS.names)
    assert rec["created_at"] == datetime(2026, 1, 5, 7, 12, tzinfo=UTC)
    assert rec["payload_action"] == "opened"
    assert json.loads(rec["payload"])["number"] == 7
    assert rec["org_login"] == "duckdb"


def test_normalize_event_tolerates_missing_optional_fields():
    raw = event(1)
    del raw["org"], raw["payload"]
    rec = gharchive.normalize_event(raw, "f", NOW)
    assert rec["org_login"] is None and rec["payload"] is None


@pytest.mark.parametrize("drop", ["id", "type", "actor", "repo", "created_at"])
def test_normalize_event_rejects_missing_required(drop):
    raw = event(1)
    del raw[drop]
    with pytest.raises(gharchive.InvalidEvent):
        gharchive.normalize_event(raw, "f", NOW)


def test_ingest_file_quarantines_and_dedupes(settings):
    lines = [json.dumps(event(i)) for i in range(5)]
    lines += [json.dumps(event(2)), "{not json", json.dumps({"id": "x", "type": "PushEvent"})]
    path = write_archive(settings.raw_dir / "gharchive" / gharchive.archive_filename(HOUR), lines)

    res = gharchive.ingest_file(settings, HOUR, path)

    assert (res.rows_read, res.rows_written, res.rows_duplicate, res.rows_rejected) == (8, 5, 1, 2)
    table = pq.read_table(res.partition_path)
    assert table.schema.equals(GHARCHIVE_EVENTS, check_metadata=False)
    assert sorted(table.column("event_id").to_pylist()) == ["0", "1", "2", "3", "4"]
    rejects = (
        gharchive.partition_dir(settings.bronze_dir / "_quarantine" / "gharchive", HOUR)
        / "rejects.jsonl"
    )
    assert len(rejects.read_text().splitlines()) == 2
    manifest = json.loads(
        (
            gharchive.partition_dir(settings.bronze_dir / "_manifests" / "gharchive", HOUR)
            / "manifest.json"
        ).read_text()
    )
    assert manifest["rows_written"] == 5


def test_ingest_is_idempotent_and_clears_stale_rejects(settings):
    path = settings.raw_dir / "gharchive" / gharchive.archive_filename(HOUR)
    write_archive(path, [json.dumps(event(1)), "garbage"])
    first = gharchive.ingest_file(settings, HOUR, path)

    write_archive(path, [json.dumps(event(1)), json.dumps(event(2))])  # upstream fixed the file
    second = gharchive.ingest_file(settings, HOUR, path)

    assert first.partition_path == second.partition_path
    assert pq.read_table(second.partition_path).num_rows == 2
    parquet_files = list((settings.bronze_dir / "gharchive").rglob("*.parquet"))
    assert len(parquet_files) == 1, "re-runs must overwrite, never append"
    assert not list((settings.bronze_dir / "_quarantine").rglob("rejects.jsonl"))
    assert not list((settings.bronze_dir / "gharchive").rglob("*.tmp"))
