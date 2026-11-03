from datetime import UTC, datetime

from oss_pulse.ingest.pypi import releases_from_document, write_reference

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def f(ts, size=10, yanked=False):
    return {"upload_time_iso_8601": ts, "size": size, "yanked": yanked}


def test_releases_from_document():
    doc = {
        "releases": {
            "1.0.0": [f("2025-01-02T00:00:00.1Z", 5), f("2025-01-01T00:00:00Z", 7)],
            "1.0.1": [f("2025-02-01T00:00:00Z", yanked=True)],
            "2.0.0rc0": [],  # registered but no files -> skipped
        }
    }
    rows = {r["version"]: r for r in releases_from_document("DuckDB", doc, NOW)}
    assert set(rows) == {"1.0.0", "1.0.1"}
    assert rows["1.0.0"]["package"] == "duckdb"
    assert rows["1.0.0"]["uploaded_at"] == datetime(2025, 1, 1, tzinfo=UTC)  # earliest file
    assert rows["1.0.0"]["total_size_bytes"] == 12
    assert rows["1.0.1"]["is_yanked"] is True


def test_reference_table_matches_config(settings):
    import pyarrow.parquet as pq

    table = pq.read_table(write_reference(settings))
    assert table.num_rows == len(settings.tracked_projects())
