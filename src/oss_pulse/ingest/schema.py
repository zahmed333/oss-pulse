"""Bronze-layer contracts.

Bronze is "raw but typed": every source record lands exactly once, with a stable,
explicit Arrow schema, plus lineage columns (`_source_file`, `_ingested_at`).
Nested payloads stay as JSON text so upstream schema drift never breaks ingestion --
it is handled downstream in dbt, where it is visible and testable.
"""

from __future__ import annotations

import pyarrow as pa

UTC_TS = pa.timestamp("us", tz="UTC")

GHARCHIVE_EVENTS = pa.schema(
    [
        pa.field("event_id", pa.string(), nullable=False),
        pa.field("event_type", pa.string(), nullable=False),
        pa.field("created_at", UTC_TS, nullable=False),
        pa.field("actor_id", pa.int64(), nullable=False),
        pa.field("actor_login", pa.string()),
        pa.field("repo_id", pa.int64(), nullable=False),
        pa.field("repo_name", pa.string()),
        pa.field("org_login", pa.string()),
        pa.field("payload_action", pa.string()),
        pa.field("payload", pa.string()),  # raw JSON
        pa.field("is_public", pa.bool_()),
        pa.field("_source_file", pa.string(), nullable=False),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)

PYPI_RELEASES = pa.schema(
    [
        pa.field("package", pa.string(), nullable=False),
        pa.field("version", pa.string(), nullable=False),
        pa.field("uploaded_at", UTC_TS),
        pa.field("is_yanked", pa.bool_()),
        pa.field("file_count", pa.int32()),
        pa.field("total_size_bytes", pa.int64()),
        pa.field("requires_python", pa.string()),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)

TRACKED_PROJECTS = pa.schema(
    [
        pa.field("repo_name", pa.string(), nullable=False),
        pa.field("pypi_package", pa.string()),
    ]
)
