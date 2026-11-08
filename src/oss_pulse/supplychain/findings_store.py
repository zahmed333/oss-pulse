"""Findings as a bronze Parquet table, for the dbt models behind `check`."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pyarrow as pa

from oss_pulse.ingest.io import atomic_write_table
from oss_pulse.ingest.schema import UTC_TS
from oss_pulse.supplychain.findings import Finding

FINDINGS = pa.schema(
    [
        pa.field("target", pa.string(), nullable=False),
        pa.field("target_type", pa.string(), nullable=False),
        pa.field("target_version", pa.string()),
        pa.field("detector", pa.string(), nullable=False),
        pa.field("rule_id", pa.string(), nullable=False),
        pa.field("severity", pa.string(), nullable=False),
        pa.field("category", pa.string(), nullable=False),
        pa.field("title", pa.string(), nullable=False),
        pa.field("detail", pa.string()),
        pa.field("location", pa.string()),
        pa.field("evidence", pa.string()),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)


def write_findings(
    bronze_dir: Path, detector: str, findings: list[Finding], day: date | None = None
) -> Path:
    day = day or datetime.now(UTC).date()
    path = (
        bronze_dir
        / "findings"
        / f"detector={detector}"
        / f"snapshot_date={day:%Y-%m-%d}"
        / "part-0.parquet"
    )
    return atomic_write_table(
        pa.Table.from_pylist([f.as_row() for f in findings], schema=FINDINGS), path
    )
