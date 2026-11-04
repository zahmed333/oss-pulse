"""One finding format for every detector, so findings can be stored in bronze, modelled
in dbt, rendered in reports and gated in CI uniformly."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

import pyarrow as pa

from oss_pulse.ingest.io import atomic_write_table
from oss_pulse.ingest.schema import UTC_TS

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}  # critical=5

FINDINGS = pa.schema(
    [
        pa.field("target", pa.string(), nullable=False),  # package name or repo path
        pa.field("target_type", pa.string(), nullable=False),  # package | repository
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


@dataclass
class Finding:
    target: str
    target_type: str
    detector: str
    rule_id: str
    severity: str
    category: str
    title: str
    detail: str = ""
    location: str = ""
    evidence: str = ""
    target_version: str | None = None
    _ingested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_row(self) -> dict:
        return asdict(self)


def worst(findings: list[Finding]) -> str | None:
    return max((f.severity for f in findings), key=SEVERITY_RANK.get, default=None)


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
