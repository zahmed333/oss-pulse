"""One finding format for every detector, so findings can be rendered, gated in CI and
stored the same way. Storage lives in findings_store, which only `check` needs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}


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
