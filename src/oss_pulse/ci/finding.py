"""One finding shape for every CI output, built from scan and check results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oss_pulse.supplychain.findings import SEVERITY_RANK, Finding


@dataclass(frozen=True)
class CiFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    path: str
    line: int | None
    evidence: str
    subject: str

    @property
    def message(self) -> str:
        return f"{self.subject}: {self.title}. {self.detail}".strip()

    def at_or_above(self, threshold: str) -> bool:
        return threshold != "never" and SEVERITY_RANK[self.severity] >= SEVERITY_RANK[threshold]


def split_location(location: str) -> tuple[str, int | None]:
    path, _, line = location.rpartition(":")
    if path and line.isdigit():
        return path, int(line)
    return location, None


def from_scan(findings: list[Finding], root: Path) -> list[CiFinding]:
    items = []
    for f in findings:
        path, line = split_location(f.location)
        items.append(
            CiFinding(f.rule_id, f.severity, f.title, f.detail, path, line, f.evidence, root.name)
        )
    return items


def from_check(findings: list[dict], dependency_file: Path) -> list[CiFinding]:
    return [
        CiFinding(
            f["rule_id"],
            f["severity"],
            f["title"],
            f"{f['detail'] or ''} ({f['location']})" if f.get("location") else f["detail"] or "",
            dependency_file.as_posix(),
            None,
            f.get("evidence") or "",
            f"{f['target']} {f.get('target_version') or ''}".strip(),
        )
        for f in findings
    ]
