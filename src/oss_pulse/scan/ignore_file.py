"""User-owned suppression lists: glob patterns over paths or rule ids."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from oss_pulse.supplychain.findings import Finding


def read_patterns(path: Path) -> list[str]:
    lines = path.read_text(errors="replace").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def matches(finding: Finding, patterns: list[str]) -> bool:
    path = finding.location.rsplit(":", 1)[0]
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(finding.rule_id, p) for p in patterns)
