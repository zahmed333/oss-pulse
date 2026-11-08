"""The steps of one `scan` run: find, add lookalike dependencies, flag a planted ignore
file, apply the user's own ignore file, sort."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from oss_pulse.ingest.dependencies import parse_dependency_file
from oss_pulse.scan.ignore_file import matches, read_patterns
from oss_pulse.supplychain import typosquat
from oss_pulse.supplychain.findings import SEVERITY_RANK, Finding
from oss_pulse.supplychain.repo_scan import scan_repository

IGNORE_FILE = ".osspulseignore"


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    suppressed: list[Finding] = field(default_factory=list)
    ignore_file: Path | None = None


def run_scan(path: Path, ignore_file: Path | None = None) -> ScanResult:
    root = path.resolve()
    users_ignore_file = ignore_file.resolve() if ignore_file and ignore_file.is_file() else None
    findings = scan_repository(root) + lookalike_dependencies(root)
    if planted := planted_ignore_file(root, findings, users_ignore_file):
        findings.append(planted)
    kept, suppressed = apply_ignore_file(findings, users_ignore_file)
    return ScanResult(root, by_severity(kept), by_severity(suppressed), users_ignore_file)


def dependency_files(root: Path) -> list[Path]:
    candidates = [root / "pyproject.toml", *sorted(root.glob("requirements*.txt"))]
    return [f for f in candidates if f.is_file()]


def lookalike_dependencies(root: Path) -> list[Finding]:
    popular = typosquat.load_popular()
    findings = []
    for dep_file in dependency_files(root):
        try:
            names = [d.name for d in parse_dependency_file(dep_file)]
        except (ValueError, OSError):
            continue
        for f in typosquat.check_names(names, popular):
            declared, popular = f.target, f.evidence
            f.target, f.target_type, f.location = root.name, "repository", dep_file.name
            f.evidence = f"{declared} (looks like {popular})"
            f.detail = f"declares {declared}, which looks like the popular package {popular}"
            findings.append(f)
    return findings


def planted_ignore_file(
    root: Path, findings: list[Finding], users_ignore_file: Path | None
) -> Finding | None:
    planted = root / IGNORE_FILE
    if not planted.is_file() or planted.resolve() == users_ignore_file:
        return None
    patterns = read_patterns(planted)
    would_hide = [f for f in findings if matches(f, patterns)]
    not_applied = "a folder can't switch off the checks on itself."
    if would_hide:
        detail = (
            f"it would have hidden {len(would_hide)} of the findings in this report. "
            f"It was not applied: {not_applied}"
        )
    else:
        detail = f"it was not applied: {not_applied}"
    return Finding(
        target=root.name,
        target_type="repository",
        detector="repo_scan",
        rule_id="EVADE-IGNORE",
        severity="high" if would_hide else "low",
        category="evasion",
        title="The folder ships its own OSS Pulse ignore file",
        detail=detail,
        location=IGNORE_FILE,
        evidence=", ".join(patterns)[:200],
    )


def apply_ignore_file(
    findings: list[Finding], users_ignore_file: Path | None
) -> tuple[list[Finding], list[Finding]]:
    if not users_ignore_file:
        return findings, []
    patterns = read_patterns(users_ignore_file)
    kept = [f for f in findings if not matches(f, patterns)]
    suppressed = [f for f in findings if matches(f, patterns)]
    return kept, suppressed


def by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.location))
