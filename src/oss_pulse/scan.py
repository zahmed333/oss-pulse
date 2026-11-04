"""`oss-pulse scan`: repository scan orchestration and rendering (no network needed).

Trust boundary: the folder being scanned is untrusted, so nothing inside it configures
the scan. An ignore file only applies when the user passes it with `--ignore-file`; an
`.osspulseignore` that ships inside the folder is reported (EVADE-IGNORE) together with
the findings it would have hidden. Suppressed findings are always counted in the report.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from oss_pulse.ingest.dependencies import parse_dependency_file
from oss_pulse.safe_text import md_code, md_text
from oss_pulse.supplychain import typosquat
from oss_pulse.supplychain.findings import SEVERITY_RANK, Finding
from oss_pulse.supplychain.repo_scan import scan_repository

IGNORE_FILE = ".osspulseignore"
ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    suppressed: list[Finding] = field(default_factory=list)
    ignore_file: Path | None = None


def _read_patterns(path: Path) -> list[str]:
    lines = path.read_text(errors="replace").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def _ignored(f: Finding, patterns: list[str]) -> bool:
    path = f.location.rsplit(":", 1)[0]
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(f.rule_id, p) for p in patterns)


def run_scan(path: Path, ignore_file: Path | None = None) -> ScanResult:
    root = path.resolve()
    findings = scan_repository(root)
    # Declared Python dependencies: typosquatting check against the bundled popular list.
    popular = typosquat.load_popular()
    for dep_file in [root / "pyproject.toml", *sorted(root.glob("requirements*.txt"))]:
        if dep_file.is_file():
            try:
                names = [d.name for d in parse_dependency_file(dep_file)]
            except (ValueError, OSError):
                continue
            for f in typosquat.check_names(names, popular):
                f.target, f.target_type, f.location = root.name, "repository", dep_file.name
                f.detail = f"dependency '{f.evidence}'-lookalike declared: {f.detail}"
                findings.append(f)
    chosen = ignore_file.resolve() if ignore_file else None
    planted = root / IGNORE_FILE
    if planted.is_file() and planted.resolve() != chosen:
        findings.append(_planted_ignore_finding(root, planted, findings))

    suppressed: list[Finding] = []
    if chosen:
        patterns = _read_patterns(chosen)
        suppressed = [f for f in findings if _ignored(f, patterns)]
        findings = [f for f in findings if not _ignored(f, patterns)]
    for group in (findings, suppressed):
        group.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.location))
    return ScanResult(root, findings, suppressed, chosen)


def _planted_ignore_finding(root: Path, planted: Path, findings: list[Finding]) -> Finding:
    would_hide = [f for f in findings if _ignored(f, _read_patterns(planted))]
    if would_hide:
        detail = (
            f"it would have hidden {len(would_hide)} of the findings in this report. "
            "It was not applied: a folder can't switch off the checks on itself."
        )
    else:
        detail = "it was not applied: a folder can't switch off the checks on itself."
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
        evidence=", ".join(_read_patterns(planted))[:200],
    )


def render_scan_markdown(result: ScanResult) -> str:
    findings = result.findings
    counts = {s: sum(f.severity == s for f in findings) for s in ICONS}
    summary = " · ".join(f"{ICONS[s]} {n} {s}" for s, n in counts.items() if n) or "🟢 no findings"
    lines = [
        "<!-- oss-pulse-scan -->",
        f"## Repository scan: {md_code(result.root.name, in_table=False)}",
        "",
        f"**{len(findings)} findings** · {summary}",
        "",
    ]
    if any(f.category == "auto-execution" and f.severity == "critical" for f in findings):
        lines += [
            "> [!CAUTION]",
            "> This folder is set up to **run code automatically** when opened or installed. "
            "Do not open it in VS Code with Workspace Trust or run `npm install`/`pip install` "
            "outside a disposable VM.",
            "",
        ]
    if findings:
        lines += ["| Severity | Rule | Finding | Where | Evidence |", "|---|---|---|---|---|"]
        for f in findings:
            lines.append(
                f"| {ICONS[f.severity]} {f.severity} | {f.rule_id} | {md_text(f.title)}: "
                f"{md_text(f.detail)} | {md_code(f.location)} | {md_code(f.evidence, 100)} |"
            )
    if result.suppressed:
        by_rule: dict[str, int] = {}
        for f in result.suppressed:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        listed = ", ".join(f"{rule} ×{n}" for rule, n in sorted(by_rule.items()))
        lines += [
            "",
            f"{len(result.suppressed)} findings suppressed by "
            f"{md_code(result.ignore_file.name, in_table=False)}: {listed}",
        ]
    lines += [
        "",
        "<sub>Static scan, nothing was executed. To accept reviewed findings in your own "
        f"repository, list paths or rule ids in a file and pass `--ignore-file {IGNORE_FILE}`; "
        "an ignore file inside a scanned folder is never applied. "
        "`oss-pulse rules` lists all rules.</sub>",
    ]
    return "\n".join(lines) + "\n"


def render_scan_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "target": str(result.root),
            "findings": [f.as_row() for f in result.findings],
            "suppressed": [f.as_row() for f in result.suppressed],
            "ignore_file": str(result.ignore_file) if result.ignore_file else None,
        },
        indent=2,
        default=str,
    )
