"""`oss-pulse scan`: repository scan orchestration and rendering (no network needed)."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from oss_pulse.ingest.dependencies import parse_dependency_file
from oss_pulse.supplychain import typosquat
from oss_pulse.supplychain.findings import SEVERITY_RANK, Finding
from oss_pulse.supplychain.repo_scan import scan_repository

IGNORE_FILE = ".osspulseignore"
ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _ignore_patterns(root: Path) -> list[str]:
    f = root / IGNORE_FILE
    if not f.is_file():
        return []
    return [
        ln.strip() for ln in f.read_text().splitlines() if ln.strip() and not ln.startswith("#")
    ]


def _ignored(f: Finding, patterns: list[str]) -> bool:
    path = f.location.rsplit(":", 1)[0]
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(f.rule_id, p) for p in patterns)


def run_scan(path: Path) -> list[Finding]:
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
    patterns = _ignore_patterns(root)
    findings = [f for f in findings if not _ignored(f, patterns)]
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.location))
    return findings


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_scan_markdown(path: Path, findings: list[Finding]) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in ICONS}
    summary = " · ".join(f"{ICONS[s]} {n} {s}" for s, n in counts.items() if n) or "🟢 no findings"
    lines = [
        "<!-- oss-pulse-scan -->",
        f"## Repository scan: `{path.resolve().name}`",
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
                f"| {ICONS[f.severity]} {f.severity} | {f.rule_id} | {_md(f.title)}: "
                f"{_md(f.detail)} | `{_md(f.location)}` | `{_md(f.evidence[:100])}` |"
            )
    lines += [
        "",
        f"<sub>Static scan, nothing was executed. Suppress reviewed findings with "
        f"glob patterns (paths or rule ids) in `{IGNORE_FILE}`. "
        "`oss-pulse rules` lists all rules.</sub>",
    ]
    return "\n".join(lines) + "\n"


def render_scan_json(path: Path, findings: list[Finding]) -> str:
    return json.dumps(
        {"target": str(path.resolve()), "findings": [f.as_row() for f in findings]},
        indent=2,
        default=str,
    )
