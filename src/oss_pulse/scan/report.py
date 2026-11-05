"""Markdown (terminal, PR comment, job summary) and JSON renderings of a ScanResult."""

from __future__ import annotations

import json
from collections import Counter

from oss_pulse.safe_text import md_code, md_text
from oss_pulse.scan.pipeline import IGNORE_FILE, ScanResult
from oss_pulse.supplychain.findings import SEVERITIES


def render_scan_markdown(result: ScanResult) -> str:
    findings = result.findings
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no rule matched"
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
                f"| {f.severity} | {f.rule_id} | {md_text(f.title)}: "
                f"{md_text(f.detail)} | {md_code(f.location)} | {md_code(f.evidence, 100)} |"
            )
    if result.suppressed:
        by_rule = Counter(f.rule_id for f in result.suppressed)
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
