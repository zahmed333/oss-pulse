"""What a person sees in their terminal: the verdict first, the evidence, then what to do.

The Markdown reports stay for PR comments and job summaries; this is the human view.
Colour only when stdout is a terminal and NO_COLOR is unset, and only on the verdict word.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass

from oss_pulse.safe_text import visible

HOLD, REVIEW, NOTE, CLEAR = "hold", "review", "note", "clear"
VERDICT_OF_SEVERITY = {"critical": HOLD, "high": HOLD, "medium": REVIEW, "low": NOTE, "info": NOTE}
VERDICT_ORDER = [HOLD, REVIEW, NOTE, CLEAR]
COLOURS = {HOLD: "\x1b[1;31m", REVIEW: "\x1b[1m", NOTE: "\x1b[2m", CLEAR: "\x1b[1m"}
RESET = "\x1b[0m"
GUIDE = "https://github.com/zahmed333/oss-pulse/blob/main/docs/if-you-opened-it.md"
RULES = "https://github.com/zahmed333/oss-pulse/blob/main/docs/RULES.md"


def use_colour(stream=sys.stdout) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def word(verdict: str, colour: bool) -> str:
    padded = f"{verdict:<7}"
    return f"{COLOURS[verdict]}{padded}{RESET}" if colour else padded


def worst(verdicts: Iterable[str]) -> str:
    present = set(verdicts)
    return next((v for v in VERDICT_ORDER if v in present), CLEAR)


@dataclass(frozen=True)
class Row:
    verdict: str
    where: str
    says: str
    rule_id: str
    evidence: str = ""


def _rows(rows: list[Row], colour: bool) -> list[str]:
    lines = []
    for row in sorted(rows, key=lambda r: VERDICT_ORDER.index(r.verdict)):
        lines.append(
            f"  {word(row.verdict, colour)} {visible(row.where)}  {row.says}  [{row.rule_id}]"
        )
        if row.evidence:
            lines.append(f"          {visible(row.evidence, 110)}")
    return lines


def _numbered(steps: list[str]) -> list[str]:
    return [f"  {i}. {step}" for i, step in enumerate(steps, 1)]


def render_scan(findings, folder: str, suppressed: int = 0, colour: bool = False) -> str:
    rows = [
        Row(VERDICT_OF_SEVERITY[f.severity], f.location, f.title, f.rule_id, f.evidence)
        for f in findings
    ]
    verdict = worst(r.verdict for r in rows)
    runs_on_open = any(
        f.category == "auto-execution" and VERDICT_OF_SEVERITY[f.severity] == HOLD for f in findings
    )
    if verdict == HOLD and runs_on_open:
        headline = "Don't open this folder in VS Code, and don't install its dependencies."
        reason = "It is set up to run code as soon as it is opened or installed."
    elif verdict == HOLD:
        headline = "Don't run or install this code until the findings below are explained."
        reason = "It contains code that hides, steals or downloads more code."
    elif verdict == REVIEW:
        headline = "Read the lines below before you open or install this."
        reason = "Nothing clearly malicious, but some of it runs on install or in CI."
    else:
        headline = f"No rule matched in {folder}."
        reason = (
            "Clear means no rule matched. It isn't an audit, and it can't see what the "
            "code downloads after it starts."
        )

    lines = [f"{word(verdict, colour)}{headline}", f"       {reason}", ""]
    if rows:
        lines += _rows(rows, colour) + [""]
    if verdict == HOLD:
        steps = [
            "Delete the folder, or open it only in Restricted Mode: when VS Code asks "
            'whether you trust the authors, choose "No, I don\'t trust the authors".',
            f"If you already opened it or ran npm install, follow {GUIDE}",
            "If a recruiter sent it, report the posting where you found it.",
        ]
        lines += ["next", *_numbered(steps), ""]
    elif verdict == REVIEW:
        lines += ["next", *_numbered([f"Each rule is explained at {RULES}"]), ""]
    tail = f"{len(rows)} finding{'s' if len(rows) != 1 else ''}; nothing was run."
    if suppressed:
        tail += f" {suppressed} accepted in your ignore file."
    lines.append(tail)
    return "\n".join(lines) + "\n"


LEVEL_VERDICT = {"critical": HOLD, "high": HOLD, "medium": REVIEW, "unknown": NOTE, "ok": CLEAR}


def render_check(result, colour: bool = False) -> str:
    rows = result.rows
    verdict = worst(LEVEL_VERDICT[r["risk_level"]] for r in rows)
    held = [r["pypi_package"] for r in rows if LEVEL_VERDICT[r["risk_level"]] == HOLD]
    reviewed = [r["pypi_package"] for r in rows if LEVEL_VERDICT[r["risk_level"]] == REVIEW]
    if verdict == HOLD:
        headline = f"Don't install {_names(held)} until the reasons below are dealt with."
    elif verdict == REVIEW:
        headline = f"Look at {_names(reviewed)} before you merge or install."
    else:
        headline = f"No rule matched in {len(rows)} dependencies."
    lines = [f"{word(verdict, colour)}{headline}", ""]
    for r in sorted(rows, key=lambda r: VERDICT_ORDER.index(LEVEL_VERDICT[r["risk_level"]])):
        row_verdict = LEVEL_VERDICT[r["risk_level"]]
        name = f"{r['pypi_package']} {r['resolved_version'] or ''}".strip()
        reasons = r["risk_reasons"] or (["attested"] if r.get("has_provenance") else [])
        first = reasons[0] if reasons else ""
        lines.append(f"  {word(row_verdict, colour)} {visible(name):<28} {visible(first, 90)}")
        for extra in reasons[1:]:
            lines.append(f"  {'':<7} {'':<28} {visible(extra, 90)}")
    if result.unavailable_signals:
        lines += ["", "not checked"]
        lines += [f"  {visible(s, 110)}" for s in result.unavailable_signals]
    if verdict == HOLD:
        steps = [
            "Remove or replace the packages marked hold, or pin a version without the problem.",
            f"Each reason names a rule; {RULES} explains it and what to check.",
            "If you already installed one, treat that machine as exposed and rotate its "
            "credentials.",
        ]
        lines += ["", "next", *_numbered(steps)]
    lines += ["", f"{len(rows)} dependencies checked; nothing was installed or run."]
    return "\n".join(lines) + "\n"


def _names(names: list[str], limit: int = 3) -> str:
    shown = names[:limit]
    more = len(names) - len(shown)
    text = ", ".join(shown[:-1]) + (f" and {shown[-1]}" if len(shown) > 1 else shown[0])
    return f"{text} (and {more} more)" if more else text
