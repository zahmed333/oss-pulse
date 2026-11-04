"""GitHub Actions workflow checks: the CI/CD half of the supply chain.

Covers the patterns behind tj-actions/changed-files (mutable tags), Nx/s1ngularity
(pull_request_target + PR checkout) and Ultralytics (script injection, cache poisoning).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from oss_pulse.supplychain.code_scan import Hit

SHA = re.compile(r"^[0-9a-f]{40}$")
TRUSTED_OWNERS = {"actions", "github"}  # first-party; still better pinned, but not flagged
INJECTABLE = re.compile(
    r"\$\{\{\s*(github\.head_ref|github\.event\.[\w.\[\]*'\"-]*?"
    r"(?:title|body|name|label|ref|message|email|default_branch|page_name|head_ref)"
    r"(?:\b|\]))[^}]*\}\}"
)
RELEASE_HINT = re.compile(
    r"pypa/gh-action-pypi-publish|twine\s+upload|npm\s+publish|"
    r"uv\s+publish|poetry\s+publish|release|publish|deploy",
    re.I,
)


def _line(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _triggers(doc: dict) -> set[str]:
    on = doc.get("on", doc.get(True))  # PyYAML parses a bare `on:` key as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def scan_workflow(rel: str, text: str) -> list[Hit]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    hits: list[Hit] = []
    triggers = _triggers(doc)
    jobs = doc.get("jobs") or {}
    is_release = (
        bool(RELEASE_HINT.search(rel))
        or bool(RELEASE_HINT.search(str(doc.get("name", ""))))
        or "pypa/gh-action-pypi-publish" in text
        or "twine upload" in text
    )
    every_job_has_perms = bool(jobs) and all(
        isinstance(j, dict) and "permissions" in j for j in jobs.values()
    )
    if "permissions" not in doc and not every_job_has_perms:
        hits.append(Hit("GHA-PERMS", rel, 1, "no permissions: block"))

    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses") or "")
            if uses and not uses.startswith(("./", "docker://")) and "@" in uses:
                ref = uses.rsplit("@", 1)[1]
                owner = uses.split("/", 1)[0].lower()
                if owner not in TRUSTED_OWNERS and not SHA.match(ref):
                    hits.append(Hit("GHA-UNPINNED", rel, _line(text, uses), uses))
            with_ = step.get("with") or {}
            if "pull_request_target" in triggers and uses.startswith("actions/checkout"):
                ref = str(with_.get("ref", ""))
                if "head" in ref or "github.event.pull_request" in ref:
                    hits.append(Hit("GHA-PRT", rel, _line(text, ref), f"checkout ref: {ref}"))
            run = str(step.get("run") or "")
            if m := INJECTABLE.search(run):
                hits.append(Hit("GHA-INJECT", rel, _line(text, m.group(0)), m.group(0)))
            if is_release and (
                uses.startswith("actions/cache")
                or (uses.startswith("actions/setup-") and with_.get("cache"))
            ):
                hits.append(Hit("GHA-CACHE-RELEASE", rel, _line(text, uses), uses))
    return hits


def scan_workflows(root: Path) -> list[Hit]:
    hits = []
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for path in sorted(wf_dir.glob("*.y*ml")):
            hits.extend(
                scan_workflow(str(path.relative_to(root)), path.read_text(errors="replace"))
            )
    return hits
