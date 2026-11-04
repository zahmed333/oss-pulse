"""`oss-pulse scan`: inspect an untrusted repository *before* you open or run it.

This is the developer-machine attack path: a "coding assignment" from a fake recruiter
(Contagious Interview), a cloned demo project, a tool found while searching for an AI
helper. Binance's 2026 incident involved exactly this kind of entry point. Opening such
a folder in VS Code or running `npm install` / `pip install .` can be enough to run
the payload.

Nothing in the target is executed or installed. The scanner reads files as bytes.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from oss_pulse.supplychain.code_scan import RE, Hit, scan_file
from oss_pulse.supplychain.findings import Finding
from oss_pulse.supplychain.rules import rule
from oss_pulse.supplychain.workflows import scan_workflows

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".oss-pulse",
    ".idea",
}
MAX_FILES = 50_000
MAX_BYTES = 5_000_000
NPM_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare")


def _jsonc(text: str):
    """Parse VS Code-style JSON with comments and trailing commas."""
    text = re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", text, flags=re.S))
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def scan_vscode(root: Path) -> list[Hit]:
    hits = []
    tasks = root / ".vscode" / "tasks.json"
    if tasks.is_file():
        raw = tasks.read_text(errors="replace")
        try:
            doc = _jsonc(raw)
        except ValueError:
            doc = {}
            if "folderOpen" in raw:  # unparseable but clearly trying to auto-run
                hits.append(Hit("AUTO-VSCODE", ".vscode/tasks.json", 1, "runOn: folderOpen"))
        for task in doc.get("tasks", []) if isinstance(doc, dict) else []:
            if (task.get("runOptions") or {}).get("runOn") == "folderOpen":
                cmd = " ".join(str(x) for x in [task.get("command", ""), *task.get("args", [])])
                for os_key in ("windows", "linux", "osx"):
                    cmd += " " + str((task.get(os_key) or {}).get("command", ""))
                line = raw.count("\n", 0, raw.find("folderOpen")) + 1
                hits.append(
                    Hit(
                        "AUTO-VSCODE",
                        ".vscode/tasks.json",
                        line,
                        f"{task.get('label', '?')}: {cmd.strip()[:120]}",
                    )
                )
    settings = root / ".vscode" / "settings.json"
    if settings.is_file():
        raw = settings.read_text(errors="replace")
        if re.search(r'"task\.allowAutomaticTasks"\s*:\s*"on"', raw):
            hits.append(
                Hit(
                    "AUTO-VSCODE-SETTINGS",
                    ".vscode/settings.json",
                    raw.count("\n", 0, raw.find("allowAutomaticTasks")) + 1,
                    '"task.allowAutomaticTasks": "on"',
                )
            )
    return hits


def scan_package_json(root: Path, path: Path) -> list[Hit]:
    rel = str(path.relative_to(root))
    try:
        doc = json.loads(path.read_text(errors="replace"))
    except ValueError:
        return []
    hits = []
    scripts = doc.get("scripts") or {} if isinstance(doc, dict) else {}
    for hook in NPM_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str):
            continue
        dangerous = any(RE[k].search(cmd) for k in ("dl_shell", "dl_ps", "exfil")) or re.search(
            r"\b(?:curl|wget)\b|node\s+-e|base64\s+-d|eval\b", cmd
        )
        hits.append(
            Hit("AUTO-NPM-NET" if dangerous else "AUTO-NPM", rel, 1, f'"{hook}": "{cmd[:120]}"')
        )
    if isinstance(doc, dict) and ("husky" in doc or "simple-git-hooks" in doc):
        hits.append(Hit("AUTO-HOOK", rel, 1, "git hooks configured via package.json"))
    return hits


def scan_hooks(root: Path) -> list[Hit]:
    hits = []
    for d in (".husky", ".githooks"):
        for p in sorted((root / d).glob("*")) if (root / d).is_dir() else []:
            if p.is_file() and not p.name.startswith(("_", ".")):
                hits.append(Hit("AUTO-HOOK", str(p.relative_to(root)), 1, f"{d} hook: {p.name}"))
    hooks = root / ".git" / "hooks"
    if hooks.is_dir():
        for p in sorted(hooks.iterdir()):
            if p.is_file() and not p.name.endswith(".sample"):
                hits.append(
                    Hit(
                        "AUTO-HOOK",
                        str(p.relative_to(root)),
                        1,
                        f"active git hook shipped with the folder: {p.name}",
                    )
                )
    return hits


def walk(root: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield p


def scan_repository(root: Path) -> list[Finding]:
    root = root.resolve()
    hits: list[Hit] = [*scan_vscode(root), *scan_hooks(root), *scan_workflows(root)]
    for p in walk(root):
        rel = str(p.relative_to(root))
        if p.name == "package.json":
            hits.extend(scan_package_json(root, p))
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            hits.extend(scan_file(rel, p.read_bytes(), context="repo"))
        except OSError:
            continue
    return [_to_finding(root, h) for h in hits]


def _to_finding(root: Path, h: Hit) -> Finding:
    r = rule(h.rule_id)
    return Finding(
        target=root.name,
        target_type="repository",
        detector="repo_scan",
        rule_id=h.rule_id,
        severity=h.effective_severity,
        category=r.category,
        title=r.title,
        detail=h.detail or r.why,
        location=f"{h.file}:{h.line}",
        evidence=h.evidence,
    )
