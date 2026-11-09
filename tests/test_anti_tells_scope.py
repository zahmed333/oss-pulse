"""scripts/anti_tells.py has to see copy wherever it lives.

The first version read string literals in four files under src/, so every "no new copy
hits" check was empty for the scanner modules, the Action's scripts and the SQL that
writes report text. Each case here copies one real file into an empty layout, saves the
linter's output on the untouched copy as the baseline, adds an emoji to a string literal
and expects exit 1 naming that file. The baseline step shows the hit comes from the new
literal, whatever the file already contains.

The Action's shell and JavaScript are copied from action/ once they live there, and from
the steps embedded in action.yml until then.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
LINTER = REPO / "scripts" / "anti_tells.py"
BASELINE = REPO / "docs" / "research" / "anti-tells-2bc3e4f.txt"
ROCKET = "\U0001f680"

spec = importlib.util.spec_from_file_location("anti_tells", LINTER)
anti_tells = importlib.util.module_from_spec(spec)
spec.loader.exec_module(anti_tells)


def action_scripts() -> dict[str, str]:
    action_dir = REPO / "action"
    found = {}
    for pattern in ("*.sh", "*.js"):
        files = sorted(p for p in action_dir.glob(pattern) if ".test." not in p.name)
        if files:
            found[f"action/{files[0].name}"] = files[0].read_text(encoding="utf-8")
    steps = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))["runs"]["steps"]
    shell = [s["run"] for s in steps if s.get("shell") == "bash" and "run" in s]
    scripts = [s["with"]["script"] for s in steps if "script" in (s.get("with") or {})]
    if shell:
        found.setdefault("action/run.sh", max(shell, key=len))
    if scripts:
        found.setdefault("action/comment.js", max(scripts, key=len))
    return found


ACTION = action_scripts()
CASES = [
    (
        "src/oss_pulse/supplychain/repo_scan.py",
        (REPO / "src/oss_pulse/supplychain/repo_scan.py").read_text(encoding="utf-8"),
        f'\nDONE = "scan finished {ROCKET}"\n',
    ),
    *[
        (rel, text, f'\necho "done {ROCKET}"\n' if rel.endswith(".sh") else
         f'\ncore.notice("done {ROCKET}");\n')
        for rel, text in sorted(ACTION.items())
    ],
    (
        "transform/models/marts/mart_dependency_risk.sql",
        (REPO / "transform/models/marts/mart_dependency_risk.sql").read_text(encoding="utf-8"),
        f"\nselect 'checked {ROCKET}' as note\n",
    ),
]  # fmt: skip


def lint(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(LINTER), *args, str(repo)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_action_has_a_shell_and_a_javascript_script():
    assert {Path(rel).suffix for rel in ACTION} == {".sh", ".js"}


@pytest.mark.parametrize("rel, original, addition", CASES, ids=[c[0] for c in CASES])
def test_emoji_added_to_a_copy_is_a_new_hit(tmp_path, rel, original, addition):
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    target.write_text(original, encoding="utf-8")
    baseline = tmp_path / "baseline.txt"
    baseline.write_text(lint(tmp_path).stdout, encoding="utf-8")
    assert lint(tmp_path, "--baseline", str(baseline)).returncode == 0

    target.write_text(original + addition, encoding="utf-8")
    result = lint(tmp_path, "--baseline", str(baseline))
    assert result.returncode == 1, result.stdout
    new = [line for line in result.stdout.splitlines() if line.startswith(f"{rel}:")]
    assert len(new) == 1 and " emoji " in new[0], result.stdout


TYPER_COMMAND = 'import typer\napp = typer.Typer()\n@app.command()\ndef go():\n    """Go now!"""\n'
SHELL_CODE = '#!/usr/bin/env bash\n# done!\nif [ ! -f "$X" ]; then exit 2; fi\n'


@pytest.mark.parametrize(
    "rel, text, flagged",
    [
        ("src/x.py", 'MSG = "Ship it!"\n', True),
        ("src/x.py", 'import re\nP = re.compile(r"(?<![ \\t])x(?!y)")\n', False),  # a pattern
        ("src/x.py", 'ON_RTD = "READTHEDOCS" in env\n', False),  # one bare word
        ("src/x.py", 'def f():\n    """Done!"""\n', False),  # a docstring
        ("src/x.py", TYPER_COMMAND, True),  # a command's docstring is its --help text
        ("dashboard/app.py", 'st.title("Pulse \U0001f680")\n', True),
        ("action/run.sh", SHELL_CODE, False),  # a shebang, a comment and a test
        ("action/run.sh", 'echo "All done!"\n', True),
        ("action/run.sh", 'cat <<EOF\nEverything is AWESOME\nEOF\n', True),  # a heredoc
        ("action/comment.js", "// posted!\nif (!ok) core.notice(`skipped ${n} forks`);\n", False),
        ("action/comment.js", "core.notice('Posted!');\n", True),
        ("transform/models/m.sql", "-- don't stop!\nselect 'it''s fine' as a\n", False),
        ("transform/models/m.sql", "select 'MALWARE DETECTED' as a\n", True),
        ("action.yml", "runs:\n  steps:\n    - name: Done!\n", True),
        ("action.yml", "description: >\n  A seamless check\n", True),  # a block scalar
        (".github/workflows/ci.yml", "steps:\n  - run: echo fine!\n", False),
        (".github/workflows/ci.yml", 'steps:\n  - run: echo "::error::Oops!"\n', True),
        ("docs/guide.md", "Run it.\n\n```\nmake it!\n```\n", False),  # inside a fence
        ("docs/research/notes.md", "It works!\n", True),
        ("tests/test_x.py", 'X = "Ship it!"\n', False),  # out of scope
        ("scripts/x.py", 'X = "Ship it!"\n', False),  # out of scope
    ],
)  # fmt: skip
def test_copy_is_flagged_and_code_is_not(tmp_path, rel, text, flagged):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    hits, errors = anti_tells.collect(tmp_path)
    assert not errors
    assert bool(hits) is flagged, hits


def test_baseline_ignores_moved_lines_and_catches_edited_ones(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(f"# x\n\nStatus {ROCKET} done\n", encoding="utf-8")
    baseline = tmp_path / "baseline.txt"
    baseline.write_text(lint(tmp_path).stdout, encoding="utf-8")

    readme.write_text(f"# x\n\nintro\n\nStatus {ROCKET} done\n", encoding="utf-8")
    assert lint(tmp_path, "--baseline", str(baseline)).returncode == 0

    readme.write_text(f"# x\n\nStatus {ROCKET} finished\n", encoding="utf-8")
    edited = lint(tmp_path, "--baseline", str(baseline))
    assert edited.returncode == 1
    assert edited.stdout.startswith("README.md:3 ")


def test_unreadable_python_exits_2(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "broken.py").write_text("def (:\n", encoding="utf-8")
    result = lint(tmp_path)
    assert result.returncode == 2
    assert "can't read src/broken.py" in result.stderr


def test_committed_baseline_reads_back_in_full():
    text = BASELINE.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    summary = re.fullmatch(r"(\d+) hits?: .+", lines[-1])
    assert summary, lines[-1]
    assert all(anti_tells.HIT_LINE.match(line) for line in lines[:-1])
    assert sum(anti_tells.read_baseline(BASELINE).values()) == int(summary[1]) == len(lines) - 1
