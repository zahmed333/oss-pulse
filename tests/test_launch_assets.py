"""The launch assets have to stay true to the code they show.

`docs/brand/demo.svg` is generated from a real run against `examples/take-home`, and the
README shows it as the first thing a visitor sees. If the fixture stops tripping the
rules, the recording becomes a lie, so this test fails instead of letting it rot.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "examples" / "take-home"


def scan() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", "from oss_pulse.cli import app; app()", "scan", str(FIXTURE)],
        cwd=REPO,
        env={"NO_COLOR": "1", "PYTHONPATH": str(REPO / "src"), "PYTHONIOENCODING": "utf-8"},
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_the_demo_fixture_holds() -> None:
    result = scan()
    assert result.returncode == 1, result.stdout
    assert "Don't open this folder in VS Code" in result.stdout
    assert "AUTO-VSCODE" in result.stdout
    assert "CODE-HIDDEN" in result.stdout


def test_the_demo_svg_is_committed_and_animated() -> None:
    svg = (REPO / "docs" / "brand" / "demo.svg").read_text(encoding="utf-8")
    assert "<animate" in svg
    assert "hold" in svg
    assert "AUTO-VSCODE" in svg


def test_the_installer_is_valid_shell() -> None:
    result = subprocess.run(
        ["bash", "-n", str(REPO / "install.sh")], capture_output=True, text=True, encoding="utf-8"
    )
    assert result.returncode == 0, result.stderr


def test_the_readme_leads_with_the_demo() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert readme.index("docs/brand/demo.svg") < readme.index("## Why")
    assert "install.sh" in readme
