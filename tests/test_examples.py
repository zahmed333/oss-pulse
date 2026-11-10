"""The example gallery: every folder gets the verdict examples/README.md promises, and
none of them contains code that would harm someone who runs it."""

from pathlib import Path

import pytest

from oss_pulse.scan import run_scan
from oss_pulse.terminal import render_scan

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
HARMFUL = {"CODE-SECRETS", "CODE-EXFIL", "CODE-ENVDUMP", "CODE-DLEXEC", "CODE-CLIP"}

EXPECTED = {
    "take-home": ("hold", {"AUTO-VSCODE", "CODE-HIDDEN"}, "Don't open this folder in VS Code"),
    "npm-install-hook": ("hold", {"AUTO-NPM-NET"}, "Don't install this folder's dependencies"),
    "typosquat-requirements": ("hold", {"TYPO-001"}, "imitates a popular package"),
    "hijackable-workflow": ("hold", {"GHA-PRT", "GHA-INJECT"}, "Don't merge or run these"),
    "clean-project": ("clear", set(), "No rule matched"),
}


def test_every_example_is_listed():
    folders = {p.name for p in EXAMPLES.iterdir() if p.is_dir()}
    assert folders == set(EXPECTED)
    index = (EXAMPLES / "README.md").read_text()
    assert all(f"]({name})" in index for name in EXPECTED)


@pytest.mark.parametrize("name", EXPECTED)
def test_example_gets_its_verdict_and_stays_harmless(name):
    verdict, rules, headline = EXPECTED[name]
    findings = run_scan(EXAMPLES / name).findings
    found = {f.rule_id for f in findings}
    text = render_scan(findings, name)
    assert text.startswith(verdict), text
    assert headline in text.splitlines()[0]
    assert rules <= found
    assert not HARMFUL & found, f"{name} must not contain working attack code"


def test_typosquat_example_cannot_be_installed():
    lines = (EXAMPLES / "typosquat-requirements" / "requirements.txt").read_text().splitlines()
    lookalikes = [ln for ln in lines if ln.startswith(("reqeusts", "python-dateutils"))]
    assert lookalikes and all("+oss.pulse.demo" in ln for ln in lookalikes)
