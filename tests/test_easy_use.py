"""Getting started: plain `oss-pulse`, the terminal view, `init`, `accept`, slim installs."""

import json
import subprocess
import sys
from pathlib import Path

import yaml
from typer.testing import CliRunner

from oss_pulse.cli import app
from oss_pulse.commands.easy import detect_ci, render_ci
from oss_pulse.scan import run_scan
from oss_pulse.terminal import render_scan

runner = CliRunner()


def take_home(root: Path) -> Path:
    folder = root / "take-home"
    (folder / ".vscode").mkdir(parents=True)
    task = {"label": "setup", "command": "node font.woff2", "runOptions": {"runOn": "folderOpen"}}
    (folder / ".vscode" / "tasks.json").write_text(json.dumps({"tasks": [task]}))
    return folder


def test_terminal_view_leads_with_the_verdict_and_next_steps(tmp_path):
    result = run_scan(take_home(tmp_path))
    text = render_scan(result.findings, "take-home")
    first_line = text.splitlines()[0]
    assert first_line.startswith("hold") and "Don't open this folder" in first_line
    assert "Restricted Mode" in text and "if-you-opened-it" in text
    assert "\x1b" not in text


def test_clear_folder_says_clear_is_not_an_audit(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    text = render_scan(run_scan(tmp_path).findings, tmp_path.name)
    assert text.startswith("clear") and "isn't an audit" in text


def test_plain_oss_pulse_scans_the_current_folder_and_exits_1_on_hold(tmp_path, monkeypatch):
    monkeypatch.chdir(take_home(tmp_path))
    result = runner.invoke(app, [])
    assert result.exit_code == 1
    assert result.output.startswith("hold")


def test_scan_fails_on_high_by_default(tmp_path):
    result = runner.invoke(app, ["scan", str(take_home(tmp_path)), "--annotations", "none"])
    assert result.exit_code == 1


def test_init_writes_valid_pipelines_for_each_ci(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\n")
    for ci, path in (
        ("github", ".github/workflows/oss-pulse.yml"),
        ("azure", "azure-pipelines-oss-pulse.yml"),
        ("gitlab", ".gitlab/oss-pulse.gitlab-ci.yml"),
    ):
        result = runner.invoke(app, ["init", "--ci", ci, "--path", str(tmp_path)])
        assert result.exit_code == 0, result.output
        pipeline = yaml.safe_load((tmp_path / path).read_text())
        assert pipeline
    again = runner.invoke(app, ["init", "--ci", "github", "--path", str(tmp_path)])
    assert again.exit_code == 2 and "already exists" in again.output


def test_init_detects_the_ci_system(tmp_path):
    assert detect_ci(tmp_path) == "github"
    (tmp_path / "azure-pipelines.yml").write_text("steps: []\n")
    assert detect_ci(tmp_path) == "azure"
    assert "--ignore-file .osspulseignore" in render_ci("azure", "requirements.txt")


def test_accept_records_reason_and_applies_only_when_passed(tmp_path):
    folder = take_home(tmp_path)
    result = runner.invoke(
        app, ["accept", ".vscode/*", "--reason", "our own dev task", "--path", str(folder)]
    )
    assert result.exit_code == 0
    assert "our own dev task" in (folder / ".osspulseignore").read_text()
    assert run_scan(folder, ignore_file=folder / ".osspulseignore").findings == []
    implicit = {f.rule_id for f in run_scan(folder).findings}
    assert {"AUTO-VSCODE", "EVADE-IGNORE"} <= implicit


def test_missing_ignore_file_means_nothing_accepted(tmp_path):
    folder = take_home(tmp_path)
    result = run_scan(folder, ignore_file=folder / ".osspulseignore")
    assert {f.rule_id for f in result.findings} == {"AUTO-VSCODE"}


def test_the_cli_starts_without_the_data_pipeline():
    code = (
        "import sys, oss_pulse.cli, oss_pulse.scan; "
        "print(sorted(m for m in ('duckdb', 'pyarrow', 'dbt') if m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_pre_commit_hook_is_declared():
    root = Path(__file__).resolve().parents[1]
    hooks = yaml.safe_load((root / ".pre-commit-hooks.yaml").read_text())
    assert hooks[0]["id"] == "oss-pulse-scan" and hooks[0]["pass_filenames"] is False


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and result.output.startswith("oss-pulse ")
