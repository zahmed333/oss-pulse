"""The commands for getting started: plain `oss-pulse`, `init` and `accept`."""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import typer

from oss_pulse.scan import IGNORE_FILE

DEPENDENCY_FILES = ("requirements.txt", "pyproject.toml")
RELEASE = "0ee47501f69e4b8b7f2d916700467f2dcfaf4308"

easy = typer.Typer()


def check_extra_installed() -> bool:
    return all(importlib.util.find_spec(m) for m in ("duckdb", "pyarrow", "dbt"))


def run_here(folder: Path) -> int:
    """What plain `oss-pulse` does: scan this folder, then check its dependencies."""
    from oss_pulse.scan import run_scan
    from oss_pulse.supplychain.findings import SEVERITY_RANK
    from oss_pulse.terminal import render_scan, use_colour

    result = run_scan(folder)
    typer.echo(render_scan(result.findings, folder.resolve().name, colour=use_colour()), nl=False)
    status = int(any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"] for f in result.findings))
    if (folder / IGNORE_FILE).is_file():
        typer.echo(
            f"\nThis folder has its own {IGNORE_FILE}; it was not applied. If this is your "
            f"own project, run: oss-pulse scan . --ignore-file {IGNORE_FILE}",
            err=True,
        )

    dependency_file = next((folder / n for n in DEPENDENCY_FILES if (folder / n).is_file()), None)
    if dependency_file is None:
        return status
    if not check_extra_installed():
        typer.echo(
            f"\nTo also check the packages in {dependency_file.name}: "
            "pip install 'oss-pulse[check]'",
            err=True,
        )
        return status
    from oss_pulse.check import SEVERITY, run_check
    from oss_pulse.terminal import render_check

    typer.echo("")
    checked = run_check(dependency_file, folder.resolve() / ".oss-pulse")
    typer.echo(render_check(checked, colour=use_colour()), nl=False)
    return max(status, int(checked.worst() >= SEVERITY["high"]))


GITHUB_WORKFLOW = f"""name: oss-pulse

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "23 7 * * 1"

permissions:
  contents: read
  pull-requests: write

jobs:
  oss-pulse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: zahmed333/oss-pulse@{RELEASE}
        with:
          dependency-file: {{dependency_file}}
          fail-on: high
          ignore-file: {{ignore_file}}
"""

AZURE_PIPELINE = f"""trigger:
  branches: {{{{ include: [main] }}}}
pr:
  branches: {{{{ include: ['*'] }}}}
schedules:
  - cron: "23 7 * * 1"
    displayName: weekly, because new advisories appear without code changes
    branches: {{{{ include: [main] }}}}
    always: true

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
  - bash: python -m pip install --quiet "oss-pulse[check] @ git+https://github.com/zahmed333/oss-pulse@{RELEASE}"
    displayName: install oss-pulse
  - bash: |
      mkdir -p "$(Agent.TempDirectory)/oss-pulse"
      status=0
      oss-pulse scan . --fail-on high {{ignore_arg}}\\
        --junit "$(Agent.TempDirectory)/oss-pulse/scan.junit.xml" || status=$?
      {{check_line}}
      exit $status
    displayName: oss-pulse
  - task: PublishTestResults@2
    condition: succeededOrFailed()
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: $(Agent.TempDirectory)/oss-pulse/*.junit.xml
      testRunTitle: oss-pulse
"""

GITLAB_JOB = f"""include:
  - remote: https://raw.githubusercontent.com/zahmed333/oss-pulse/{RELEASE}/ci/gitlab/oss-pulse.gitlab-ci.yml

variables:
  OSS_PULSE_DEPENDENCY_FILE: {{dependency_file}}
  OSS_PULSE_FAIL_ON: high
"""

TARGETS = {
    "github": Path(".github/workflows/oss-pulse.yml"),
    "azure": Path("azure-pipelines-oss-pulse.yml"),
    "gitlab": Path(".gitlab/oss-pulse.gitlab-ci.yml"),
}


def detect_ci(folder: Path) -> str:
    if (folder / ".github").is_dir():
        return "github"
    if any(folder.glob("azure-pipelines*.yml")) or (folder / ".azure-pipelines").is_dir():
        return "azure"
    if (folder / ".gitlab-ci.yml").is_file():
        return "gitlab"
    return "github"


def render_ci(ci: str, dependency_file: str) -> str:
    if ci == "github":
        return GITHUB_WORKFLOW.format(
            dependency_file=dependency_file or "''", ignore_file=IGNORE_FILE
        )
    if ci == "azure":
        ignore_arg = f"--ignore-file {IGNORE_FILE} "
        out = "$(Agent.TempDirectory)/oss-pulse"
        check_line = (
            f'oss-pulse check {dependency_file} --fail-on high --data-dir "{out}/lake" '
            f'--junit "{out}/check.junit.xml" || {{ rc=$?; [ $rc -gt $status ] && status=$rc; }}'
            if dependency_file
            else ":"
        )
        return AZURE_PIPELINE.format(ignore_arg=ignore_arg, check_line=check_line)
    return GITLAB_JOB.format(dependency_file=dependency_file or "requirements.txt")


@easy.command("init")
def init(
    ci: str = typer.Option(
        None, "--ci", help="github, azure or gitlab (default: detected from the repository)"
    ),
    folder: Path = typer.Option(Path("."), "--path", file_okay=False, help="Repository root"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
) -> None:
    """Add oss-pulse to this repository's CI: pull requests, pushes to main, and weekly."""
    ci = ci or detect_ci(folder)
    if ci not in TARGETS:
        raise typer.BadParameter("--ci must be github, azure or gitlab")
    target = folder / TARGETS[ci]
    if target.exists() and not force:
        typer.echo(f"error: {target} already exists; use --force to replace it", err=True)
        raise typer.Exit(code=2)
    dependency_file = next((n for n in DEPENDENCY_FILES if (folder / n).is_file()), "")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_ci(ci, dependency_file))
    typer.echo(f"wrote {target}")
    next_steps = {
        "github": "Commit it; it runs on the next pull request.",
        "azure": "Commit it, then in Azure DevOps create a pipeline from this file "
        "(Pipelines > New pipeline > Existing YAML file).",
        "gitlab": f"Commit it and add it to .gitlab-ci.yml:  include: - local: {TARGETS['gitlab']}",
    }
    typer.echo(next_steps[ci])


@easy.command("accept")
def accept(
    pattern: str = typer.Argument(
        ..., help="A path (glob) or a rule id, e.g. tests/fixtures/* or GHA-PERMS"
    ),
    reason: str = typer.Option(..., "--reason", "-r", help="Why this finding is acceptable"),
    folder: Path = typer.Option(Path("."), "--path", file_okay=False, help="Repository root"),
) -> None:
    """Accept a reviewed finding in your own repository, with a reason and a date."""
    ignore_file = folder / IGNORE_FILE
    stamp = datetime.now(UTC).date().isoformat()
    entry = f"# {stamp}: {reason.strip()}\n{pattern.strip()}\n"
    existing = ignore_file.read_text() if ignore_file.is_file() else ""
    separator = "" if not existing or existing.endswith("\n") else "\n"
    ignore_file.write_text(existing + separator + entry)
    typer.echo(f"added {pattern} to {ignore_file}")
    typer.echo(
        f"It applies when you pass it explicitly: oss-pulse scan . --ignore-file {IGNORE_FILE}. "
        "Pipelines from 'oss-pulse init' already do."
    )
