"""The supply-chain commands: check, scan and rules."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_pulse.ci.outputs import CiOutputs

FAIL_ON_LEVELS = ("critical", "high", "medium", "never")
ANNOTATION_MODES = ("auto", "azure", "github", "gitlab", "jenkins", "generic", "none")

JUNIT_OPTION = typer.Option(None, "--junit", help="Also write JUnit XML (test results in any CI)")
SARIF_OPTION = typer.Option(None, "--sarif", help="Also write SARIF 2.1.0 (code scanning)")
ANNOTATIONS_OPTION = typer.Option(
    "auto",
    "--annotations",
    help="Log annotations for the CI system: auto (detected), azure, github, gitlab, "
    "jenkins, generic or none",
)

security = typer.Typer()


@security.command("check")
def check(
    dependency_file: Path = typer.Argument(
        Path("pyproject.toml"),
        exists=True,
        dir_okay=False,
        help="pyproject.toml or requirements.txt",
    ),
    days: int = typer.Option(90, help="Activity window in days"),
    fail_on: str = typer.Option(
        "never", help="Exit 1 if any dependency is at/above: critical | high | medium | never"
    ),
    internal: list[str] = typer.Option(
        [], "--internal", help="Private package name to guard against dependency confusion"
    ),
    scan_artifacts: bool = typer.Option(True, help="Scan release sdists/wheels for malware"),
    strict: bool = typer.Option(False, help="Fail if any data source could not be checked"),
    markdown: Path = typer.Option(None, help="Also write the Markdown report here"),
    json_out: Path = typer.Option(None, "--json", help="Also write the JSON report here"),
    include_optional: bool = typer.Option(True, help="Include extras and dependency groups"),
    data_dir: Path = typer.Option(Path(".oss-pulse"), help="Local lakehouse for this check"),
    junit: Path = JUNIT_OPTION,
    sarif: Path = SARIF_OPTION,
    annotations: str = ANNOTATIONS_OPTION,
) -> None:
    """Assess supply-chain risk of your project's dependencies."""
    from oss_pulse.check import SEVERITY, render_json, render_markdown, run_check
    from oss_pulse.ci.finding import from_check

    _validate_fail_on(fail_on)
    _validate_annotations(annotations)
    result = run_check(
        dependency_file,
        data_dir.resolve(),
        days=days,
        include_optional=include_optional,
        internal=internal,
        scan_artifacts=scan_artifacts,
    )
    md = render_markdown(result)
    typer.echo(md)
    if markdown:
        markdown.write_text(md)
    if json_out:
        json_out.write_text(render_json(result))
    _write_ci_outputs(
        from_check(result.findings, dependency_file),
        CiOutputs(junit, sarif, annotations),
        suite=f"oss-pulse check {dependency_file.name}",
        fail_on=fail_on,
        markdown=markdown,
    )
    if strict and result.degraded:
        typer.echo("failing (--strict): some signals could not be collected", err=True)
        raise typer.Exit(code=2)
    if fail_on != "never" and result.worst() >= SEVERITY[fail_on]:
        typer.echo(f"failing: at least one dependency is at or above '{fail_on}' risk", err=True)
        raise typer.Exit(code=1)


@security.command("scan")
def scan(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        file_okay=False,
        help="Repository or folder to inspect (nothing is executed)",
    ),
    fail_on: str = typer.Option("never", help="critical | high | medium | never"),
    ignore_file: Path = typer.Option(
        None,
        exists=True,
        dir_okay=False,
        help="Your own list of reviewed paths or rule ids to suppress. A file inside the "
        "scanned folder is never applied unless you pass it here.",
    ),
    markdown: Path = typer.Option(None, help="Also write the Markdown report here"),
    json_out: Path = typer.Option(None, "--json", help="Also write the JSON report here"),
    junit: Path = JUNIT_OPTION,
    sarif: Path = SARIF_OPTION,
    annotations: str = ANNOTATIONS_OPTION,
) -> None:
    """Read an untrusted repository before you open or install it.

    Catches auto-run VS Code tasks, npm install hooks, malicious setup.py/.pth files,
    obfuscated or hidden payloads, credential/wallet stealers, exfiltration endpoints,
    typosquatted dependencies and unsafe GitHub Actions workflows.
    """
    from oss_pulse.ci.finding import from_scan
    from oss_pulse.scan import render_scan_json, render_scan_markdown, run_scan
    from oss_pulse.supplychain.findings import SEVERITY_RANK

    _validate_fail_on(fail_on)
    _validate_annotations(annotations)
    result = run_scan(path, ignore_file=ignore_file)
    md = render_scan_markdown(result)
    typer.echo(md)
    if markdown:
        markdown.write_text(md)
    if json_out:
        json_out.write_text(render_scan_json(result))
    _write_ci_outputs(
        from_scan(result.findings, result.root),
        CiOutputs(junit, sarif, annotations),
        suite=f"oss-pulse scan {result.root.name}",
        fail_on=fail_on,
        markdown=markdown,
    )
    if fail_on != "never" and any(
        SEVERITY_RANK[f.severity] >= SEVERITY_RANK[fail_on] for f in result.findings
    ):
        typer.echo(f"failing: findings at or above '{fail_on}'", err=True)
        raise typer.Exit(code=1)


@security.command("rules")
def rules() -> None:
    """List every detection rule, why it matters and which real attack used it."""
    from oss_pulse.supplychain.rules import RULES

    for r in RULES.values():
        typer.echo(f"{r.id:<20} {r.severity:<9} {r.category:<20} {r.title}")
        typer.echo(f"{'':<20} {r.why}")
        if r.seen_in:
            typer.echo(f"{'':<20} seen in: {r.seen_in}")
        typer.echo("")


@security.command("pr-comment")
def pr_comment(
    report: Path = typer.Argument(..., exists=True, dir_okay=False, help="Markdown report"),
) -> None:
    """Post or update the oss-pulse comment on the current Azure DevOps pull request.

    Run it in a pull-request build with SYSTEM_ACCESSTOKEN mapped into the step's
    environment. On GitHub, the oss-pulse Action posts the comment itself.
    """
    import os

    import httpx

    from oss_pulse.ci.pull_request import AzurePullRequest, NotAPullRequestBuild, upsert_comment

    try:
        pr = AzurePullRequest.from_env(os.environ)
    except NotAPullRequestBuild as exc:
        typer.echo(f"not an Azure DevOps pull-request build ({exc}); no comment posted", err=True)
        return
    with httpx.Client(timeout=30.0) as client:
        outcome = upsert_comment(pr, report.read_text(), client)
    typer.echo(f"pull request comment {outcome}", err=True)


def _write_ci_outputs(findings, outputs, *, suite: str, fail_on: str, markdown) -> None:
    for line in outputs.write(findings, suite=suite, fail_on=fail_on, markdown=markdown):
        typer.echo(line)


def _validate_annotations(value: str) -> None:
    if value not in ANNOTATION_MODES:
        raise typer.BadParameter(f"--annotations must be one of: {', '.join(ANNOTATION_MODES)}")


def _validate_fail_on(value: str) -> None:
    if value not in FAIL_ON_LEVELS:
        raise typer.BadParameter(f"--fail-on must be one of: {', '.join(FAIL_ON_LEVELS)}")
