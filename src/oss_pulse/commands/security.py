"""The supply-chain commands: check, scan and rules."""

from __future__ import annotations

from pathlib import Path

import typer

FAIL_ON_LEVELS = ("critical", "high", "medium", "never")

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
) -> None:
    """Assess supply-chain risk of your project's dependencies."""
    from oss_pulse.check import SEVERITY, render_json, render_markdown, run_check

    _validate_fail_on(fail_on)
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
) -> None:
    """Read an untrusted repository before you open or install it.

    Catches auto-run VS Code tasks, npm install hooks, malicious setup.py/.pth files,
    obfuscated or hidden payloads, credential/wallet stealers, exfiltration endpoints,
    typosquatted dependencies and unsafe GitHub Actions workflows.
    """
    from oss_pulse.scan import render_scan_json, render_scan_markdown, run_scan
    from oss_pulse.supplychain.findings import SEVERITY_RANK

    _validate_fail_on(fail_on)
    result = run_scan(path, ignore_file=ignore_file)
    md = render_scan_markdown(result)
    typer.echo(md)
    if markdown:
        markdown.write_text(md)
    if json_out:
        json_out.write_text(render_scan_json(result))
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


def _validate_fail_on(value: str) -> None:
    if value not in FAIL_ON_LEVELS:
        raise typer.BadParameter(f"--fail-on must be one of: {', '.join(FAIL_ON_LEVELS)}")
