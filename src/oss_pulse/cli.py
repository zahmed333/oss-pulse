"""`oss-pulse` command line."""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from oss_pulse.commands.easy import easy, run_here
from oss_pulse.commands.lakehouse import lakehouse
from oss_pulse.commands.security import security

app = typer.Typer(
    help="oss-pulse: check a folder or your Python dependencies for supply-chain malware "
    "before you run them.",
    invoke_without_command=True,
)
app.add_typer(security)
app.add_typer(easy)
app.add_typer(lakehouse)


@app.callback()
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show what oss-pulse is doing"),
) -> None:
    """Run with no command to check the current folder: what would run if you opened it,
    and, when it has a requirements.txt or pyproject.toml, the packages it would install."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    )
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
    if ctx.invoked_subcommand is None:
        raise typer.Exit(code=run_here(Path(".")))


if __name__ == "__main__":
    app()
