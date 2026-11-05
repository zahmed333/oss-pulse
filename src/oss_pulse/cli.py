"""`oss-pulse` command line."""

from __future__ import annotations

import logging

import typer

from oss_pulse.commands.lakehouse import lakehouse
from oss_pulse.commands.security import security

app = typer.Typer(
    help="oss-pulse: check a folder or your Python dependencies for supply-chain malware "
    "before you run them.",
    no_args_is_help=True,
)
app.add_typer(security)
app.add_typer(lakehouse)


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    )


if __name__ == "__main__":
    app()
