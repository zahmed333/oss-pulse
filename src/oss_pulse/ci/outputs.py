"""Write every requested CI output for one scan or check."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from oss_pulse.ci import providers
from oss_pulse.ci.finding import CiFinding
from oss_pulse.ci.junit import render_junit
from oss_pulse.ci.sarif import render_sarif


def tool_version() -> str:
    try:
        return version("oss-pulse")
    except PackageNotFoundError:
        return "0.0.0"


@dataclass(frozen=True)
class CiOutputs:
    junit: Path | None = None
    sarif: Path | None = None
    annotations: str = "auto"

    def provider(self) -> str | None:
        if self.annotations == "none":
            return None
        return providers.detect() if self.annotations == "auto" else self.annotations

    def write(
        self, findings: list[CiFinding], *, suite: str, fail_on: str, markdown: Path | None
    ) -> list[str]:
        if self.junit:
            self.junit.write_text(render_junit(findings, suite=suite, fail_on=fail_on))
        if self.sarif:
            self.sarif.write_text(render_sarif(findings, version=tool_version()))
        provider = self.provider()
        if provider is None:
            return []
        lines = providers.annotations(findings, provider, fail_on) if provider != "generic" else []
        summary = str(markdown.resolve()) if markdown else None
        return lines + providers.summary_commands(provider, summary)
