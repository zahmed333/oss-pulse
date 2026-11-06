"""Detect the CI system and write findings as its native log annotations.

Annotation lines are parsed as commands by the CI agent, so every value taken from a
scanned file is escaped with that system's own rules before it is printed.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from oss_pulse.ci.finding import CiFinding
from oss_pulse.safe_text import visible

AZURE = "azure"
GITHUB = "github"
GITLAB = "gitlab"
JENKINS = "jenkins"
GENERIC = "generic"

_DETECTORS = (
    (AZURE, "TF_BUILD"),
    (GITHUB, "GITHUB_ACTIONS"),
    (GITLAB, "GITLAB_CI"),
    (JENKINS, "JENKINS_URL"),
)


def detect(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    for provider, variable in _DETECTORS:
        if env.get(variable):
            return provider
    return GENERIC


def _azure_escape(value: str) -> str:
    return (
        visible(value)
        .replace("%", "%AZP25")
        .replace(";", "%3B")
        .replace("]", "%5D")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _github_escape(value: str, *, property_value: bool = False) -> str:
    escaped = visible(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def _azure_annotation(f: CiFinding, failing: bool) -> str:
    kind = "error" if failing else "warning"
    props = [f"type={kind}", f"sourcepath={_azure_escape(f.path)}", f"code={f.rule_id}"]
    if f.line:
        props.append(f"linenumber={f.line}")
    return f"##vso[task.logissue {';'.join(props)}]{_azure_escape(f.message)}"


def _github_annotation(f: CiFinding, failing: bool) -> str:
    kind = "error" if failing else "warning"
    props = [f"file={_github_escape(f.path, property_value=True)}"]
    if f.line:
        props.append(f"line={f.line}")
    props.append(f"title={_github_escape(f'oss-pulse {f.rule_id}', property_value=True)}")
    return f"::{kind} {','.join(props)}::{_github_escape(f.message)}"


def _plain_annotation(f: CiFinding, failing: bool) -> str:
    where = f"{f.path}:{f.line}" if f.line else f.path
    kind = "error" if failing else "warning"
    return visible(f"{kind}: {where}: {f.rule_id} {f.message}")


_FORMATTERS = {
    AZURE: _azure_annotation,
    GITHUB: _github_annotation,
    GITLAB: _plain_annotation,
    JENKINS: _plain_annotation,
    GENERIC: _plain_annotation,
}


def annotations(findings: list[CiFinding], provider: str, fail_on: str) -> list[str]:
    format_line = _FORMATTERS[provider]
    return [format_line(f, f.at_or_above(fail_on)) for f in findings]


def summary_commands(provider: str, markdown_path: str | None) -> list[str]:
    if provider == AZURE and markdown_path:
        return [f"##vso[task.uploadsummary]{_azure_escape(markdown_path)}"]
    return []
