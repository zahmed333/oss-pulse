"""`oss-pulse check`: supply-chain risk of a project's dependencies.

fetch -> detect -> store -> decide -> report. Every source except PyPI is optional: when
one is unreachable the check still runs and the report names what is missing.
"""

from oss_pulse.check.pipeline import run_check
from oss_pulse.check.report import render_json, render_markdown
from oss_pulse.check.result import LEVELS, SEVERITY, CheckResult
from oss_pulse.check.versions import version_facts

__all__ = [
    "LEVELS",
    "SEVERITY",
    "CheckResult",
    "render_json",
    "render_markdown",
    "run_check",
    "version_facts",
]
