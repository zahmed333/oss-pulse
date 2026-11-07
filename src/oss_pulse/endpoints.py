"""Every external service oss-pulse talks to, and how to point it somewhere else.

Each URL can be overridden with an environment variable, for an internal PyPI mirror,
GitHub Enterprise Server or an approved proxy. HTTP clients also honour HTTPS_PROXY,
NO_PROXY and SSL_CERT_FILE, so a corporate proxy and its certificate work as they are.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Endpoint:
    key: str
    env_var: str
    default: str
    used_for: str
    if_unreachable: str

    @property
    def url(self) -> str:
        return os.getenv(self.env_var, self.default).rstrip("/")


ENDPOINTS = {
    e.key: e
    for e in (
        Endpoint(
            "pypi",
            "OSS_PULSE_PYPI_URL",
            "https://pypi.org/pypi",
            "package metadata and release files",
            "check cannot run",
        ),
        Endpoint(
            "integrity",
            "OSS_PULSE_PYPI_INTEGRITY_URL",
            "https://pypi.org/integrity",
            "Trusted Publishing attestations (PEP 740)",
            "provenance rules are not checked",
        ),
        Endpoint(
            "files",
            "OSS_PULSE_PYPI_FILES_URL",
            "https://files.pythonhosted.org",
            "release files for the malware scan (links come from the PyPI metadata)",
            "release files are not scanned",
        ),
        Endpoint(
            "github",
            "OSS_PULSE_GITHUB_API_URL",
            "https://api.github.com",
            "repository activity, archived flag and tags",
            "maintenance signals and the git-tag rule are not checked",
        ),
        Endpoint(
            "osv",
            "OSS_PULSE_OSV_URL",
            "https://api.osv.dev",
            "known vulnerabilities and known-malicious packages",
            "advisories are not checked",
        ),
        Endpoint(
            "scorecard",
            "OSS_PULSE_SCORECARD_URL",
            "https://api.securityscorecards.dev",
            "OpenSSF Scorecard results",
            "Scorecard results are not shown",
        ),
        Endpoint(
            "popular",
            "OSS_PULSE_POPULAR_LIST_URL",
            "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json",
            "a fresh list of popular package names for lookalike checks",
            "the list bundled with oss-pulse is used",
        ),
    )
}

SKIPPABLE = ("github", "osv", "scorecard", "integrity", "files")


def url(key: str) -> str:
    return ENDPOINTS[key].url


def skipped_from_env() -> set[str]:
    raw = os.getenv("OSS_PULSE_SKIP", "")
    return {part.strip() for part in raw.split(",") if part.strip()}
