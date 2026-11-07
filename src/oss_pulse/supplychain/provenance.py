"""PEP 740 provenance via PyPI's Integrity API.

Packages released with Trusted Publishing carry a signed attestation that names the
exact repository and workflow that built them. We use it two ways:

  PROV-001  the previous release was attested and the resolved one is not
            -> looks like an upload with a stolen API token (Ultralytics 8.3.45/46)
  PROV-002  the attestation names a different repository than the package links to
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from oss_pulse.endpoints import url
from oss_pulse.supplychain.findings import Finding
from oss_pulse.supplychain.rules import rule

log = logging.getLogger(__name__)

INTEGRITY = url("integrity")


@dataclass(frozen=True)
class Provenance:
    attested: bool
    repository: str | None = None
    workflow: str | None = None
    publisher_kind: str | None = None


def fetch_provenance(project: str, version: str, filename: str, client: httpx.Client) -> Provenance:
    url = f"{INTEGRITY}/{project}/{version}/{filename}/provenance"
    resp = client.get(url, headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
    if resp.status_code == 404:
        return Provenance(attested=False)
    resp.raise_for_status()
    for bundle in resp.json().get("attestation_bundles") or []:
        pub = bundle.get("publisher") or {}
        return Provenance(True, pub.get("repository"), pub.get("workflow"), pub.get("kind"))
    return Provenance(attested=False)


def release_provenance(
    project: str, version: str | None, releases: dict, client: httpx.Client
) -> Provenance | None:
    files = [f for f in (releases.get(version) or []) if not f.get("yanked")] if version else []
    if not files:
        return None
    try:
        return fetch_provenance(project, version, files[0]["filename"], client)
    except httpx.HTTPError as exc:
        log.warning("provenance lookup failed for %s %s: %s", project, version, exc)
        return None


def check_provenance(
    package: str,
    resolved: Provenance | None,
    previous: Provenance | None,
    previous_version: str | None,
    linked_repo: str | None,
    version: str | None,
) -> list[Finding]:
    out = []
    if resolved and previous and previous.attested and not resolved.attested:
        r = rule("PROV-001")
        out.append(
            Finding(
                package,
                "package",
                "provenance",
                r.id,
                r.severity,
                r.category,
                r.title,
                detail=f"{previous_version} was published via Trusted Publishing from "
                f"{previous.repository}; {version} has no attestation. {r.why}",
                target_version=version,
            )
        )
    if (
        resolved
        and resolved.attested
        and resolved.repository
        and linked_repo
        and resolved.repository.lower() != linked_repo.lower()
    ):
        r = rule("PROV-002")
        out.append(
            Finding(
                package,
                "package",
                "provenance",
                r.id,
                r.severity,
                r.category,
                r.title,
                detail=f"built by {resolved.repository} ({resolved.workflow}) but PyPI "
                f"links to {linked_repo}. {r.why}",
                evidence=resolved.repository,
                target_version=version,
            )
        )
    return out
