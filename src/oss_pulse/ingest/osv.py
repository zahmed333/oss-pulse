"""Known vulnerabilities from OSV.dev (aggregates GitHub Security Advisories, PyPA
advisory-db, and others). https://google.github.io/osv.dev/api/

We query by *package* (not version) and keep every advisory with its full list of
affected versions. That lets dbt answer two different questions:

  * is the version a fresh install resolves to vulnerable right now?   (urgent)
  * does your version specifier still *allow* a vulnerable version?   (tighten it)
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pyarrow as pa
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from oss_pulse.config import Settings
from oss_pulse.endpoints import url
from oss_pulse.ingest.io import atomic_write_json, atomic_write_table
from oss_pulse.ingest.schema import OSV_VULNERABILITIES

log = logging.getLogger(__name__)

OSV_API = url("osv")


def normalize_version(v: str) -> str:
    try:
        return str(Version(v))
    except InvalidVersion:
        return v


def _severity(vuln: dict) -> str:
    label = str((vuln.get("database_specific") or {}).get("severity") or "").lower()
    if label in {"critical", "high", "low"}:
        return label
    if label in {"moderate", "medium"}:
        return "medium"
    # Fall back to the CVSS base score when only a vector is present (GHSA usually has both)
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        try:
            num = float(score)
        except ValueError:
            continue
        return "critical" if num >= 9 else "high" if num >= 7 else "medium" if num >= 4 else "low"
    return "unknown"


def _ts(v: str | None) -> datetime | None:
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None


def vulns_to_rows(package: str, vulns: list[dict], ingested_at: datetime) -> list[dict]:
    name = canonicalize_name(package)
    rows = []
    for v in vulns:
        affected, fixed = set(), set()
        for a in v.get("affected") or []:
            pkg = a.get("package") or {}
            if pkg.get("ecosystem") != "PyPI" or canonicalize_name(pkg.get("name", "")) != name:
                continue
            affected.update(normalize_version(x) for x in a.get("versions") or [])
            for r in a.get("ranges") or []:
                fixed.update(
                    normalize_version(e["fixed"]) for e in r.get("events", []) if "fixed" in e
                )
        malicious = v["id"].startswith("MAL-")
        if not affected and not malicious:
            continue
        rows.append(
            {
                "pypi_package": name,
                "vuln_id": v["id"],
                "aliases": v.get("aliases") or [],
                "summary": (v.get("summary") or v.get("details") or "")[:300],
                "severity": _severity(v),
                "published_at": _ts(v.get("published")),
                "modified_at": _ts(v.get("modified")),
                "is_withdrawn": bool(v.get("withdrawn")),
                "is_malicious": malicious,
                "affected_versions": sorted(affected),
                "fixed_versions": sorted(
                    fixed, key=lambda s: Version(s) if _valid(s) else Version("0")
                ),
                "_ingested_at": ingested_at,
            }
        )
    return rows


def _valid(v: str) -> bool:
    try:
        Version(v)
        return True
    except InvalidVersion:
        return False


def fetch_vulns(settings: Settings, package: str, client: httpx.Client, day: date) -> list[dict]:
    name = canonicalize_name(package)
    cached = settings.raw_dir / "osv" / f"{day:%Y-%m-%d}" / f"{name}.json"
    if cached.exists():
        return json.loads(cached.read_text())
    vulns, token = [], None
    while True:
        body = {"package": {"name": name, "ecosystem": "PyPI"}}
        if token:
            body["page_token"] = token
        resp = client.post(f"{OSV_API}/v1/query", json=body)
        resp.raise_for_status()
        doc = resp.json()
        vulns.extend(doc.get("vulns") or [])
        token = doc.get("next_page_token")
        if not token:
            break
    atomic_write_json(vulns, cached)  # type: ignore[arg-type]
    return vulns


def ingest_osv(
    settings: Settings,
    packages: list[str],
    day: date | None = None,
    client: httpx.Client | None = None,
) -> Path:
    day = day or datetime.now(UTC).date()
    ingested_at = datetime.now(UTC)
    own = client is None
    client = client or httpx.Client(timeout=30.0)
    rows: list[dict] = []
    try:
        for package in packages:
            rows.extend(
                vulns_to_rows(package, fetch_vulns(settings, package, client, day), ingested_at)
            )
    finally:
        if own:
            client.close()
    path = settings.bronze_dir / "osv" / f"snapshot_date={day:%Y-%m-%d}" / "part-0.parquet"
    atomic_write_table(pa.Table.from_pylist(rows, schema=OSV_VULNERABILITIES), path)
    log.info("osv: %d advisories across %d packages", len(rows), len(packages))
    return path
