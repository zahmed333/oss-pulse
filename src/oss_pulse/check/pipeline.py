"""The steps of one `check` run, in the order they happen."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

import duckdb
import httpx
import pyarrow as pa
from packaging.utils import canonicalize_name

from oss_pulse import endpoints
from oss_pulse.check.result import LEVELS, CheckResult
from oss_pulse.check.versions import (
    NO_FACTS,
    previous_stable_release,
    pypi_spelling,
    version_facts,
)
from oss_pulse.config import Settings, TrackedProject
from oss_pulse.ingest import github_api, osv, pypi, scorecard
from oss_pulse.ingest.dependencies import DeclaredDependency, parse_dependency_file, resolve_repo
from oss_pulse.ingest.io import atomic_write_table
from oss_pulse.ingest.schema import DEPENDENCIES
from oss_pulse.supplychain import artifacts, provenance, typosquat
from oss_pulse.supplychain.findings import SEVERITY_RANK, Finding
from oss_pulse.supplychain.findings_store import write_findings
from oss_pulse.transform import run_dbt

log = logging.getLogger(__name__)


@dataclass
class CheckRun:
    settings: Settings
    dependencies: list[DeclaredDependency]
    internal_names: set[str]
    window_days: int
    client: httpx.Client
    gh: github_api.GitHubClient | None
    skip: set[str] = field(default_factory=set)
    today: date = field(default_factory=lambda: datetime.now(UTC).date())
    pypi_docs: dict[str, dict | None] = field(default_factory=dict)
    linked_repo: dict[str, tuple[str | None, str]] = field(default_factory=dict)
    facts: dict[str, dict] = field(default_factory=dict)
    canonical_repo: dict[str, str] = field(default_factory=dict)
    repo_lookup: dict[str, str] = field(default_factory=dict)
    provenance: dict[str, provenance.Provenance | None] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    detectors_run: set[str] = field(default_factory=set)
    unavailable_signals: list[str] = field(default_factory=list)

    @property
    def public_names(self) -> list[str]:
        return [d.name for d in self.dependencies if d.name not in self.internal_names]

    def is_wanted(self, source: str, what: str) -> bool:
        if source in self.skip:
            self.unavailable_signals.append(f"{what}: skipped (--skip {source})")
            return False
        return True

    def public_releases(self):
        """(dependency, PyPI document, resolved version) for every public, resolvable dependency."""
        for dep in self.dependencies:
            doc = self.pypi_docs.get(dep.name)
            version = self.facts[dep.name]["resolved_version"]
            if doc and version and dep.name not in self.internal_names:
                yield dep, doc, version


def run_check(
    dependency_file: Path,
    data_dir: Path,
    days: int = 90,
    include_optional: bool = True,
    internal: list[str] | None = None,
    scan_artifacts: bool = True,
    gh: github_api.GitHubClient | None = None,
    http: httpx.Client | None = None,
    skip: set[str] | None = None,
) -> CheckResult:
    dependencies = parse_dependency_file(dependency_file, include_optional=include_optional)
    if not dependencies:
        raise ValueError(f"no dependencies found in {dependency_file}")
    log.info("found %d dependencies in %s", len(dependencies), dependency_file.name)

    client = http or httpx.Client(timeout=30.0, follow_redirects=True)
    run = CheckRun(
        settings=Settings(data_dir=data_dir),
        dependencies=dependencies,
        internal_names={canonicalize_name(n) for n in internal or []},
        window_days=days,
        client=client,
        gh=gh,
        skip=set(skip or ()) | endpoints.skipped_from_env(),
    )
    try:
        fetch_pypi_metadata(run)
        detect_lookalike_names(run)
        fetch_github_activity(run)
        detect_provenance_changes(run)
        if scan_artifacts and run.is_wanted("files", "release-file malware scan"):
            scan_release_files(run)
        store_in_bronze(run)
    finally:
        if http is None:
            client.close()
    store_findings(run)
    decide_risk_levels(run)
    return load_result(run, dependency_file.name)


def fetch_pypi_metadata(run: CheckRun) -> None:
    for dep in run.dependencies:
        doc = run.pypi_docs[dep.name] = pypi.fetch_document(
            run.settings, dep.name, run.client, run.today
        )
        if dep.name in run.internal_names:
            run.linked_repo[dep.name] = (None, "internal")
            run.facts[dep.name] = dict(NO_FACTS)
        else:
            run.linked_repo[dep.name] = resolve_repo(doc) if doc else (None, "not_on_pypi")
            run.facts[dep.name] = version_facts(dep.requirement, doc)


def detect_lookalike_names(run: CheckRun) -> None:
    popular = typosquat.load_popular(run.settings.raw_dir / "reference", run.client, run.today)
    run.findings += typosquat.check_names(run.public_names, popular)
    exists_on_pypi = {name: run.pypi_docs.get(name) is not None for name in run.internal_names}
    run.findings += typosquat.check_dependency_confusion(sorted(run.internal_names), exists_on_pypi)
    run.detectors_run |= {"typosquat", "dependency_confusion"}


def fetch_github_activity(run: CheckRun) -> None:
    if not run.is_wanted("github", "GitHub activity (maintenance signals)"):
        return
    repos = sorted({repo for repo, _ in run.linked_repo.values() if repo})
    try:
        run.canonical_repo = github_api.ingest_repos(
            run.settings,
            repos,
            days=run.window_days,
            gh=run.gh,
            today=run.today,
            status=run.repo_lookup,
        )
    except github_api.GitHubAPIError as exc:
        run.unavailable_signals.append(f"GitHub activity (maintenance signals): {exc}")
        return
    unreachable = [r for r in repos if run.repo_lookup.get(r, "unavailable") == "unavailable"]
    if unreachable:
        run.unavailable_signals.append(
            f"GitHub activity (maintenance signals) for {len(unreachable)} of "
            f"{len(repos)} repositories: access denied"
        )


def detect_provenance_changes(run: CheckRun) -> None:
    if not run.is_wanted("integrity", "Trusted Publishing attestations (provenance)"):
        return
    for dep, doc, version in run.public_releases():
        releases = doc.get("releases") or {}
        previous = previous_stable_release(doc, version)
        current_attestation = provenance.release_provenance(
            dep.name, pypi_spelling(doc, version), releases, run.client
        )
        previous_attestation = provenance.release_provenance(
            dep.name, pypi_spelling(doc, previous), releases, run.client
        )
        run.provenance[dep.name] = current_attestation
        linked = run.linked_repo[dep.name][0]
        run.findings += provenance.check_provenance(
            dep.name,
            current_attestation,
            previous_attestation,
            previous,
            run.canonical_repo.get(linked or "", linked),
            version,
        )
    run.detectors_run.add("provenance")


def scan_release_files(run: CheckRun) -> None:
    for dep, doc, version in run.public_releases():
        files = (doc.get("releases") or {}).get(pypi_spelling(doc, version) or "", [])
        run.findings += artifacts.scan_release(
            dep.name, version, files, run.settings.raw_dir / "artifacts", run.client
        )
    run.detectors_run.add("artifact_scan")


def store_in_bronze(run: CheckRun) -> None:
    atomic_write_table(
        pa.Table.from_pylist(
            [_dependency_row(run, dep) for dep in run.dependencies], schema=DEPENDENCIES
        ),
        run.settings.bronze_dir / "reference" / "dependencies.parquet",
    )
    pypi.write_reference(run.settings, _tracked_projects(run))
    pypi.ingest_pypi(run.settings, snapshot=run.today, packages=run.public_names, client=run.client)
    if run.is_wanted("osv", "OSV.dev (vulnerabilities, known-malicious packages)"):
        _ingest_advisories(run)
    if run.is_wanted("scorecard", "OpenSSF Scorecard"):
        scorecard.ingest_scorecard(
            run.settings, sorted(set(run.canonical_repo.values())), day=run.today, client=run.client
        )


def _ingest_advisories(run: CheckRun) -> None:
    try:
        osv.ingest_osv(run.settings, run.public_names, day=run.today, client=run.client)
    except httpx.HTTPError as exc:
        run.unavailable_signals.append(
            f"OSV.dev (vulnerabilities, known-malicious packages): {exc}"
        )


def _dependency_row(run: CheckRun, dep: DeclaredDependency) -> dict:
    linked, resolution = run.linked_repo[dep.name]
    attestation = run.provenance.get(dep.name)
    return {
        "pypi_package": dep.name,
        "requirement": dep.requirement,
        "dependency_group": dep.group,
        "declared_in": dep.declared_in,
        "repo_name": run.canonical_repo.get(linked, linked) if linked else None,
        "resolution": resolution,
        "repo_lookup": run.repo_lookup.get(linked, "unavailable") if linked else "none",
        **run.facts[dep.name],
        "has_provenance": attestation.attested if attestation else None,
        "provenance_repo": attestation.repository if attestation else None,
    }


def _tracked_projects(run: CheckRun) -> list[TrackedProject]:
    found = set(run.canonical_repo.values())
    tracked, seen = [], set()
    for dep in run.dependencies:
        linked = run.linked_repo[dep.name][0]
        repo = run.canonical_repo.get(linked, linked) if linked else None
        if repo in found and repo.lower() not in seen:
            seen.add(repo.lower())
            tracked.append(TrackedProject(repo=repo, pypi=dep.name))
    return tracked


def store_findings(run: CheckRun) -> None:
    for detector in run.detectors_run:
        mine = [f for f in run.findings if f.detector == detector]
        write_findings(run.settings.bronze_dir, detector, mine, run.today)


def decide_risk_levels(run: CheckRun) -> None:
    window = json.dumps({"health_window_days": run.window_days})
    if not run_dbt(run.settings, ["build", "--full-refresh", "--vars", window], quiet=True):
        raise RuntimeError("dbt build failed - rerun with -v for details")


def load_result(run: CheckRun, source: str) -> CheckResult:
    with duckdb.connect(str(run.settings.warehouse_path)) as con:
        rows = _query(con, "select * from main_marts.mart_dependency_risk")
        findings = _query(
            con, "select * from main_marts.fct_supply_chain_findings where target_type = 'package'"
        )
    rows.sort(key=lambda r: (LEVELS.index(r["risk_level"]), r["pypi_package"]))
    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["target"], f["rule_id"]))
    return CheckResult(
        rows=rows,
        source=source,
        window_days=run.window_days,
        findings=findings,
        unavailable_signals=run.unavailable_signals,
    )


def _query(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict]:
    cursor = con.execute(sql)
    columns = [c[0] for c in cursor.description]
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
