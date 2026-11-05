"""`oss-pulse check`: supply-chain risk assessment of a project's dependencies.

    dependency file
       │
       ├─► PyPI metadata ─► source repo ─► GitHub API (activity, archived?, tags)
       ├─► PyPI releases ─► resolved version, allowed range, release timing
       ├─► OSV.dev ─────── known vulnerabilities + known malicious packages
       ├─► OpenSSF Scorecard
       ├─► PyPI Integrity API ─ provenance (Trusted Publishing) of resolved vs previous
       ├─► top-PyPI list ─ typosquatting / dependency confusion
       └─► release artifacts (sdist + wheel) ─ static malware heuristics
                         │
                   bronze (Parquet) ─► dbt ─► mart_dependency_risk ─► report / CI gate

Every external source is optional except PyPI: if one is unreachable the check still
runs, and the report says loudly which signal is missing (`--strict` turns that into a
failure).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import httpx
import pyarrow as pa
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, canonicalize_version
from packaging.version import InvalidVersion, Version

from oss_pulse.config import Settings, TrackedProject
from oss_pulse.ingest import github_api, osv, pypi, scorecard
from oss_pulse.ingest.dependencies import parse_dependency_file, resolve_repo
from oss_pulse.ingest.io import atomic_write_table
from oss_pulse.ingest.schema import DEPENDENCIES
from oss_pulse.safe_text import md_code, md_text
from oss_pulse.supplychain import artifacts, provenance, typosquat
from oss_pulse.supplychain.findings import SEVERITY_RANK, Finding, write_findings
from oss_pulse.transform import run_dbt

log = logging.getLogger(__name__)

LEVELS = ["critical", "high", "medium", "unknown", "ok"]
ICONS = {level: level for level in [*LEVELS, "low", "info"]}  # plain words, no emoji
SEVERITY = {"critical": 3, "high": 2, "medium": 1, "unknown": 0, "ok": 0}
REPORT_MARKER = "<!-- oss-pulse-report -->"


@dataclass
class CheckResult:
    rows: list[dict]
    source: str
    window_days: int
    findings: list[dict] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)  # signals that could not be collected

    def counts(self) -> dict[str, int]:
        return {lvl: sum(r["risk_level"] == lvl for r in self.rows) for lvl in LEVELS}

    def worst(self) -> int:
        return max((SEVERITY[r["risk_level"]] for r in self.rows), default=0)


def version_facts(requirement: str, doc: dict | None) -> dict:
    """What a fresh install resolves to, which releases the specifier allows, and when the
    package first appeared on PyPI (brand-new packages are a typosquatting signal)."""
    empty = {
        "resolved_version": None,
        "resolved_version_key": None,
        "allowed_versions": [],
        "is_pinned": False,
        "first_release_at": None,
    }
    if not doc:
        return empty
    req = Requirement(requirement)
    versions, uploads, spelling = [], [], {}
    for v, files in (doc.get("releases") or {}).items():
        uploads += [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            parsed = Version(v)
        except InvalidVersion:
            continue
        versions.append(parsed)
        spelling[parsed] = v  # keep PyPI's own spelling so joins on version match exactly
    allowed = sorted(req.specifier.filter(versions))
    first = min(uploads) if uploads else None
    resolved = allowed[-1] if allowed else None
    return {
        "resolved_version": spelling[resolved] if resolved else None,
        "resolved_version_key": canonicalize_version(resolved) if resolved else None,
        # normalised, to compare with OSV's normalised affected-version lists
        "allowed_versions": [str(v) for v in allowed],
        "is_pinned": any(s.operator in ("==", "===") for s in req.specifier),
        "first_release_at": datetime.fromisoformat(first.replace("Z", "+00:00")) if first else None,
    }


def _previous_version(doc: dict, version: str | None) -> str | None:
    if not version:
        return None
    older = []
    for v, files in (doc.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv < Version(version) and not pv.is_prerelease:
            older.append(pv)
    return str(max(older)) if older else None


def _release_key(doc: dict, version: str) -> str | None:
    """PyPI's own spelling of a version (the releases dict key)."""
    for v in doc.get("releases") or {}:
        try:
            if Version(v) == Version(version):
                return v
        except InvalidVersion:
            continue
    return None


def run_check(
    dependency_file: Path,
    data_dir: Path,
    days: int = 90,
    include_optional: bool = True,
    internal: list[str] | None = None,
    scan_artifacts: bool = True,
    gh: github_api.GitHubClient | None = None,
    http: httpx.Client | None = None,
) -> CheckResult:
    settings = Settings(data_dir=data_dir)
    today = datetime.now(UTC).date()
    degraded: list[str] = []
    findings: list[Finding] = []
    detectors_run: set[str] = set()

    deps = parse_dependency_file(dependency_file, include_optional=include_optional)
    if not deps:
        raise ValueError(f"no dependencies found in {dependency_file}")
    log.info("found %d dependencies in %s", len(deps), dependency_file.name)
    names = [d.name for d in deps]
    internal = [canonicalize_name(n) for n in (internal or [])]

    client = http or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        # 1. PyPI metadata: source repo + version facts --------------------------
        docs: dict[str, dict | None] = {}
        resolved: dict[str, tuple[str | None, str]] = {}
        facts: dict[str, dict] = {}
        for d in deps:
            if d.name in internal:  # never ask public PyPI about the *contents* of internal deps
                docs[d.name] = pypi.fetch_document(settings, d.name, client, today)
                resolved[d.name], facts[d.name] = (
                    (None, "internal"),
                    version_facts(d.requirement, None),
                )
                continue
            doc = docs[d.name] = pypi.fetch_document(settings, d.name, client, today)
            resolved[d.name] = resolve_repo(doc) if doc else (None, "not_on_pypi")
            facts[d.name] = version_facts(d.requirement, doc)

        # 2. Identity: typosquatting + dependency confusion -----------------------
        popular = typosquat.load_popular(settings.raw_dir / "reference", client, today)
        findings += typosquat.check_names([n for n in names if n not in internal], popular)
        findings += typosquat.check_dependency_confusion(
            internal, {n: docs.get(n) is not None for n in internal}
        )
        detectors_run |= {"typosquat", "dependency_confusion"}

        # 3. GitHub activity snapshot ----------------------------------------------
        repos = sorted({repo for repo, _ in resolved.values() if repo})
        lookup: dict[str, str] = {}
        try:
            canonical = github_api.ingest_repos(
                settings, repos, days=days, gh=gh, today=today, status=lookup
            )
        except github_api.GitHubAPIError as exc:  # e.g. rate limit: stop asking
            degraded.append(f"GitHub activity (maintenance signals): {exc}")
            canonical = {}
        unavailable = [r for r in repos if lookup.get(r, "unavailable") == "unavailable"]
        if unavailable and not degraded:
            degraded.append(
                f"GitHub activity (maintenance signals) for {len(unavailable)} of "
                f"{len(repos)} repositories: access denied"
            )

        # 4. Provenance (PEP 740) --------------------------------------------------
        prov: dict[str, provenance.Provenance | None] = {}
        for d in deps:
            doc, version = docs.get(d.name), facts[d.name]["resolved_version"]
            if not doc or not version or d.name in internal:
                continue
            releases = doc.get("releases") or {}
            key = _release_key(doc, version)
            prev = _previous_version(doc, version)
            cur_p = prov[d.name] = provenance.release_provenance(d.name, key, releases, client)
            prev_p = provenance.release_provenance(
                d.name, _release_key(doc, prev) if prev else None, releases, client
            )
            linked = canonical.get(resolved[d.name][0] or "", resolved[d.name][0])
            findings += provenance.check_provenance(d.name, cur_p, prev_p, prev, linked, version)
        detectors_run.add("provenance")

        # 5. Release artifacts: static malware heuristics ---------------------------
        if scan_artifacts:
            for d in deps:
                doc, version = docs.get(d.name), facts[d.name]["resolved_version"]
                if not doc or not version or d.name in internal:
                    continue
                files = (doc.get("releases") or {}).get(_release_key(doc, version) or "", [])
                findings += artifacts.scan_release(
                    d.name, version, files, settings.raw_dir / "artifacts", client
                )
            detectors_run.add("artifact_scan")

        # 6. Bronze: dependencies, reference, releases, advisories, scorecards -----------
        dep_rows, tracked, seen = [], [], set()
        for d in deps:
            repo, how = resolved[d.name]
            repo = canonical.get(repo, repo) if repo else None
            p = prov.get(d.name)
            dep_rows.append(
                {
                    "pypi_package": d.name,
                    "requirement": d.requirement,
                    "dependency_group": d.group,
                    "declared_in": d.declared_in,
                    "repo_name": repo,
                    "resolution": how,
                    "repo_lookup": lookup.get(resolved[d.name][0] or "", "unavailable")
                    if resolved[d.name][0]
                    else "none",
                    **facts[d.name],
                    "has_provenance": p.attested if p else None,
                    "provenance_repo": p.repository if p else None,
                }
            )
            if repo and repo in canonical.values() and repo.lower() not in seen:
                seen.add(repo.lower())
                tracked.append(TrackedProject(repo=repo, pypi=d.name))
        atomic_write_table(
            pa.Table.from_pylist(dep_rows, schema=DEPENDENCIES),
            settings.bronze_dir / "reference" / "dependencies.parquet",
        )
        pypi.write_reference(settings, tracked)
        public = [n for n in names if n not in internal]
        pypi.ingest_pypi(settings, snapshot=today, packages=public, client=client)
        try:
            osv.ingest_osv(settings, public, day=today, client=client)
        except httpx.HTTPError as exc:
            degraded.append(f"OSV.dev (vulnerabilities, known-malicious packages): {exc}")
        scorecard.ingest_scorecard(
            settings, sorted(set(canonical.values())), day=today, client=client
        )
    finally:
        if http is None:
            client.close()

    for detector in detectors_run:
        write_findings(
            settings.bronze_dir, detector, [f for f in findings if f.detector == detector], today
        )

    # 7. Transform: same dbt project, window suited to dependency review -----------------
    ok = run_dbt(
        settings,
        ["build", "--full-refresh", "--vars", json.dumps({"health_window_days": days})],
        quiet=True,
    )
    if not ok:
        raise RuntimeError("dbt build failed - rerun with -v for details")

    con = duckdb.connect(str(settings.warehouse_path))
    try:
        rows = _fetch(con, "select * from main_marts.mart_dependency_risk")
        found = _fetch(
            con, "select * from main_marts.fct_supply_chain_findings where target_type = 'package'"
        )
    finally:
        con.close()
    rows.sort(key=lambda r: (LEVELS.index(r["risk_level"]), r["pypi_package"]))
    found.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["target"], f["rule_id"]))
    return CheckResult(
        rows=rows, source=dependency_file.name, window_days=days, findings=found, degraded=degraded
    )


def _fetch(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict]:
    cur = con.execute(sql)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


# ----------------------------------------------------------------------- rendering


def _days(v) -> str:
    if v is None:
        return "–"
    return "today" if v == 0 else f"{v}d ago"


def render_markdown(result: CheckResult) -> str:
    c = result.counts()
    summary = ", ".join(f"{c[lvl]} {lvl}" for lvl in LEVELS if c[lvl])
    lines = [
        REPORT_MARKER,
        "## Supply-chain risk report",
        "",
        f"**{len(result.rows)} dependencies** in {md_code(result.source, in_table=False)} "
        f"· {summary}",
        "",
    ]
    for d in result.degraded:
        lines.append(f"> [!WARNING]\n> Not checked: {md_text(d)}")
    if result.degraded:
        lines.append("")
    lines += [
        "| | Package | Version | Repository | Why | Last release | Last commit | Bus factor |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in result.rows:
        # repo_name only ever holds [A-Za-z0-9_.-]/[A-Za-z0-9_.-] (dependencies.GITHUB_URL)
        repo = f"[{r['repo_name']}](https://github.com/{r['repo_name']})" if r["repo_name"] else "–"
        why = "<br>".join(md_text(x) for x in r["risk_reasons"]) or "–"
        bus = "–" if r["bus_factor"] is None else str(r["bus_factor"])
        prov = " (attested)" if r.get("has_provenance") else ""
        lines.append(
            f"| {ICONS[r['risk_level']]} | {md_code(r['pypi_package'])} "
            f"| {md_text(r['resolved_version'] or '–')}"
            f"{prov} | {repo} | {why} | {_days(r['days_since_last_release'])} "
            f"| {_days(r['days_since_last_commit'])} | {bus} |"
        )
    if result.findings:
        lines += [
            "",
            f"<details><summary><b>Findings</b> ({len(result.findings)})</summary>",
            "",
            "| Severity | Package | Rule | Finding | Where | Evidence |",
            "|---|---|---|---|---|---|",
        ]
        for f in result.findings:
            lines.append(
                f"| {f['severity']} | {md_code(f['target'])} "
                f"| {f['rule_id']} | {md_text(f['title'])}: {md_text(f['detail'])} "
                f"| {md_code(f['location'] or '–')} | {md_code(f['evidence'] or '–', 100)} |"
            )
        lines.append("</details>")
    lines += [
        "",
        f"<sub>Attested means the release has a Trusted Publishing attestation (PEP 740). "
        f"Activity window: last {result.window_days} days. Bus factor = fewest people "
        "responsible for ≥50% of commits and opened PRs. Generated by OSS Pulse; "
        "run `oss-pulse rules` for the full rule catalogue.</sub>",
    ]
    return "\n".join(lines) + "\n"


def render_json(result: CheckResult) -> str:
    return json.dumps(
        {
            "source": result.source,
            "window_days": result.window_days,
            "summary": result.counts(),
            "degraded": result.degraded,
            "dependencies": result.rows,
            "findings": result.findings,
        },
        indent=2,
        default=str,
    )
