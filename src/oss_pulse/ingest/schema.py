"""Bronze-layer contracts.

Bronze is "raw but typed": every source record lands exactly once, with a stable,
explicit Arrow schema, plus lineage columns (`_source_file`, `_ingested_at`).
Nested payloads stay as JSON text so upstream schema drift never breaks ingestion --
it is handled downstream in dbt, where it is visible and testable.
"""

from __future__ import annotations

import pyarrow as pa

UTC_TS = pa.timestamp("us", tz="UTC")

GHARCHIVE_EVENTS = pa.schema(
    [
        pa.field("event_id", pa.string(), nullable=False),
        pa.field("event_type", pa.string(), nullable=False),
        pa.field("created_at", UTC_TS, nullable=False),
        pa.field("actor_id", pa.int64(), nullable=False),
        pa.field("actor_login", pa.string()),
        pa.field("repo_id", pa.int64(), nullable=False),
        pa.field("repo_name", pa.string()),
        pa.field("org_login", pa.string()),
        pa.field("payload_action", pa.string()),
        pa.field("payload", pa.string()),  # raw JSON
        pa.field("is_public", pa.bool_()),
        pa.field("_source_file", pa.string(), nullable=False),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)

PYPI_RELEASES = pa.schema(
    [
        pa.field("package", pa.string(), nullable=False),
        pa.field("version", pa.string(), nullable=False),
        pa.field("uploaded_at", UTC_TS),
        pa.field("is_yanked", pa.bool_()),
        pa.field("file_count", pa.int32()),
        pa.field("total_size_bytes", pa.int64()),
        pa.field("requires_python", pa.string()),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)

TRACKED_PROJECTS = pa.schema(
    [
        pa.field("repo_name", pa.string(), nullable=False),
        pa.field("pypi_package", pa.string()),
    ]
)

# Repo-level attributes from the GitHub REST API (one row per repo per snapshot).
GITHUB_REPOS = pa.schema(
    [
        pa.field("repo_name", pa.string(), nullable=False),
        pa.field("repo_id", pa.int64()),
        pa.field("is_archived", pa.bool_()),
        pa.field("is_fork", pa.bool_()),
        pa.field("stargazers_count", pa.int64()),
        pa.field("open_issues_count", pa.int64()),
        pa.field("license_spdx", pa.string()),
        pa.field("default_branch", pa.string()),
        pa.field("created_at", UTC_TS),
        pa.field("pushed_at", UTC_TS),
        pa.field("fetch_window_start", UTC_TS, nullable=False),
        pa.field("is_truncated", pa.bool_()),
        pa.field("tag_versions", pa.list_(pa.string())),  # newest 100 tags, as versions
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)

# Dependencies declared by the project being checked, and how each was resolved to a repo.
DEPENDENCIES = pa.schema(
    [
        pa.field("pypi_package", pa.string(), nullable=False),
        pa.field("requirement", pa.string()),
        pa.field("dependency_group", pa.string()),
        pa.field("declared_in", pa.string()),
        pa.field("repo_name", pa.string()),
        pa.field("resolution", pa.string(), nullable=False),
        pa.field("repo_lookup", pa.string()),  # found | not_found | unavailable | none
        # What a fresh install resolves to, and every release the specifier permits.
        pa.field("resolved_version", pa.string()),
        pa.field("resolved_version_key", pa.string()),  # canonical form, matches tag_versions
        pa.field("allowed_versions", pa.list_(pa.string())),
        pa.field("is_pinned", pa.bool_()),
        pa.field("first_release_at", UTC_TS),
        # PEP 740 provenance of the resolved version (Trusted Publishing).
        pa.field("has_provenance", pa.bool_()),
        pa.field("provenance_repo", pa.string()),
    ]
)

# Known vulnerabilities (OSV.dev) affecting PyPI packages, one row per (package, advisory).
OSV_VULNERABILITIES = pa.schema(
    [
        pa.field("pypi_package", pa.string(), nullable=False),
        pa.field("vuln_id", pa.string(), nullable=False),
        pa.field("aliases", pa.list_(pa.string())),
        pa.field("summary", pa.string()),
        pa.field("severity", pa.string()),  # critical | high | medium | low | unknown
        pa.field("published_at", UTC_TS),
        pa.field("modified_at", UTC_TS),
        pa.field("is_withdrawn", pa.bool_()),
        pa.field("is_malicious", pa.bool_()),  # MAL- advisory: the package itself is malware
        pa.field("affected_versions", pa.list_(pa.string())),
        pa.field("fixed_versions", pa.list_(pa.string())),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)

# OpenSSF Scorecard results, one row per (repo, check).
SCORECARD_CHECKS = pa.schema(
    [
        pa.field("repo_name", pa.string(), nullable=False),
        pa.field("scorecard_date", pa.date32()),
        pa.field("overall_score", pa.float64()),
        pa.field("check_name", pa.string(), nullable=False),
        pa.field("check_score", pa.int32()),  # 0-10, -1 = not applicable
        pa.field("reason", pa.string()),
        pa.field("_ingested_at", UTC_TS, nullable=False),
    ]
)
