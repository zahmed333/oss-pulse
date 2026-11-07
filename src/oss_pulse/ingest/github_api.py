"""Second ingestion path: the GitHub REST API, for an arbitrary set of repositories.

GH Archive is ideal for the ecosystem-wide batch view but means downloading the whole
firehose. To check *your* dependencies right now, we instead pull the last N days of
activity per repo from the REST API and translate it into the **same bronze event
contract** as GH Archive. Every dbt model downstream works unchanged on either source.

    /repos/{r}                  -> github_repos (archived? license? last push?)
    /repos/{r}/issues?since=    -> IssuesEvent + PullRequestEvent (opened / closed / merged)
    /repos/{r}/issues/comments  -> IssueCommentEvent   (time to first response)
    /repos/{r}/commits?since=   -> PushEvent, one per commit  (bus factor)

Raw API pages are cached in the raw zone, so re-runs on the same day cost zero requests
and every bronze row can be traced back to the exact response it came from.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pyarrow as pa
from packaging.utils import canonicalize_version
from packaging.version import InvalidVersion, Version

from oss_pulse.config import Settings
from oss_pulse.endpoints import url
from oss_pulse.ingest.gharchive import InvalidEvent, normalize_event
from oss_pulse.ingest.io import atomic_write_json, atomic_write_table
from oss_pulse.ingest.schema import GHARCHIVE_EVENTS, GITHUB_REPOS

log = logging.getLogger(__name__)

API = url("github")
DEFAULT_MAX_PAGES = 5  # per endpoint per repo: bounds cost on very busy repos


class GitHubAPIError(RuntimeError):
    pass


class RepoNotFound(GitHubAPIError):
    pass


class RepoForbidden(GitHubAPIError):
    """403 that is not a rate limit (e.g. blocked by an org policy or proxy)."""


def _ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stable_int(text: str) -> int:
    return int(hashlib.sha1(text.encode()).hexdigest()[:12], 16)


class GitHubClient:
    """Minimal REST client: auth, pagination, rate-limit awareness, raw-zone caching."""

    def __init__(
        self,
        cache_dir: Path,
        token: str | None = None,
        client: httpx.Client | None = None,
        max_pages: int = DEFAULT_MAX_PAGES,
    ):
        self.cache_dir = cache_dir
        self.max_pages = max_pages
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "oss-pulse",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.http = client or httpx.Client(base_url=API, timeout=30.0, follow_redirects=True)
        self.http.headers.update(headers)
        self.requests_made = 0

    @classmethod
    def from_env(cls, cache_dir: Path, **kw) -> GitHubClient:
        token = os.getenv("OSS_PULSE_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")
        return cls(cache_dir, token=token, **kw)

    def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        for attempt in range(1, 5):
            resp = self.http.get(path, params=params)
            self.requests_made += 1
            if resp.status_code == 404:
                raise RepoNotFound(path)
            if resp.status_code == 401:
                raise GitHubAPIError("GitHub rejected the token (401). Check GITHUB_TOKEN.")
            remaining = resp.headers.get("x-ratelimit-remaining")
            if resp.status_code in (403, 429) and remaining == "0":
                reset = int(resp.headers.get("x-ratelimit-reset", "0"))
                raise GitHubAPIError(
                    f"GitHub rate limit exhausted (resets at "
                    f"{datetime.fromtimestamp(reset, UTC):%H:%M} UTC). Set GITHUB_TOKEN to get "
                    "5,000 requests/hour instead of 60."
                )
            if resp.status_code == 403:
                raise RepoForbidden(f"{path}: {resp.text[:200]}")
            if resp.status_code >= 500 and attempt < 4:
                time.sleep(2**attempt)
                continue
            resp.raise_for_status()
            return resp
        raise AssertionError("unreachable")

    def get_json(self, path: str, cache_key: str, params: dict | None = None):
        cached = self.cache_dir / f"{cache_key}.json"
        if cached.exists():
            return json.loads(cached.read_text())
        body = self._get(path, params).json()
        atomic_write_json({"path": path, "params": params, "body": body}, cached)
        return {"path": path, "params": params, "body": body}

    def paginate(self, path: str, cache_key: str, params: dict) -> tuple[list[dict], bool]:
        """Follow pages until exhausted or max_pages. Returns (items, truncated)."""
        items: list[dict] = []
        for page in range(1, self.max_pages + 1):
            doc = self.get_json(
                path, f"{cache_key}-p{page}", {**params, "per_page": 100, "page": page}
            )
            body = doc["body"]
            items.extend(body)
            if len(body) < 100:
                return items, False
        return items, True


@dataclass
class RepoSnapshot:
    repo: dict
    events: list[dict]  # GH Archive-format raw events
    truncated: bool


def _event(
    repo: dict, etype: str, created_at: str, actor: dict | None, payload: dict, key: str
) -> dict:
    actor = actor or {}
    login = actor.get("login")
    return {
        "id": f"api:{_stable_int(repo['full_name'] + key)}",
        "type": etype,
        "actor": {"id": actor.get("id") or (_stable_int(login) if login else 0), "login": login},
        "repo": {"id": repo["id"], "name": repo["full_name"]},
        "payload": payload,
        "public": True,
        "created_at": created_at,
        "org": {"login": repo["owner"]["login"]},
    }


def issues_to_events(repo: dict, issues: list[dict], since: datetime) -> Iterator[dict]:
    for it in issues:
        number, user = it["number"], it.get("user") or {}
        created, closed = _ts(it.get("created_at")), _ts(it.get("closed_at"))
        pr = it.get("pull_request")
        if pr is not None:
            merged_at = pr.get("merged_at")
            body = {
                "number": number,
                "user": {"login": user.get("login")},
                "created_at": it["created_at"],
                "closed_at": it.get("closed_at"),
                "merged_at": merged_at,
                "merged": merged_at is not None,
            }
            if created and created >= since:
                yield _event(
                    repo,
                    "PullRequestEvent",
                    it["created_at"],
                    user,
                    {
                        "action": "opened",
                        "number": number,
                        "pull_request": {
                            **body,
                            "merged": False,
                            "merged_at": None,
                            "closed_at": None,
                        },
                    },
                    f"pr:{number}:opened",
                )
            if closed and closed >= since:
                yield _event(
                    repo,
                    "PullRequestEvent",
                    it["closed_at"],
                    None,
                    {"action": "closed", "number": number, "pull_request": body},
                    f"pr:{number}:closed",
                )
        else:
            issue = {
                "number": number,
                "user": {"login": user.get("login")},
                "created_at": it["created_at"],
                "closed_at": it.get("closed_at"),
            }
            if created and created >= since:
                yield _event(
                    repo,
                    "IssuesEvent",
                    it["created_at"],
                    user,
                    {"action": "opened", "issue": issue},
                    f"issue:{number}:opened",
                )
            if closed and closed >= since:
                yield _event(
                    repo,
                    "IssuesEvent",
                    it["closed_at"],
                    it.get("closed_by"),
                    {"action": "closed", "issue": issue},
                    f"issue:{number}:closed",
                )


_ISSUE_NUMBER = re.compile(r"/issues/(\d+)$")


def comments_to_events(
    repo: dict, comments: list[dict], issue_authors: dict[int, str | None], since: datetime
) -> Iterator[dict]:
    for c in comments:
        m = _ISSUE_NUMBER.search(c.get("issue_url", ""))
        created = _ts(c.get("created_at"))
        if not m or not created or created < since:
            continue
        number = int(m.group(1))
        yield _event(
            repo,
            "IssueCommentEvent",
            c["created_at"],
            c.get("user"),
            {
                "action": "created",
                "issue": {"number": number, "user": {"login": issue_authors.get(number)}},
                "comment": {"id": c["id"], "created_at": c["created_at"]},
            },
            f"comment:{c['id']}",
        )


def commits_to_events(repo: dict, commits: list[dict]) -> Iterator[dict]:
    for c in commits:
        author = c.get("author") or {}
        if not author.get("login"):  # commit e-mail not linked to an account
            name = ((c.get("commit") or {}).get("author") or {}).get("name") or "unknown"
            author = {"login": f"{name} (unlinked)", "id": _stable_int("name:" + name)}
        when = ((c.get("commit") or {}).get("committer") or {}).get("date")
        if when:
            yield _event(
                repo,
                "PushEvent",
                when,
                author,
                {"size": 1, "distinct_size": 1, "head": c["sha"]},
                f"commit:{c['sha']}",
            )


def tag_versions(tags: list[str], repo_name: str = "") -> list[str]:
    """Canonicalise tags like 'v1.2.0', 'release-1.2', 'pkg-1.2.0', 'pkg==1.2' to versions."""
    out = []
    for t in tags:
        candidate = re.sub(r"^(?:.*?[-_/=@])?v?(?=\d)", "", t, count=1)
        try:
            out.append(canonicalize_version(Version(candidate)))
        except InvalidVersion:
            continue
    return sorted(set(out))


def fetch_repo(gh: GitHubClient, repo_name: str, since: datetime, day: date) -> RepoSnapshot:
    slug = repo_name.replace("/", "__")
    key = f"{day:%Y-%m-%d}/{slug}"
    repo = gh.get_json(f"/repos/{repo_name}", f"{key}/repo")["body"]
    # Follow renames/transfers: the API redirects, and full_name is the canonical name.
    params = {"since": _iso(since)}
    issues, t1 = gh.paginate(
        f"/repos/{repo_name}/issues",
        f"{key}/issues",
        {**params, "state": "all", "sort": "created", "direction": "desc"},
    )
    comments, t2 = gh.paginate(
        f"/repos/{repo_name}/issues/comments",
        f"{key}/comments",
        {**params, "sort": "created", "direction": "desc"},
    )
    commits, t3 = gh.paginate(f"/repos/{repo_name}/commits", f"{key}/commits", params)
    tags = gh.get_json(f"/repos/{repo_name}/tags", f"{key}/tags", {"per_page": 100})["body"]
    repo["_tag_versions"] = tag_versions([t["name"] for t in tags], repo.get("name", ""))

    authors = {i["number"]: (i.get("user") or {}).get("login") for i in issues}
    events = [
        *issues_to_events(repo, issues, since),
        *comments_to_events(repo, comments, authors, since),
        *commits_to_events(repo, commits),
    ]
    return RepoSnapshot(repo=repo, events=events, truncated=t1 or t2 or t3)


def _repo_row(snap: RepoSnapshot, since: datetime, ingested_at: datetime) -> dict:
    r = snap.repo
    return {
        "repo_name": r["full_name"],
        "repo_id": r["id"],
        "is_archived": bool(r.get("archived")),
        "is_fork": bool(r.get("fork")),
        "stargazers_count": r.get("stargazers_count"),
        "open_issues_count": r.get("open_issues_count"),
        "license_spdx": (r.get("license") or {}).get("spdx_id"),
        "default_branch": r.get("default_branch"),
        "created_at": _ts(r.get("created_at")),
        "pushed_at": _ts(r.get("pushed_at")),
        "fetch_window_start": since,
        "is_truncated": snap.truncated,
        "tag_versions": r.get("_tag_versions") or [],
        "_ingested_at": ingested_at,
    }


def ingest_repos(
    settings: Settings,
    repos: list[str],
    days: int = 90,
    gh: GitHubClient | None = None,
    today: date | None = None,
    status: dict[str, str] | None = None,
) -> dict[str, str]:
    """Snapshot `days` of activity for each repo into bronze. Returns {requested: canonical}.

    If `status` is given it is filled with {requested: found | not_found | unavailable}, so
    callers can tell "this repo is gone" (a risk) from "we could not look" (unknown)."""
    status = {} if status is None else status
    today = today or datetime.now(UTC).date()
    since = datetime(today.year, today.month, today.day, tzinfo=UTC) - timedelta(days=days)
    ingested_at = datetime.now(UTC)
    gh = gh or GitHubClient.from_env(settings.raw_dir / "github_api")
    canonical: dict[str, str] = {}

    for repo_name in repos:
        try:
            snap = fetch_repo(gh, repo_name, since, today)
        except RepoNotFound:
            log.warning("repo %s not found (deleted or private) - skipping", repo_name)
            status[repo_name] = "not_found"
            continue
        except RepoForbidden as exc:
            log.warning("access to %s forbidden - skipping (%s)", repo_name, exc)
            status[repo_name] = "unavailable"
            continue
        status[repo_name] = "found"
        name = snap.repo["full_name"]
        canonical[repo_name] = name
        source_file = f"github_api/{today:%Y-%m-%d}/{name}"
        rows = []
        for raw in snap.events:
            try:
                rows.append(normalize_event(raw, source_file, ingested_at))
            except InvalidEvent as exc:  # pragma: no cover - API shapes are controlled
                log.warning("skipping malformed API event for %s: %s", name, exc)
        part = f"snapshot_date={today:%Y-%m-%d}/repo={name.replace('/', '__')}"
        atomic_write_table(
            pa.Table.from_pylist(rows, schema=GHARCHIVE_EVENTS),
            settings.bronze_dir / "github_api" / part / "events.parquet",
        )
        atomic_write_table(
            pa.Table.from_pylist([_repo_row(snap, since, ingested_at)], schema=GITHUB_REPOS),
            settings.bronze_dir / "github_repos" / part / "repo.parquet",
        )
        log.info(
            "github api %s: %d events%s", name, len(rows), " (truncated)" if snap.truncated else ""
        )
    log.info("github api: %d requests made (rest served from cache)", gh.requests_made)
    return canonical
