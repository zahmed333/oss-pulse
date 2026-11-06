"""Keep one oss-pulse comment on an Azure DevOps pull request, updated on every run.

Uses the pipeline's own System.AccessToken; the build service needs "Contribute to pull
requests" on the repository.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx

API_VERSION = "7.1"
MARKER = "<!-- oss-pulse -->"
MAX_COMMENT_CHARS = 140_000
COMMENT_ACTIVE = 1


class NotAPullRequestBuild(Exception):
    pass


@dataclass(frozen=True)
class AzurePullRequest:
    collection_uri: str
    project: str
    repository_id: str
    pull_request_id: str
    token: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> AzurePullRequest:
        names = {
            "collection_uri": "SYSTEM_COLLECTIONURI",
            "project": "SYSTEM_TEAMPROJECT",
            "repository_id": "BUILD_REPOSITORY_ID",
            "pull_request_id": "SYSTEM_PULLREQUEST_PULLREQUESTID",
            "token": "SYSTEM_ACCESSTOKEN",
        }
        missing = [var for var in names.values() if not env.get(var)]
        if missing:
            raise NotAPullRequestBuild(f"missing {', '.join(missing)}")
        return cls(**{field: env[var] for field, var in names.items()})

    @property
    def threads_url(self) -> str:
        base = self.collection_uri.rstrip("/")
        return (
            f"{base}/{self.project}/_apis/git/repositories/{self.repository_id}"
            f"/pullRequests/{self.pull_request_id}/threads"
        )


def comment_body(markdown: str) -> str:
    body = f"{MARKER}\n{markdown}"
    if len(body) <= MAX_COMMENT_CHARS:
        return body
    return body[:MAX_COMMENT_CHARS] + "\n\n(report truncated; see the build summary)"


def _existing_comment(threads: list[dict]) -> tuple[int, int] | None:
    for thread in threads:
        for comment in thread.get("comments") or []:
            if MARKER in (comment.get("content") or ""):
                return thread["id"], comment["id"]
    return None


def upsert_comment(pr: AzurePullRequest, markdown: str, client: httpx.Client) -> str:
    auth = {"Authorization": f"Bearer {pr.token}"}
    params = {"api-version": API_VERSION}
    listing = client.get(pr.threads_url, headers=auth, params=params)
    listing.raise_for_status()
    body = comment_body(markdown)
    found = _existing_comment(listing.json().get("value") or [])
    if found:
        thread_id, comment_id = found
        url = f"{pr.threads_url}/{thread_id}/comments/{comment_id}"
        client.patch(url, headers=auth, params=params, json={"content": body}).raise_for_status()
        return "updated"
    new_thread = {
        "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
        "status": COMMENT_ACTIVE,
    }
    client.post(pr.threads_url, headers=auth, params=params, json=new_thread).raise_for_status()
    return "created"
