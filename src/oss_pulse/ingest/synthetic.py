"""Deterministic synthetic data in the *exact* on-disk format of GH Archive and PyPI.

Why this exists: CI and reviewers should be able to run the full pipeline offline in
seconds, and tests need known ground truth. Synthetic files are written into the raw
zone, so they flow through the identical parsing/ingestion code path as real data.

It deliberately injects dirty data -- malformed JSON, records missing required
fields, and duplicate event ids -- so the quarantine and dedupe logic is exercised
on every run.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from oss_pulse.config import Settings
from oss_pulse.ingest.gharchive import archive_filename, floor_hour, hour_range


def _stable_id(text: str, mod: int = 10**9) -> int:
    return int(hashlib.sha1(text.encode()).hexdigest()[:12], 16) % mod + 1


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Sim:
    def __init__(self, start: datetime, end: datetime, seed: int):
        self.rng = random.Random(seed)
        self.start, self.end = start, end
        self.events: list[dict] = []
        self._next_id = 30_000_000_000 + seed * 1_000_000

    def _rand_ts(self, lo: datetime | None = None) -> datetime:
        lo = lo or self.start
        span = (self.end - lo).total_seconds()
        return lo + timedelta(seconds=self.rng.uniform(0, max(span, 1)))

    def user(self, login: str) -> dict:
        return {"id": _stable_id("u:" + login), "login": login}

    def emit(self, ts: datetime, etype: str, repo: str, actor: str, payload: dict) -> None:
        if ts >= self.end:
            return
        self._next_id += 1
        owner = repo.split("/")[0]
        self.events.append(
            {
                "id": str(self._next_id),
                "type": etype,
                "actor": {**self.user(actor), "display_login": actor},
                "repo": {
                    "id": _stable_id("r:" + repo),
                    "name": repo,
                    "url": f"https://api.github.com/repos/{repo}",
                },
                "payload": payload,
                "public": True,
                "created_at": _iso(ts),
                "org": {"id": _stable_id("o:" + owner), "login": owner},
            }
        )

    def simulate_repo(self, repo: str, activity: float) -> None:
        rng = self.rng
        hours = (self.end - self.start).total_seconds() / 3600
        n_core = rng.randint(1, 6)
        core = [f"{repo.split('/')[1]}-maint{i}" for i in range(n_core)]
        # Zipf-ish weights: some repos end up with a single dominant maintainer (bus factor 1)
        weights = [1 / (i + 1) ** rng.uniform(0.5, 2.5) for i in range(n_core)]
        outsiders = [f"user{rng.randint(1, 5000)}" for _ in range(40)]

        def n(rate_per_hour: float) -> int:
            lam = rate_per_hour * hours * activity
            return max(0, int(rng.gauss(lam, lam**0.5 + 0.01)))

        for _ in range(n(1.5)):
            self.emit(
                self._rand_ts(), "WatchEvent", repo, rng.choice(outsiders), {"action": "started"}
            )
        for _ in range(n(0.3)):
            actor = rng.choice(outsiders)
            self.emit(
                self._rand_ts(),
                "ForkEvent",
                repo,
                actor,
                {"forkee": {"full_name": f"{actor}/{repo.split('/')[1]}"}},
            )
        for _ in range(n(0.8)):
            size = rng.randint(1, 8)
            self.emit(
                self._rand_ts(),
                "PushEvent",
                repo,
                rng.choices(core, weights)[0],
                {
                    "push_id": rng.randint(1, 10**10),
                    "size": size,
                    "distinct_size": size,
                    "ref": "refs/heads/main",
                },
            )

        number = rng.randint(100, 20000)
        for _pull_request in range(n(0.5)):
            number += 1
            author = rng.choices(core, weights)[0] if rng.random() < 0.6 else rng.choice(outsiders)
            opened = self._rand_ts()
            pr = {
                "id": _stable_id(f"pr:{repo}:{number}"),
                "number": number,
                "state": "open",
                "merged": False,
                "created_at": _iso(opened),
                "closed_at": None,
                "merged_at": None,
                "user": self.user(author),
                "additions": rng.randint(1, 800),
                "deletions": rng.randint(0, 300),
                "changed_files": rng.randint(1, 25),
            }
            self.emit(
                opened,
                "PullRequestEvent",
                repo,
                author,
                {"action": "opened", "number": number, "pull_request": dict(pr)},
            )
            outcome = rng.random()
            if outcome < 0.75:
                closed = opened + timedelta(hours=rng.expovariate(1 / 18))
                merged = outcome < 0.6
                closer = rng.choices(core, weights)[0]
                pr.update(
                    state="closed",
                    merged=merged,
                    closed_at=_iso(closed),
                    merged_at=_iso(closed) if merged else None,
                )
                self.emit(
                    closed,
                    "PullRequestEvent",
                    repo,
                    closer,
                    {"action": "closed", "number": number, "pull_request": dict(pr)},
                )

        for _issue in range(n(0.4)):
            number += 1
            author = rng.choice(outsiders)
            opened = self._rand_ts()
            issue = {
                "id": _stable_id(f"is:{repo}:{number}"),
                "number": number,
                "created_at": _iso(opened),
                "closed_at": None,
                "user": self.user(author),
            }
            self.emit(opened, "IssuesEvent", repo, author, {"action": "opened", "issue": issue})
            t = opened
            for c in range(rng.randint(0, 4)):
                t = t + timedelta(hours=rng.expovariate(1 / (6 if c == 0 else 12)))
                commenter = author if rng.random() < 0.3 else rng.choices(core, weights)[0]
                self.emit(
                    t,
                    "IssueCommentEvent",
                    repo,
                    commenter,
                    {
                        "action": "created",
                        "issue": {"number": number, "user": self.user(author)},
                        "comment": {
                            "id": rng.randint(1, 10**10),
                            "user": self.user(commenter),
                            "created_at": _iso(t),
                        },
                    },
                )
            if rng.random() < 0.5:
                t = t + timedelta(hours=rng.expovariate(1 / 24))
                self.emit(
                    t,
                    "IssuesEvent",
                    repo,
                    rng.choices(core, weights)[0],
                    {"action": "closed", "issue": {**issue, "closed_at": _iso(t)}},
                )

        if rng.random() < min(0.9, 0.04 * hours * activity):
            ts = self._rand_ts()
            self.emit(
                ts,
                "ReleaseEvent",
                repo,
                core[0],
                {
                    "action": "published",
                    "release": {
                        "tag_name": f"v{rng.randint(0, 3)}.{rng.randint(0, 30)}.0",
                        "published_at": _iso(ts),
                        "prerelease": False,
                    },
                },
            )

    def simulate_noise(self, n_events: int) -> None:
        types = [
            "PushEvent",
            "WatchEvent",
            "CreateEvent",
            "IssueCommentEvent",
            "ForkEvent",
            "DeleteEvent",
            "PullRequestEvent",
            "GollumEvent",
        ]
        for _ in range(n_events):
            repo = f"noise{self.rng.randint(1, 400)}/project{self.rng.randint(1, 50)}"
            self.emit(
                self._rand_ts(),
                self.rng.choice(types),
                repo,
                f"user{self.rng.randint(1, 9000)}",
                {},
            )


def generate_gharchive(
    settings: Settings, start: datetime, end: datetime, seed: int = 42, noise_per_hour: int = 300
) -> list[Path]:
    start, end = floor_hour(start), floor_hour(end)
    sim = _Sim(start, end, seed)
    for i, project in enumerate(settings.tracked_projects()):
        sim.simulate_repo(project.repo, activity=0.3 + (i % 5) * 0.4)
    sim.simulate_noise(noise_per_hour * len(hour_range(start, end)))

    by_hour: dict[datetime, list[str]] = defaultdict(list)
    for ev in sorted(sim.events, key=lambda e: e["created_at"]):
        hour = floor_hour(datetime.fromisoformat(ev["created_at"].replace("Z", "+00:00")))
        by_hour[hour].append(json.dumps(ev, separators=(",", ":")))

    rng = random.Random(seed + 1)
    out_dir = settings.raw_dir / "gharchive"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for hour in hour_range(start, end):
        lines = by_hour.get(hour, [])
        if lines:  # inject dirty data: duplicate, malformed JSON, contract violation
            lines.append(rng.choice(lines))
            lines.append('{"id": "broken", "type": "PushEvent", "actor": {')
            lines.append(json.dumps({"id": "999", "type": "PushEvent", "created_at": _iso(hour)}))
        path = out_dir / archive_filename(hour)
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        written.append(path)
    return written


def generate_pypi(settings: Settings, as_of: datetime, seed: int = 42) -> list[Path]:
    rng = random.Random(seed)
    out_dir = settings.raw_dir / "pypi"
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for project in settings.tracked_projects():
        if not project.pypi:
            continue
        releases: dict[str, list[dict]] = {}
        ts = as_of - timedelta(days=730)
        major, minor, patch = 0, rng.randint(1, 9), 0
        cadence = rng.uniform(7, 45)
        while ts < as_of:
            if rng.random() < 0.25:
                minor, patch = minor + 1, 0
            else:
                patch += 1
            n_files = rng.randint(1, 30)
            releases[f"{major}.{minor}.{patch}"] = [
                {
                    "upload_time_iso_8601": _iso(ts + timedelta(minutes=k)),
                    "size": rng.randint(50_000, 40_000_000),
                    "yanked": rng.random() < 0.02,
                    "requires_python": ">=3.9",
                }
                for k in range(n_files)
            ]
            ts += timedelta(days=rng.expovariate(1 / cadence))
        doc = {"info": {"name": project.pypi}, "releases": releases}
        path = out_dir / f"{project.pypi.lower()}.json"
        path.write_text(json.dumps(doc))
        paths.append(path)
    return paths
