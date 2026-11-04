"""Typosquatting and dependency-confusion checks against the most-downloaded PyPI projects.

Popular names come from hugovk/top-pypi-packages (refreshed daily when online, bundled
snapshot otherwise). A dependency is only suspicious if it is *not itself popular* but
looks like a popular name: one edit away, or a popular name wrapped in a common affix.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path

import httpx
from packaging.utils import canonicalize_name

from oss_pulse.supplychain.findings import Finding
from oss_pulse.supplychain.rules import rule

log = logging.getLogger(__name__)

TOP_URL = (
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
)
BUNDLED = Path(__file__).with_name("data") / "top_pypi_packages.txt"
TARGETS = 5000  # names worth impersonating
AFFIXES = [
    ("python-", ""),
    ("", "-python"),
    ("py", ""),
    ("py-", ""),
    ("", "py"),
    ("", "-py"),
    ("", "3"),
    ("", "2"),
    ("", "-dev"),
    ("", "-lib"),
    ("", "-sdk"),
    ("", "-api"),
    ("", "-tools"),
    ("", "-utils"),
    ("", "-core"),
    ("", "-official"),
    ("", "-secure"),
]


def load_popular(
    cache_dir: Path | None = None, client: httpx.Client | None = None, day: date | None = None
) -> list[str]:
    """Most-popular-first canonical names. Live (cached per day) with bundled fallback."""
    day = day or datetime.now(UTC).date()
    if cache_dir and client:
        cached = cache_dir / f"top-pypi-{day:%Y-%m-%d}.json"
        try:
            if not cached.exists():
                resp = client.get(TOP_URL, timeout=30.0)
                resp.raise_for_status()
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_bytes(resp.content)
            rows = json.loads(cached.read_text())["rows"]
            return [canonicalize_name(r["project"]) for r in rows]
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("popular-package list unavailable (%s); using bundled snapshot", exc)
    return _bundled()


@lru_cache(maxsize=1)
def _bundled() -> list[str]:
    return [
        canonicalize_name(x)
        for x in BUNDLED.read_text().splitlines()
        if x and not x.startswith("#")
    ]


def damerau_levenshtein(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance with early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def find_lookalike(
    name: str, popular: list[str], popular_set: set[str] | None = None
) -> tuple[str, str, str] | None:
    """Return (rule_id, popular_name, how) if `name` impersonates a popular project."""
    name = canonicalize_name(name)
    if name in (popular_set if popular_set is not None else set(popular)):
        return None  # it *is* a popular project
    targets = popular[:TARGETS]
    squashed = name.replace("-", "")
    for p in targets:
        if len(p) < 4:
            continue  # too short: everything is one edit from "six"
        if squashed == p.replace("-", "") and name != p:
            return "TYPO-001", p, "same letters, different separators"
        if damerau_levenshtein(name, p, 1) <= 1:
            return "TYPO-001", p, "one character different"
    for p in targets[:1000]:
        if len(p) < 4:
            continue
        for pre, suf in AFFIXES:
            if name == f"{pre}{p}{suf}":
                return "TYPO-002", p, f"'{p}' with an added '{pre or suf}'"
    return None


def check_names(packages: list[str], popular: list[str]) -> list[Finding]:
    findings, popular_set = [], set(popular)
    for pkg in packages:
        hit = find_lookalike(pkg, popular, popular_set)
        if hit:
            rule_id, target, how = hit
            r = rule(rule_id)
            findings.append(
                Finding(
                    pkg,
                    "package",
                    "typosquat",
                    rule_id,
                    r.severity,
                    r.category,
                    r.title,
                    detail=f"looks like '{target}' ({how}). {r.why}",
                    evidence=target,
                )
            )
    return findings


def check_dependency_confusion(
    internal: list[str], exists_on_pypi: dict[str, bool]
) -> list[Finding]:
    r = rule("CONF-001")
    return [
        Finding(
            n,
            "package",
            "dependency_confusion",
            r.id,
            r.severity,
            r.category,
            r.title,
            detail=f"'{n}' is declared internal but a public package with that name "
            f"exists on pypi.org. {r.why}",
        )
        for n in internal
        if exists_on_pypi.get(canonicalize_name(n))
    ]
