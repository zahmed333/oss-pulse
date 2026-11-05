"""What a fresh install of a requirement resolves to, read from a PyPI JSON document."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from packaging.requirements import Requirement
from packaging.utils import canonicalize_version
from packaging.version import InvalidVersion, Version

NO_FACTS = {
    "resolved_version": None,
    "resolved_version_key": None,
    "allowed_versions": [],
    "is_pinned": False,
    "first_release_at": None,
}


def installable_releases(doc: dict) -> Iterator[tuple[Version, str]]:
    """(parsed version, PyPI's own spelling) for every release with a non-yanked file."""
    for spelling, files in (doc.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            yield Version(spelling), spelling
        except InvalidVersion:
            continue


def first_upload(doc: dict) -> datetime | None:
    uploads = [
        f["upload_time_iso_8601"]
        for files in (doc.get("releases") or {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    return datetime.fromisoformat(min(uploads).replace("Z", "+00:00")) if uploads else None


def version_facts(requirement: str, doc: dict | None) -> dict:
    if not doc:
        return dict(NO_FACTS)
    specifier = Requirement(requirement).specifier
    spelling_of = dict(installable_releases(doc))
    allowed = sorted(specifier.filter(spelling_of))
    newest_allowed = allowed[-1] if allowed else None
    return {
        "resolved_version": spelling_of[newest_allowed] if newest_allowed else None,
        "resolved_version_key": canonicalize_version(newest_allowed) if newest_allowed else None,
        "allowed_versions": [str(v) for v in allowed],
        "is_pinned": any(s.operator in ("==", "===") for s in specifier),
        "first_release_at": first_upload(doc),
    }


def previous_stable_release(doc: dict, version: str | None) -> str | None:
    if not version:
        return None
    current = Version(version)
    older = [v for v, _ in installable_releases(doc) if v < current and not v.is_prerelease]
    return str(max(older)) if older else None


def pypi_spelling(doc: dict, version: str | None) -> str | None:
    if not version:
        return None
    wanted = Version(version)
    for spelling in doc.get("releases") or {}:
        try:
            if Version(spelling) == wanted:
                return spelling
        except InvalidVersion:
            continue
    return None
