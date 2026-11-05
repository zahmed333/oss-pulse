"""Scan the *actual files pip would install* for a package version.

Reviewing a project's GitHub repository is not enough: in the Ultralytics compromise the
malicious code existed only in the PyPI artifacts. So we download the release's sdist and
a wheel straight from PyPI and inspect them in memory.

Safety: archives are never extracted to disk (no path traversal, no symlink tricks) and
nothing is executed. Downloads are verified against PyPI's published SHA-256 digests and
cached in the raw zone by digest.
"""

from __future__ import annotations

import hashlib
import io
import logging
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

import httpx

from oss_pulse.supplychain.code_scan import Hit, scan_file
from oss_pulse.supplychain.findings import Finding
from oss_pulse.supplychain.rules import rule

log = logging.getLogger(__name__)

MAX_ARCHIVE_BYTES = 60_000_000
MAX_MEMBER_BYTES = 5_000_000
MAX_MEMBERS = 20_000


class IntegrityError(RuntimeError):
    pass


def pick_files(release_files: list[dict]) -> list[dict]:
    """The sdist plus one wheel (prefer pure-Python), skipping anything too large."""
    ok = [
        f
        for f in release_files
        if not f.get("yanked") and (f.get("size") or 0) <= MAX_ARCHIVE_BYTES
    ]
    sdists = [f for f in ok if f.get("packagetype") == "sdist"]
    wheels = sorted(
        (f for f in ok if f.get("packagetype") == "bdist_wheel"),
        key=lambda f: ("none-any" not in f["filename"], f.get("size") or 0),
    )
    return sdists[:1] + wheels[:1]


def download(file: dict, cache_dir: Path, client: httpx.Client) -> bytes:
    sha = (file.get("digests") or {}).get("sha256")
    cached = cache_dir / f"{sha}-{file['filename']}" if sha else None
    if cached and cached.exists():
        return cached.read_bytes()
    resp = client.get(file["url"])
    resp.raise_for_status()
    data = resp.content
    if sha and hashlib.sha256(data).hexdigest() != sha:
        raise IntegrityError(f"{file['filename']}: SHA-256 does not match PyPI's digest")
    if cached:
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
    return data


def iter_members(filename: str, data: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield (path, bytes) for regular files inside an sdist/wheel, without extracting."""
    count = 0
    if filename.endswith((".whl", ".zip", ".egg")):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                    continue
                count += 1
                if count > MAX_MEMBERS:
                    return
                yield info.filename, zf.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for member in tf:
                if not member.isfile() or member.size > MAX_MEMBER_BYTES:
                    continue  # skips symlinks, hardlinks, devices
                count += 1
                if count > MAX_MEMBERS:
                    return
                fh = tf.extractfile(member)
                if fh:
                    yield member.name, fh.read()


def scan_release(
    package: str, version: str, release_files: list[dict], cache_dir: Path, client: httpx.Client
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for f in pick_files(release_files):
        context = "sdist" if f.get("packagetype") == "sdist" else "wheel"
        try:
            data = download(f, cache_dir, client)
            hits: list[Hit] = []
            for path, content in iter_members(f["filename"], data):
                hits.extend(scan_file(path, content, context))
        except IntegrityError as exc:
            findings.append(
                Finding(
                    package,
                    "package",
                    "artifact_scan",
                    "CODE-BIN",
                    "critical",
                    "malicious-code",
                    "Downloaded file does not match PyPI digest",
                    detail=str(exc),
                    location=f["filename"],
                    target_version=version,
                )
            )
            continue
        except (httpx.HTTPError, tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as exc:
            log.warning("could not scan %s: %s", f["filename"], exc)
            continue
        for h in hits:
            path_inside_archive = h.file.split("/", 1)[-1]
            if (h.rule_id, path_inside_archive) in seen:
                continue
            seen.add((h.rule_id, path_inside_archive))
            r = rule(h.rule_id)
            findings.append(
                Finding(
                    target=package,
                    target_type="package",
                    detector="artifact_scan",
                    rule_id=h.rule_id,
                    severity=h.effective_severity,
                    category=r.category,
                    title=r.title,
                    detail=h.detail or r.why,
                    location=f"{f['filename']}:{h.file}:{h.line}",
                    evidence=h.evidence,
                    target_version=version,
                )
            )
    return findings
