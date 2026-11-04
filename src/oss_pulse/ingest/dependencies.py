"""Turn a project's dependency file into a list of GitHub repositories to assess.

Supported inputs: `pyproject.toml` (PEP 621 `[project]`, PEP 735 `[dependency-groups]`,
Poetry) and pip `requirements*.txt`. Each package is resolved to its source repository
using the metadata its maintainers published on PyPI (`project_urls`, `home_page`).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

GITHUB_URL = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)
# Not repositories, even though they live on github.com.
_NOT_REPOS = {"sponsors", "orgs", "apps", "marketplace", "features", "topics", "settings"}
# project_urls keys, most to least trustworthy as "the source code lives here".
_KEY_PRIORITY = (
    "source",
    "repository",
    "code",
    "github",
    "homepage",
    "home",
    "issues",
    "tracker",
    "bug",
    "changelog",
    "documentation",
    "docs",
)


@dataclass(frozen=True)
class DeclaredDependency:
    name: str  # PEP 503 canonical name
    requirement: str
    group: str
    declared_in: str


def _parse_requirement(line: str) -> Requirement | None:
    try:
        return Requirement(line)
    except InvalidRequirement:
        return None


def parse_requirements_txt(path: Path) -> list[DeclaredDependency]:
    deps = []
    for raw in path.read_text().splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://", ".", "/")):
            continue  # comments, pip options (-r, -e, --hash...), URLs and local paths
        req = _parse_requirement(line.rstrip("\\").strip())
        if req:
            deps.append(
                DeclaredDependency(canonicalize_name(req.name), str(req), "main", path.name)
            )
    return deps


def parse_pyproject(path: Path, include_optional: bool = True) -> list[DeclaredDependency]:
    doc = tomllib.loads(path.read_text())
    groups: dict[str, list[str]] = {}
    project = doc.get("project", {})
    groups["main"] = list(project.get("dependencies", []))
    if include_optional:
        for extra, reqs in project.get("optional-dependencies", {}).items():
            groups[f"extra:{extra}"] = list(reqs)
        for group, reqs in doc.get("dependency-groups", {}).items():
            groups[f"group:{group}"] = [r for r in reqs if isinstance(r, str)]

    poetry = doc.get("tool", {}).get("poetry", {})
    poetry_groups = {"main": poetry.get("dependencies", {})}
    if include_optional:
        poetry_groups["group:dev"] = poetry.get("dev-dependencies", {})
        for g, body in poetry.get("group", {}).items():
            poetry_groups[f"group:{g}"] = body.get("dependencies", {})
    for group, table in poetry_groups.items():
        groups.setdefault(group, []).extend(n for n in table if n.lower() != "python")

    deps, seen = [], set()
    for group, reqs in groups.items():
        for spec in reqs:
            req = _parse_requirement(spec)
            if not req:
                continue
            name = canonicalize_name(req.name)
            if name == canonicalize_name(project.get("name", "")):
                continue  # self-references like "mypkg[extra]"
            if name not in seen:
                seen.add(name)
                deps.append(DeclaredDependency(name, str(req), group, path.name))
    return deps


def parse_dependency_file(path: Path, include_optional: bool = True) -> list[DeclaredDependency]:
    if path.name == "pyproject.toml":
        return parse_pyproject(path, include_optional)
    if path.suffix in {".txt", ".in"}:
        return parse_requirements_txt(path)
    raise ValueError(
        f"unsupported dependency file: {path.name} (expected pyproject.toml or requirements*.txt)"
    )


def _github_repo(url: str) -> str | None:
    m = GITHUB_URL.search(url or "")
    if not m:
        return None
    owner, name = m.group(1), m.group(2)
    name = re.sub(r"\.git$", "", name)
    if owner.lower() in _NOT_REPOS or not name or name.startswith("."):
        return None
    return f"{owner}/{name}"


def resolve_repo(pypi_doc: dict) -> tuple[str | None, str]:
    """Return (owner/name, how-it-was-resolved) from a PyPI JSON document."""
    info = pypi_doc.get("info") or {}
    urls = {k.lower(): v for k, v in (info.get("project_urls") or {}).items() if v}
    for wanted in _KEY_PRIORITY:
        for key, url in urls.items():
            if wanted in key and (repo := _github_repo(url)):
                return repo, f"project_urls:{key}"
    for key, url in urls.items():
        if repo := _github_repo(url):
            return repo, f"project_urls:{key}"
    if repo := _github_repo(info.get("home_page") or ""):
        return repo, "home_page"
    return None, "unresolved"
