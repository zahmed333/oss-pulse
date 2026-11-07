"""The wheel must carry everything `scan` and `check` read at runtime.

Before this test existed a fresh `pip install` crashed on the first `scan`: the typosquat
list was caught by a `.gitignore` rule and the dbt project was never in the wheel. The
editable install used for development hid both problems, so CI also smoke-tests the
built wheel (`wheel-smoke` in .github/workflows/ci.yml)."""

from __future__ import annotations

import shutil
import subprocess
import tomllib

import pytest
import yaml

from oss_pulse.config import PROJECT_ROOT
from oss_pulse.supplychain import typosquat

DBT_DIR_KEYS = (
    "model-paths",
    "macro-paths",
    "test-paths",
    "seed-paths",
    "snapshot-paths",
    "analysis-paths",
)


def test_bundled_typosquat_list_is_not_git_ignored():
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    rel = typosquat.BUNDLED.relative_to(PROJECT_ROOT)
    res = subprocess.run(["git", "check-ignore", "-q", str(rel)], cwd=PROJECT_ROOT)
    if res.returncode == 128:
        pytest.skip("not a git checkout")
    assert res.returncode == 1, f"{rel} is git-ignored, so it would be missing from the wheel"


def test_wheel_force_includes_the_whole_dbt_project():
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    forced = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    project_dir = PROJECT_ROOT / "transform"
    project = yaml.safe_load((project_dir / "dbt_project.yml").read_text())

    needed = {"transform/dbt_project.yml", "transform/profiles.yml"}
    for key in DBT_DIR_KEYS:
        for sub in project.get(key, []):
            path = project_dir / sub
            if path.is_dir() and any(p.is_file() for p in path.rglob("*")):
                needed.add(f"transform/{sub}")

    missing = needed - set(forced)
    assert not missing, f"not shipped in the wheel: {sorted(missing)}"
    for src in needed:
        assert forced[src] == "oss_pulse/dbt_project/" + src.removeprefix("transform/")


def test_this_repository_passes_its_own_scan():
    """CI runs `oss-pulse scan . --fail-on high --ignore-file .osspulseignore`; a new test
    fixture full of attack shapes must be listed in .osspulseignore before it is pushed."""
    from oss_pulse.scan import run_scan
    from oss_pulse.supplychain.findings import SEVERITY_RANK

    result = run_scan(PROJECT_ROOT, ignore_file=PROJECT_ROOT / ".osspulseignore")
    blocking = [
        f"{f.location} {f.rule_id}"
        for f in result.findings
        if SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"]
    ]
    assert not blocking, blocking
