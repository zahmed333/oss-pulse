"""Rule catalogue. Every finding references one of these, so reports can explain *what*
was detected, *why it matters*, and *which real attack* used the technique.

Run `oss-pulse rules` to print this catalogue.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    category: str
    title: str
    why: str
    seen_in: str = ""


_RULES = [
    Rule(
        "OSV-MAL",
        "critical",
        "known-malicious",
        "Package is a known malicious package",
        "OSV.dev lists a MAL- advisory (OpenSSF malicious-packages) for this package.",
        "Thousands of typosquats and credential stealers on PyPI/npm",
    ),
    Rule(
        "OSV-VULN",
        "high",
        "vulnerability",
        "Resolved version has known vulnerabilities",
        "A fresh install gets a version with a published advisory.",
    ),
    Rule(
        "OSV-RANGE",
        "medium",
        "vulnerability",
        "Version range still allows vulnerable versions",
        "Your specifier permits versions with advisories; a pinned or cached install may use one.",
    ),
    Rule(
        "TYPO-001",
        "high",
        "typosquatting",
        "Name is one edit away from a popular package",
        "Typosquats rely on a single mistyped character (reqeusts, python-dateutils).",
        "Long-running PyPI typosquatting campaigns",
    ),
    Rule(
        "TYPO-002",
        "medium",
        "typosquatting",
        "Name wraps a popular package name",
        "Affix squats ('requests-py', 'py-numpy') impersonate well-known projects.",
    ),
    Rule(
        "CONF-001",
        "critical",
        "dependency-confusion",
        "Internal package name exists on public PyPI",
        "pip may install the public package instead of your private one.",
        "Dependency-confusion attacks on large companies (2021 onwards)",
    ),
    Rule(
        "SRC-001",
        "medium",
        "provenance",
        "No source repository linked",
        "Without a linked repository the code cannot be reviewed or compared with the release.",
    ),
    Rule(
        "NEW-001",
        "medium",
        "provenance",
        "Package first published very recently",
        "Most malicious packages are days old when they are installed.",
    ),
    Rule(
        "REL-001",
        "medium",
        "release-integrity",
        "Resolved version was released very recently",
        "Hijacked releases are usually caught and yanked within hours or days; waiting a few "
        "days before adopting a new version avoids most of them.",
        "Qix/debug+chalk (Sep 2025), Shai-Hulud, Nx: malicious versions were live for hours",
    ),
    Rule(
        "REL-002",
        "medium",
        "release-integrity",
        "Recent release after a long dormancy",
        "A dormant project that suddenly ships a new version is a classic account-takeover signal.",
    ),
    Rule(
        "REL-003",
        "medium",
        "release-integrity",
        "Released version has no matching git tag",
        "The published artifact may not correspond to any reviewed source in the repository.",
        "Ultralytics (Dec 2024): malicious code existed only on PyPI, never in git",
    ),
    Rule(
        "PROV-001",
        "high",
        "release-integrity",
        "Trusted Publishing provenance disappeared in this release",
        "The previous release had a PEP 740 attestation and this one does not, which is how a "
        "stolen API token upload looks.",
        "Ultralytics 8.3.45/8.3.46 were pushed directly with a leftover API token",
    ),
    Rule(
        "PROV-002",
        "high",
        "release-integrity",
        "Provenance points to a different repository",
        "The release was built from a repository other than the one the package links to.",
    ),
    Rule(
        "CODE-PTH",
        "high",
        "malicious-code",
        "Executable .pth file",
        ".pth files run on every Python start-up, before any of your code. Legitimate uses are "
        "rare; malware uses them for persistence.",
    ),
    Rule(
        "CODE-SETUP",
        "high",
        "malicious-code",
        "setup.py runs commands or network calls",
        "Code in setup.py runs at install time with your user's privileges.",
    ),
    Rule(
        "CODE-CMDCLASS",
        "low",
        "malicious-code",
        "setup.py overrides build/install commands",
        "Common for C extensions, but also a place to hide payloads; review if other signals fire.",
    ),
    Rule(
        "CODE-OBF",
        "high",
        "malicious-code",
        "Obfuscated code execution",
        "exec/eval of base64/zlib/marshal-decoded data hides what actually runs.",
    ),
    Rule(
        "CODE-DLEXEC",
        "high",
        "malicious-code",
        "Downloads and executes code",
        "Fetching a second stage at install or run time ('curl | sh', urlretrieve + exec).",
    ),
    Rule(
        "CODE-SECRETS",
        "high",
        "malicious-code",
        "Reads credentials or wallet data",
        "Access to ~/.ssh, cloud credentials, .pypirc/.npmrc, browser stores or crypto wallets.",
        "Shai-Hulud and Contagious Interview payloads harvest tokens and wallets",
    ),
    Rule(
        "CODE-ENVDUMP",
        "high",
        "malicious-code",
        "Serialises the whole environment",
        "Dumping os.environ / process.env and sending it is how CI tokens are stolen.",
        "Nx/s1ngularity, GhostActions",
    ),
    Rule(
        "CODE-EXFIL",
        "high",
        "malicious-code",
        "Known exfiltration endpoint",
        "Discord/Telegram webhooks, paste sites, tunnels or raw IP URLs in package code.",
    ),
    Rule(
        "CODE-CLIP",
        "high",
        "malicious-code",
        "Clipboard access combined with wallet addresses",
        "Clipboard hijackers swap copied crypto addresses for the attacker's.",
    ),
    Rule(
        "CODE-BIN",
        "medium",
        "malicious-code",
        "Executable binary shipped in source package",
        "Binaries in an sdist or repository cannot be reviewed.",
    ),
    Rule(
        "CODE-HIDDEN",
        "high",
        "malicious-code",
        "Code hidden off-screen or in fake media files",
        "Hundreds of spaces before a payload, or JavaScript inside a .png/.woff file.",
        "Contagious Interview coding assignments",
    ),
    Rule(
        "CODE-JSOBF",
        "high",
        "malicious-code",
        "Obfuscated JavaScript",
        "eval/new Function over decoded strings, or very long single-line minified payloads "
        "outside build output.",
    ),
    Rule(
        "EVADE-IGNORE",
        "high",
        "evasion",
        "The folder ships its own OSS Pulse ignore file",
        "A folder under inspection must not be able to silence the scan of itself. The file "
        "is not applied; the finding is high when it would have hidden other findings.",
    ),
    Rule(
        "AUTO-VSCODE",
        "critical",
        "auto-execution",
        "VS Code task runs automatically when the folder is opened",
        "runOn: folderOpen executes a command as soon as the project is opened.",
        "Contagious Interview fake job interviews (DPRK); the Binance 2026 heist began with one",
    ),
    Rule(
        "AUTO-VSCODE-SETTINGS",
        "high",
        "auto-execution",
        "Workspace enables automatic tasks",
        "The repository tries to turn on task.allowAutomaticTasks for itself.",
    ),
    Rule(
        "AUTO-NPM",
        "medium",
        "auto-execution",
        "npm lifecycle script runs on install",
        "preinstall/install/postinstall/prepare scripts run during 'npm install'.",
        "Shai-Hulud, Nx, Contagious Interview npm packages",
    ),
    Rule(
        "AUTO-NPM-NET",
        "critical",
        "auto-execution",
        "npm install script downloads or executes remote code",
        "An install hook that fetches and runs code is the payload delivery itself.",
    ),
    Rule(
        "AUTO-HOOK",
        "medium",
        "auto-execution",
        "Git hooks configured inside the repository",
        "Hooks run on commit/checkout; committed hook directories are executed by tools like husky.",
    ),
    Rule(
        "GHA-PRT",
        "high",
        "ci-cd",
        "pull_request_target checks out untrusted PR code",
        "Runs fork code with repository secrets and a write token.",
        "Nx/s1ngularity (Aug 2025)",
    ),
    Rule(
        "GHA-INJECT",
        "high",
        "ci-cd",
        "Untrusted input interpolated into a run: script",
        "${{ github.event.* }} inside run: allows shell injection from issue/PR titles or branches.",
        "Ultralytics (Dec 2024)",
    ),
    Rule(
        "GHA-UNPINNED",
        "medium",
        "ci-cd",
        "Third-party action not pinned to a commit SHA",
        "Tags are mutable; an attacker who controls the action can retag it.",
        "tj-actions/changed-files (Mar 2025)",
    ),
    Rule(
        "GHA-PERMS",
        "low",
        "ci-cd",
        "Workflow has no explicit token permissions",
        "Without a permissions: block the GITHUB_TOKEN may have broad write access.",
    ),
    Rule(
        "GHA-CACHE-RELEASE",
        "medium",
        "ci-cd",
        "Release workflow restores a shared cache",
        "A poisoned cache can inject code into published artifacts.",
        "Ultralytics (Dec 2024)",
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
