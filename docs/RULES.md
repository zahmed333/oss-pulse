# Detection rules

Generated from `src/oss_pulse/supplychain/rules.py` (`oss-pulse rules` prints the same list).
Maintenance signals (archived, inactive, bus factor, ...) are computed in
`transform/models/marts/mart_dependency_risk.sql`, with thresholds as dbt vars.

## known-malicious

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `OSV-MAL` | critical | Package is a known malicious package | OSV.dev lists a MAL- advisory (OpenSSF malicious-packages) for this package. | Thousands of typosquats and credential stealers on PyPI/npm |

## vulnerability

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `OSV-VULN` | high | Resolved version has known vulnerabilities | A fresh install gets a version with a published advisory. | – |
| `OSV-RANGE` | medium | Version range still allows vulnerable versions | Your specifier permits versions with advisories; a pinned or cached install may use one. | – |

## typosquatting

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `TYPO-001` | high | Name is one edit away from a popular package | Typosquats rely on a single mistyped character (reqeusts, python-dateutils). | Long-running PyPI typosquatting campaigns |
| `TYPO-002` | medium | Name wraps a popular package name | Affix squats ('requests-py', 'py-numpy') impersonate well-known projects. | – |

## dependency-confusion

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `CONF-001` | critical | Internal package name exists on public PyPI | pip may install the public package instead of your private one. | Dependency-confusion attacks on large companies (2021 onwards) |

## provenance

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `SRC-001` | medium | No source repository linked | Without a linked repository the code cannot be reviewed or compared with the release. | – |
| `NEW-001` | medium | Package first published very recently | Most malicious packages are days old when they are installed. | – |

## release-integrity

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `REL-001` | medium | Resolved version was released very recently | Hijacked releases are usually caught and yanked within hours or days; waiting a few days before adopting a new version avoids most of them. | Qix/debug+chalk (Sep 2025), Shai-Hulud, Nx: malicious versions were live for hours |
| `REL-002` | medium | Recent release after a long dormancy | A dormant project that suddenly ships a new version is a classic account-takeover signal. | – |
| `REL-003` | medium | Released version has no matching git tag | The published artifact may not correspond to any reviewed source in the repository. | Ultralytics (Dec 2024): malicious code existed only on PyPI, never in git |
| `PROV-001` | high | Trusted Publishing provenance disappeared in this release | The previous release had a PEP 740 attestation and this one does not, which is how a stolen API token upload looks. | Ultralytics 8.3.45/8.3.46 were pushed directly with a leftover API token |
| `PROV-002` | high | Provenance points to a different repository | The release was built from a repository other than the one the package links to. | – |

## malicious-code

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `CODE-PTH` | high | Executable .pth file | .pth files run on every Python start-up, before any of your code. Legitimate uses are rare; malware uses them for persistence. | – |
| `CODE-SETUP` | high | setup.py runs commands or network calls | Code in setup.py runs at install time with your user's privileges. | – |
| `CODE-CMDCLASS` | low | setup.py overrides build/install commands | Common for C extensions, but also a place to hide payloads; review if other signals fire. | – |
| `CODE-OBF` | high | Obfuscated code execution | exec/eval of base64/zlib/marshal-decoded data hides what actually runs. | – |
| `CODE-DLEXEC` | high | Downloads and executes code | Fetching a second stage at install or run time ('curl | sh', urlretrieve + exec). | – |
| `CODE-SECRETS` | high | Reads credentials or wallet data | Access to ~/.ssh, cloud credentials, .pypirc/.npmrc, browser stores or crypto wallets. | Shai-Hulud and Contagious Interview payloads harvest tokens and wallets |
| `CODE-ENVDUMP` | high | Serialises the whole environment | Dumping os.environ / process.env and sending it is how CI tokens are stolen. | Nx/s1ngularity, GhostActions |
| `CODE-EXFIL` | high | Known exfiltration endpoint | Discord/Telegram webhooks, paste sites, tunnels or raw IP URLs in package code. | – |
| `CODE-CLIP` | high | Clipboard access combined with wallet addresses | Clipboard hijackers swap copied crypto addresses for the attacker's. | – |
| `CODE-BIN` | medium | Executable binary shipped in source package | Binaries in an sdist or repository cannot be reviewed. | – |
| `CODE-HIDDEN` | high | Code hidden off-screen or in fake media files | Hundreds of spaces before a payload, or JavaScript inside a .png/.woff file. | Contagious Interview coding assignments |
| `CODE-JSOBF` | high | Obfuscated JavaScript | eval/new Function over decoded strings, or very long single-line minified payloads outside build output. | – |

## auto-execution

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `AUTO-VSCODE` | critical | VS Code task runs automatically when the folder is opened | runOn: folderOpen executes a command as soon as the project is opened. | Contagious Interview fake job interviews (DPRK); the Binance 2026 heist began with one |
| `AUTO-VSCODE-SETTINGS` | high | Workspace enables automatic tasks | The repository tries to turn on task.allowAutomaticTasks for itself. | – |
| `AUTO-NPM` | medium | npm lifecycle script runs on install | preinstall/install/postinstall/prepare scripts run during 'npm install'. | Shai-Hulud, Nx, Contagious Interview npm packages |
| `AUTO-NPM-NET` | critical | npm install script downloads or executes remote code | An install hook that fetches and runs code is the payload delivery itself. | – |
| `AUTO-HOOK` | medium | Git hooks configured inside the repository | Hooks run on commit/checkout; committed hook directories are executed by tools like husky. | – |

## ci-cd

| Rule | Severity | Detects | Why it matters | Seen in |
|---|---|---|---|---|
| `GHA-PRT` | high | pull_request_target checks out untrusted PR code | Runs fork code with repository secrets and a write token. | Nx/s1ngularity (Aug 2025) |
| `GHA-INJECT` | high | Untrusted input interpolated into a run: script | ${{ github.event.* }} inside run: allows shell injection from issue/PR titles or branches. | Ultralytics (Dec 2024) |
| `GHA-UNPINNED` | medium | Third-party action not pinned to a commit SHA | Tags are mutable; an attacker who controls the action can retag it. | tj-actions/changed-files (Mar 2025) |
| `GHA-PERMS` | low | Workflow has no explicit token permissions | Without a permissions: block the GITHUB_TOKEN may have broad write access. | – |
| `GHA-CACHE-RELEASE` | medium | Release workflow restores a shared cache | A poisoned cache can inject code into published artifacts. | Ultralytics (Dec 2024) |
