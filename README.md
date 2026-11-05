<p><picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/logo-dark.svg">
  <img alt="oss-pulse" src="docs/brand/logo.svg" height="32">
</picture></p>

**oss-pulse checks code for malware before you run it.** Point it at a folder someone sent you, or at your project's Python dependencies. It reads the files and package metadata, executes nothing, and tells you which lines would run code on your machine and when.

## The problem it solves

oss-pulse is built for two attacks that antivirus and vulnerability scanners don't catch.

**1. The take-home assignment that hacks you when you open it.** A "recruiter" sends a coding test as a zip or a GitHub link. Inside, `.vscode/tasks.json` has a task set to `"runOn": "folderOpen"`, so VS Code runs it the moment you trust the folder. The script it runs is disguised as a font file. This is the Contagious Interview campaign, named by security researchers in 2023, aimed at developers with crypto wallets on their laptops. Antivirus doesn't flag it, because it is a text file in a project, not an executable.

**2. A package you already trust ships a poisoned release.** In December 2024, Ultralytics 8.3.41 was published to PyPI with a crypto miner in it. The malicious code was only in the file on PyPI, never in the GitHub repository, so reviewing the source on GitHub would not have shown it. `pip-audit` and Dependabot only report vulnerabilities that are already in a database, and on release day this one wasn't.

oss-pulse checks for both before anything runs.

## Try it

```sh
pip install git+https://github.com/zahmed333/oss-pulse   # not on PyPI yet

oss-pulse scan ~/take-home --fail-on high   # a folder someone sent you
oss-pulse check requirements.txt            # the packages you are about to install
oss-pulse rules                             # every rule, and the attack it comes from
```

Here is the report for an inert copy of a fake take-home (the folder is built in the test suite; nothing in it is real malware):

| Severity | Rule | Finding | Where | Evidence |
|---|---|---|---|---|
| critical | AUTO-VSCODE | VS Code task runs automatically when the folder is opened | `.vscode/tasks.json:8` | `sync-fonts: node public/fonts/fa-solid-900.woff2` |
| high | CODE-HIDDEN | Script content inside a .woff2 file | `public/fonts/fa-solid-900.woff2:1` | `const s = require('child_process'); s.exec(x)` |
| high | TYPO-001 | Dependency is one edit away from `requests` | `requirements.txt` | `reqeusts` |
| medium | AUTO-NPM | npm script runs on install | `package.json:1` | `"postinstall": "node public/fonts/fa-solid-900.woff2"` |

Opening the folder runs a "font" that is really JavaScript able to start programs, and `npm install` runs the same file again. The command exits 1, so `oss-pulse scan ~/take-home --fail-on high && code ~/take-home` will not open it.

## What each command checks

`oss-pulse scan <folder>` needs no network and never executes anything in the folder. It looks for:

- tasks and settings that make VS Code run code when the folder opens;
- npm install hooks, `setup.py` side effects, `.pth` files and git hooks that run on install or commit;
- code hidden in fake font or image files, or pushed off-screen with whitespace;
- reads of wallet files, browser passwords, SSH keys and environment variables, and Discord or Telegram upload URLs;
- misspelled dependency names, and GitHub Actions workflows that can be hijacked by a pull request.

A folder can't switch these checks off: an `.osspulseignore` file inside it is reported as a finding, not obeyed.

`oss-pulse check <requirements.txt | pyproject.toml>` looks at each dependency:

- whether OSV.dev lists it as malicious, or the version you'd get has a known advisory;
- whether its name imitates a popular package, or your company's internal package name has appeared on public PyPI (dependency confusion);
- whether the newest release looks hijacked: it lost the PyPI Trusted Publishing attestation the previous release had, it came after a long silence, or it has no matching git tag;
- what the actual files pip would download contain, so code that exists only on PyPI (the Ultralytics case) is still caught;
- whether the project is still maintained (archived, no commits, a single maintainer). These are reported as maintenance issues, not as attacks.

If GitHub, OSV or Scorecard can't be reached, the report says which source was missing. Every rule and its source incident is in [docs/RULES.md](docs/RULES.md).

## In CI

```yaml
- uses: actions/checkout@v4
- uses: zahmed333/oss-pulse@<commit-sha>   # pin to a commit, not a tag
  with:
    dependency-file: requirements.txt
    fail-on: high
    internal-packages: acme-auth, acme-utils
```

The Action fails the job at the level you choose and keeps one PR comment up to date. This repository runs it on itself: [supply-chain.yml](.github/workflows/supply-chain.yml). Details in [docs/github-action.md](docs/github-action.md).

## Why there is a data pipeline inside

`scan` is plain Python. `check` is a small data pipeline. The table below says what each part does.

One check pulls data from seven sources: your dependency file, PyPI metadata, PyPI's attestation API, the release files, GitHub, OSV and Scorecard. Several rules need data from more than one of them. For example, "this release has no attestation, but the previous one did" compares two releases, and "this package links to repository X but was attested from repository Y" combines PyPI and GitHub data. Those rules are written as SQL joins.

| Step | What it does | Why it is needed |
|---|---|---|
| Fetch and cache (Python, httpx) | Downloads each source once and saves the raw response to disk | Re-running a check makes no new requests, and every finding can be traced to the exact response it came from, for example when a maintainer disputes a result. |
| Detectors (Python AST and regex) | Read release files and folders as data, in memory, with size limits and SHA-256 checks | Untrusted code must never be imported, unpacked to disk or run. |
| Bronze tables (Parquet) | Store all sources in one typed format, partitioned by date | Seven sources with different shapes become tables with fixed schemas. A source that changes its API breaks loudly here instead of silently producing wrong verdicts. |
| Rules and verdicts (dbt on DuckDB) | Join the sources and apply release and maintenance rules; dbt tests check the results | Rules live in reviewable SQL with tests, and thresholds such as "a release under 7 days old" are settings, not code edits. DuckDB runs inside the process: no database server. |
| Report | Markdown for PR comments, JSON for scripts, an exit code for CI | One table of findings feeds every output, so a new detector needs no reporting changes. |

The same storage also powers a second, separate use: tracking the health of open-source projects over time from the GH Archive event stream (`oss-pulse demo`, `make dashboard`, `make dagster`). That part uses Dagster for hourly scheduling and Streamlit for a dashboard. It is not needed for `scan` or `check`.

## How results are decided

A missing signal is reported, never guessed. If GitHub is unreachable, the report says "GitHub not reachable" rather than "repository not found", and `--strict` turns any missing source into a CI failure.

False positives are fixed like any other bug, because people stop using a tool that flags numpy. Behaviour that legitimate libraries need, such as reading `~/.aws/credentials` or compiling C extensions, only counts when stronger evidence is also present. This is not solved yet: on the 250 most-downloaded PyPI packages, 16% still get a medium or higher finding. A fix that brings that to zero has been prototyped and is first on the [roadmap](ROADMAP.md).

Every result names its rule, file, line and the exact bytes that matched. There is no combined risk score.

## FAQ

### How do I check if a coding assignment from a recruiter is malware?

Before you open it, run `oss-pulse scan <folder>`. It reads the folder without executing anything and reports VS Code tasks that run on open (`"runOn": "folderOpen"`), npm `postinstall` hooks, scripts disguised as fonts or images, and code that reads wallets, browser passwords or SSH keys. If it reports anything at critical or high, don't open the folder in VS Code and don't run `npm install`. If VS Code asks whether you trust the authors, choose "No, I don't trust the authors": tasks don't run in Restricted Mode.

### What is the Contagious Interview attack?

A campaign, named by security researchers in 2023, in which fake recruiters send developers a take-home project that runs malware when the folder is opened or its dependencies are installed. It targets developers in crypto and Web3, and often steals wallet and browser data.

### How do I detect a malicious or typosquatted PyPI package?

Run `oss-pulse check requirements.txt` (or `pyproject.toml`). For each dependency it checks OSV.dev for known-malicious packages, compares the name against the 15,000 most downloaded PyPI packages to catch lookalikes such as `reqeusts`, and scans the actual sdist and wheel pip would download for install-time code, `.pth` files and decoded-and-executed payloads.

### How can I tell if a PyPI release was hijacked?

`check` compares the newest release with the one before it. Warning signs it reports: the release lost the PyPI Trusted Publishing attestation (PEP 740) the previous release had, it was attested from a different repository than the one the project links to, it appeared after a long quiet period, or it has no matching git tag.

### How is this different from pip-audit, Dependabot or OSV-Scanner?

Those look up known vulnerabilities in a database. oss-pulse also reads the code and release files themselves, so it can flag a malicious release on the day it is published, before anyone has filed an advisory, and it can vet a whole folder before you open it. Use it alongside a vulnerability scanner, not instead of one.

### How do I block malicious dependencies in GitHub Actions?

Add the oss-pulse Action to your workflow (see [In CI](#in-ci)) with `fail-on: high`. Pull requests that add a high-risk dependency fail, and the Action posts one PR comment explaining why.

### Does it run or upload my code?

No. `scan` makes no network requests. `check` sends package names to PyPI, OSV.dev, GitHub and OpenSSF Scorecard to look them up, and nothing else. Neither command executes code from what it inspects.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
make install      # editable install with dev, orchestration and dashboard extras
make test         # fully offline
make demo         # ecosystem pipeline on synthetic GH Archive data
oss-pulse check pyproject.toml -v
```

Set `GITHUB_TOKEN` for 5,000 GitHub API requests per hour (60 without one).

## Limitations

- It is static analysis plus metadata. A determined attacker can evade heuristics, so treat a clean report as "no known red flags", not "safe".
- It covers Python dependencies and repository contents. It does not check Homebrew, npm dependency trees, IDE extensions, or what is already running on your machine.
- Only direct dependencies are checked; lockfile and transitive support is on the [roadmap](ROADMAP.md).

## License

MIT
