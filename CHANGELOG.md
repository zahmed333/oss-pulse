# Changelog

All notable changes for people using oss-pulse. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/) once 1.0 is released.

## [Unreleased]

First public version (0.1.0, not yet on PyPI).

### Added

- `oss-pulse scan <folder>` reads a folder without running anything and reports code that runs when it is opened in VS Code, installed with npm or pip, or committed; code hidden in fake media files or behind long whitespace; credential, wallet and environment theft; lookalike dependency names; and GitHub Actions workflows a pull request can hijack.
- `oss-pulse check <requirements.txt | pyproject.toml>` checks each dependency against OSV.dev (including known-malicious packages), looks for lookalike names and dependency confusion, compares Trusted Publishing attestations with the previous release, scans the release files pip would download, and reports maintenance signals separately from threats.
- Plain `oss-pulse` checks the current folder; `oss-pulse init` writes a GitHub Actions, Azure DevOps or GitLab pipeline; `oss-pulse accept` records a reviewed finding with a reason and date; `oss-pulse doctor` shows which services a machine can reach; `oss-pulse --version`.
- CI outputs for any system: JUnit XML, SARIF 2.1.0, native log annotations, and one pull-request comment on GitHub and Azure DevOps. Templates for Azure Pipelines and GitLab, a GitHub Action and a pre-commit hook.
- Endpoints can point at mirrors or GitHub Enterprise Server; `--skip` avoids services a network blocks.

- `examples/`: five harmless folders with known verdicts (fake take-home, npm install hook, lookalike names, a hijackable GitHub workflow, a clean project).
- The verdict line now matches what was found: "Don't install this folder's dependencies" for install hooks, "Don't merge or run these workflows" for CI findings, and a lookalike-name message for typosquats.

### Security

- A scanned folder can't configure its own scan: an `.osspulseignore` inside it is reported, not applied.
- Text quoted from scanned files can't inject terminal escapes, Markdown, GitHub workflow commands or Azure Pipelines `##vso` commands.

### Detection

- Script code disguised as a font or image is now read like any other script, so the report says what it does (reads SSH keys, sends data to a Discord webhook) and not only that it is disguised.
- The environment packed into data that the same file sends to an exfiltration endpoint (`env: process.env` inside a posted object) is reported as CODE-ENVDUMP. Passing `{ env: process.env }` to a child process is not.

### Precision

- No finding at medium or above on the 250 most-downloaded PyPI packages; method and limits in [docs/benchmarks.md](docs/benchmarks.md).

### Install

- `pip install oss-pulse` is enough for `scan` (38 MB). `check` needs the `[check]` extra, which adds DuckDB, PyArrow and dbt.
