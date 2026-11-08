# Running oss-pulse in CI/CD

The quickest start: run `oss-pulse init` in your repository. It detects GitHub Actions, Azure DevOps or GitLab and writes a pipeline that runs on pull requests, pushes to main and weekly. The rest of this page is for tuning it.

oss-pulse runs the same way in every CI system: install it, run `scan` and `check`, and let the exit code gate the build. On top of that, each command can write outputs that CI systems already know how to show:

| Output | Flag | Shown in |
|---|---|---|
| JUnit XML | `--junit results.xml` | Azure DevOps Tests tab, GitLab merge request test report, Jenkins JUnit plugin, CircleCI, Buildkite, TeamCity |
| SARIF 2.1.0 | `--sarif results.sarif` | GitHub code scanning, Azure DevOps Scans tab (SARIF SAST Scans Tab extension), most security dashboards |
| Log annotations | `--annotations auto` (default) | file and line errors in Azure DevOps and GitHub Actions logs; plain `error: path:line` lines elsewhere |
| Markdown | `--markdown report.md` | Azure DevOps build summary (uploaded automatically), GitHub job summary, pull-request comments |
| JSON | `--json report.json` | your own scripts |

`--annotations auto` detects the CI system from its environment (`TF_BUILD`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`). Pass `azure`, `github`, `gitlab`, `jenkins`, `generic` or `none` to choose.

Exit codes are the same everywhere: `0` nothing at or above `--fail-on`, `1` something at or above it, `2` oss-pulse could not finish (bad arguments, PyPI unreachable, or `check --strict` with a missing signal). Treat `2` as a tool failure, not a finding.

Text quoted from scanned files is escaped for the CI system it is printed in, so a file cannot issue `##vso[...]` commands in Azure Pipelines or `::workflow-commands::` in GitHub Actions.

## Azure DevOps

Use the step template [`ci/azure-pipelines/oss-pulse.yml`](../ci/azure-pipelines/oss-pulse.yml). It installs oss-pulse, runs `scan` and `check`, publishes JUnit results to the Tests tab and SARIF as the `CodeAnalysisLogs` artifact, uploads the Markdown report to the build summary, keeps one comment on the pull request, and fails the build at your `failOn` level.

Reference it from GitHub through a service connection:

```yaml
resources:
  repositories:
    - repository: osspulse
      type: github
      name: zahmed333/oss-pulse
      endpoint: github            # your GitHub service connection
      ref: refs/heads/main        # better: a commit SHA you have reviewed

steps:
  - checkout: self
  - template: ci/azure-pipelines/oss-pulse.yml@osspulse
    parameters:
      dependencyFile: requirements.txt
      failOn: high
      internalPackages: [contoso-billing, contoso-auth]
```

If your organization does not allow GitHub service connections, copy the template into your own repository and reference it by path. A complete pipeline with a pull-request trigger and a weekly schedule is in [`ci/azure-pipelines/example.yml`](../ci/azure-pipelines/example.yml).

| Parameter | Default | Meaning |
|---|---|---|
| `dependencyFile` | `requirements.txt` | File for `check` (`''` skips it) |
| `scanPath` | `$(Build.SourcesDirectory)` | Folder for `scan` (`''` skips it) |
| `failOn` | `high` | `critical`, `high`, `medium` or `never` |
| `internalPackages` | `[]` | Your private package names, checked for dependency confusion |
| `ignoreFile` | `''` | Your reviewed suppressions, for example `.osspulseignore` |
| `pythonVersion` | `3.12` | Python used to run oss-pulse |
| `ossPulseRef` | a reviewed commit SHA | Git ref of oss-pulse to install; see [Pinning](#pinning) |
| `skip` | `''` | Sources not to contact, for example `osv,scorecard`; see [Locked-down networks](#locked-down-networks) |
| `runDoctor` | `true` | Log which services the agent can reach before the check |
| `commentOnPullRequest` | `true` | Keep one oss-pulse comment on the pull request |

The pull-request comment uses the pipeline's `System.AccessToken`. Give the project's build service "Contribute to pull requests" on the repository (Project settings, Repositories, Security). Without it the comment step logs a warning and the build continues.

Private feeds: `check` looks names up on public PyPI. Pass your internal package names in `internalPackages` so oss-pulse reports them only if the same name exists publicly (dependency confusion) and never sends their contents anywhere.

## Locked-down networks

`scan` never uses the network. `check` needs PyPI and, for full coverage, a few other services. Run `oss-pulse doctor` on the agent first: it tries each one and says what is lost without it.

```text
$ oss-pulse doctor
  ok           pypi       package metadata and release files
  ok           github     repository activity, archived flag and tags
  unreachable  osv        advisories are not checked
  ...
To avoid waiting on timeouts, skip what this machine can't reach:
  oss-pulse check requirements.txt --skip osv,scorecard
```

| Service | Default | Needed for | Override |
|---|---|---|---|
| PyPI JSON API | `https://pypi.org/pypi` | everything in `check` | `OSS_PULSE_PYPI_URL` |
| PyPI attestations | `https://pypi.org/integrity` | provenance rules | `OSS_PULSE_PYPI_INTEGRITY_URL` |
| PyPI files | `https://files.pythonhosted.org` | release-file malware scan | file links come from the PyPI metadata, so a mirror serves its own |
| GitHub API | `https://api.github.com` | maintenance signals, git-tag rule | `OSS_PULSE_GITHUB_API_URL` (GitHub Enterprise Server: `https://<host>/api/v3`) |
| OSV.dev | `https://api.osv.dev` | known vulnerabilities and malicious packages | `OSS_PULSE_OSV_URL` |
| OpenSSF Scorecard | `https://api.securityscorecards.dev` | Scorecard results | `OSS_PULSE_SCORECARD_URL` |
| Popular-package list | raw.githubusercontent.com | a fresh lookalike list | `OSS_PULSE_POPULAR_LIST_URL`; without it the bundled list is used |

What to do when a service is blocked:

- Ask for it to be allowed. The table above is the complete list; nothing else is contacted.
- Point oss-pulse at an approved mirror or proxy with the override variables. A PyPI mirror such as an Azure Artifacts upstream or Artifactory that serves the PyPI JSON API works for `OSS_PULSE_PYPI_URL`.
- Use a corporate proxy as it is: oss-pulse honours `HTTPS_PROXY`, `NO_PROXY` and `SSL_CERT_FILE`.
- Skip what stays blocked: `--skip osv,scorecard` (or `OSS_PULSE_SKIP`, or the `skip` template parameter). Skipped sources are listed as "not checked" in the report, and the check finishes without waiting on timeouts. Add `--strict` if a missing source should fail the build.

## Pinning

The templates install a fixed commit of oss-pulse (`0ee47501f69e`), so a pipeline does not change because oss-pulse's `main` changed. To upgrade, review the changes and set `ossPulseRef` (Azure DevOps), `OSS_PULSE_REF` (GitLab) or the `@<sha>` in a GitHub `uses:` to the new commit. In Azure DevOps, set the `ref:` of the `resources` block to the same commit, so the template and the code it installs match. Use commit SHAs rather than tags or branches: whoever controls a repository can move a tag, but not a commit.

## GitHub Actions

Use the composite Action in this repository; see [github-action.md](github-action.md). To send findings to GitHub code scanning as well, add `--sarif` and `github/codeql-action/upload-sarif`.

## GitLab CI

Include [`ci/gitlab/oss-pulse.gitlab-ci.yml`](../ci/gitlab/oss-pulse.gitlab-ci.yml):

```yaml
include:
  - remote: https://raw.githubusercontent.com/zahmed333/oss-pulse/main/ci/gitlab/oss-pulse.gitlab-ci.yml
variables:
  OSS_PULSE_DEPENDENCY_FILE: requirements.txt
  OSS_PULSE_FAIL_ON: high
```

Findings appear in the merge request's test report, and the Markdown, SARIF and JUnit files are kept as job artifacts.

## Jenkins, CircleCI, Buildkite and anything else

Run the commands directly and publish the JUnit file with your system's test-report step:

```sh
pip install "oss-pulse[check] @ git+https://github.com/zahmed333/oss-pulse"
oss-pulse scan . --fail-on high --junit oss-pulse-scan.xml --sarif oss-pulse-scan.sarif
oss-pulse check requirements.txt --fail-on high --junit oss-pulse-check.xml --data-dir .oss-pulse
```

In Jenkins, `junit 'oss-pulse-*.xml'` in a `post { always { ... } }` block shows the findings as failed tests.
