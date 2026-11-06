# Running oss-pulse in CI/CD

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
| `ossPulseRef` | `main` | Git ref of oss-pulse to install; pin a commit SHA |
| `commentOnPullRequest` | `true` | Keep one oss-pulse comment on the pull request |

The pull-request comment uses the pipeline's `System.AccessToken`. Give the project's build service "Contribute to pull requests" on the repository (Project settings, Repositories, Security). Without it the comment step logs a warning and the build continues.

Private feeds: `check` looks names up on public PyPI. Pass your internal package names in `internalPackages` so oss-pulse reports them only if the same name exists publicly (dependency confusion) and never sends their contents anywhere. Self-hosted agents need outbound HTTPS to pypi.org, files.pythonhosted.org, api.github.com, api.osv.dev and api.securityscorecards.dev; anything unreachable is reported as "not checked".

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
pip install "git+https://github.com/zahmed333/oss-pulse@main"
oss-pulse scan . --fail-on high --junit oss-pulse-scan.xml --sarif oss-pulse-scan.sarif
oss-pulse check requirements.txt --fail-on high --junit oss-pulse-check.xml --data-dir .oss-pulse
```

In Jenkins, `junit 'oss-pulse-*.xml'` in a `post { always { ... } }` block shows the findings as failed tests.
