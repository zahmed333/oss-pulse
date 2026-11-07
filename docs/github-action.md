# Using OSS Pulse in GitHub Actions

Add this workflow to any repository that has a `pyproject.toml` or `requirements.txt`:

```yaml
name: supply-chain
on:
  pull_request:
  schedule:
    - cron: "17 6 * * 1"   # weekly: new advisories and hijacks appear without code changes

permissions:
  contents: read
  pull-requests: write      # to post the report as a PR comment

jobs:
  oss-pulse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: <owner>/oss-pulse@<commit-sha>   # pin to a SHA - see rule GHA-UNPINNED
        with:
          dependency-file: requirements.txt
          fail-on: high
          internal-packages: |
            acme-internal-utils
            acme-auth
```

The report is posted as one PR comment, updated on each push, and written to the job summary.

| Input | Default | Description |
|---|---|---|
| `dependency-file` | `pyproject.toml` | File to check (`''` skips the dependency check) |
| `scan-path` | `.` | Folder to scan statically (`''` skips the repository scan) |
| `fail-on` | `high` | `critical`, `high`, `medium` or `never` |
| `skip` | | Sources not to contact on runners that can't reach them, for example `osv,scorecard`. Reported as not checked. |
| `ignore-file` | | Your list of reviewed paths or rule ids to suppress in the repository scan. An `.osspulseignore` inside the scanned folder is never applied on its own, because the folder under inspection must not configure its own scan. A pull request can edit the file you pass here, so protect it with CODEOWNERS; the report always lists what was suppressed. |
| `internal-packages` | | Private package names to guard against dependency confusion |
| `days` | `90` | Activity window for maintenance signals |
| `comment` | `true` | Post/update a PR comment |
| `github-token` | `github.token` | Used for API reads (5,000 req/h) and comments |
