# Contributing to oss-pulse

## Set up

```sh
git clone https://github.com/zahmed333/oss-pulse && cd oss-pulse
python -m venv .venv && source .venv/bin/activate
make install   # editable install with dev, orchestration and dashboard extras
make test      # runs fully offline
make lint
```

## Where things live

| Path | Responsibility |
|---|---|
| `src/oss_pulse/cli.py` | Builds the `oss-pulse` command from the command modules. |
| `src/oss_pulse/commands/security.py` | `check`, `scan` and `rules`. |
| `src/oss_pulse/commands/lakehouse.py` | The GH Archive health pipeline commands (`ingest`, `transform`, `report`, `demo`). |
| `src/oss_pulse/check/pipeline.py` | One `check` run as named steps: fetch PyPI metadata, detect lookalikes, fetch GitHub activity, detect provenance changes, scan release files, store, decide, load the result. |
| `src/oss_pulse/check/report.py` | Markdown and JSON output for `check`. |
| `src/oss_pulse/scan.py` | `scan`: walks a folder and renders its report. |
| `src/oss_pulse/supplychain/` | Detectors. Each takes data in and returns `Finding`s; none of them fetch, store or print. |
| `src/oss_pulse/ingest/` | Source clients and bronze writers, one module per source. |
| `src/oss_pulse/safe_text.py` | Every string from scanned code goes through here before it is printed. |
| `transform/` | dbt project: the SQL rules and the risk marts. |

Detectors, sources and renderers only meet in `check/pipeline.py` and `scan.py`, so a new detector or a new output format touches one place.

## Reporting a wrong result

Use the issue forms. A false positive or a missed detection is a bug. Include the command, the output, and for a package its name and version. Don't attach real malware: describe it, or link to an advisory.

## Adding a detection rule

1. Add the rule to `src/oss_pulse/supplychain/rules.py`: an id, severity, category, title, why it matters, and the real incident it comes from.
2. Emit it from the detector that owns the input: `code_scan.py` for file contents, `repo_scan.py` for folder layout, `workflows.py` for GitHub Actions, or a SQL model in `transform/models/` for rules that compare releases or sources.
3. Add a test with an inert fixture: base64 of `print(1)`, `example.invalid` domains, never live payloads.
4. Run the precision check: a rule that flags popular, legitimate packages will be switched off by users.
5. Regenerate `docs/RULES.md`.

## Pull requests

Keep each pull request to one change, with tests. CI runs lint, the test suite on Python 3.11 to 3.13, an install of the built wheel, the full pipeline, and oss-pulse on its own repository. `scripts/anti_tells.py` checks user-facing text against [docs/brand.md](docs/brand.md).
