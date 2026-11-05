# Contributing to oss-pulse

## Set up

```sh
git clone https://github.com/zahmed333/oss-pulse && cd oss-pulse
python -m venv .venv && source .venv/bin/activate
make install   # editable install with dev, orchestration and dashboard extras
make test      # runs fully offline
make lint
```

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
