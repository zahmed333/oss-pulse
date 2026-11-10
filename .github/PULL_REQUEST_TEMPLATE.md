## What this changes

## Why

## How it was checked

- [ ] `make test` and `make lint` pass
- [ ] New or changed rules have an inert fixture and a test (no working payloads, `example.invalid` hosts)
- [ ] The top-250 benchmark and `tests/test_artifact_precision.py` still pass if a detector changed
- [ ] User-facing text follows `docs/brand.md` (`python scripts/anti_tells.py .`)
