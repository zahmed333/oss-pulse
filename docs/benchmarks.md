# Benchmarks

## False positives on popular packages

The release-file scanner reads the sdist and the wheel pip would download. A rule that fires on well-known, legitimate packages gets the tool switched off, so it is measured on the 250 most-downloaded PyPI packages.

Method: the newest release of each package (snapshot 2026-11-04), its sdist and one wheel, downloaded once and verified against PyPI's SHA-256, then scanned offline. Every finding was reviewed by hand; none of them was malware.

| | Before | After |
|---|---|---|
| Packages with any finding at medium or above | 39 of 250 (16%) | 0 of 250 |
| Findings at medium or above | 79 | 0 |
| All findings, including low | 107 | 74 |
| Scanner CPU time, all 250 packages | 222 s | 380 s |

What changed:

- Only the sdist's top-level `setup.py` counts as install-time code. Vendored `setup.py` files deep in a source tree are ordinary files, because pip never runs them.
- A command run from `setup.py` is medium only when it fetches something, decodes something or pipes into a shell. Calls to compilers, `pkg-config` and `git`, and `exec` of a local version file, are low.
- `curl ... | sh` inside a Python comment or docstring, in CI and documentation scripts inside an sdist, or in a string no code in the same scope runs, does not count. A shell script that the top-level `setup.py` names still does.
- A download and an `exec` must be in the same function (or both at module level), not anywhere in the same file.
- Compiled files whose format matches their extension (a Windows launcher named `.exe`) are low. A program named `.png` is high.
- A Telegram or Discord API URL without a hard-coded token is low unless the same file also collects secrets.
- The same file found in the sdist and the wheel is reported once.

The remaining 74 findings are all low and do not affect a verdict: 26 compiled launcher stubs (setuptools, pip), 26 `setup(cmdclass=...)` calls in packages with C extensions, 21 local build commands in `setup.py`, and one messaging integration (tqdm's Telegram bot, where the user supplies the token).

The scanner is slower because Python files are now parsed to tell code from comments and to find which function a line belongs to: the median package takes 0.24 s, the slowest (google-api-python-client) 52 s.

### Detection did not get weaker

`tests/test_artifact_precision.py` holds 37 cases: 24 inert copies of real attack shapes that must be caught at medium or above (install hooks, download-and-execute loaders, PowerShell `irm | iex`, disguised binaries, environment exfiltration, hard-coded bot tokens, decoys in comments next to real payloads) and 13 legitimate shapes from the benchmark that must stay quiet. Before these changes the scanner passed 20 of 37; it now passes all 37, and the suite runs in CI.

### Limits of this result

The fixes were designed while looking at these same 250 packages, so "0 of 250" is an in-sample number. A held-out set (packages ranked 251 to 1,000, plus the OpenSSF malicious-packages dataset for recall) is on the [roadmap](../ROADMAP.md). Typosquat findings are measured separately; their false-positive rate is still too high (about 1.4% of real PyPI names) and their fix is also on the roadmap.
