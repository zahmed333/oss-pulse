# Roadmap

What is done, and what comes next, in the order it will be built. Each item was found by a simulated user study or a real-data benchmark (see [docs/research](docs/research/)); the studies used AI-simulated personas, not real users.

## Done

- Fresh installs work: the typosquat list and the dbt project ship in the wheel, and CI installs the built wheel into an empty environment.
- A scanned folder cannot silence its own findings; an `.osspulseignore` inside it is reported as EVADE-IGNORE.
- Text quoted from scanned files cannot inject terminal escapes, CI workflow commands, or Markdown links, images, HTML or mentions into reports.
- dbt sends no usage statistics and writes nothing into the installed package.
- No finding at medium or above on the 250 most-downloaded PyPI packages, with 37 precision and recall cases in the test suite ([docs/benchmarks.md](docs/benchmarks.md)).
- Runs in Azure DevOps, GitHub Actions, GitLab and Jenkins: JUnit, SARIF, native annotations and pull-request comments ([docs/ci.md](docs/ci.md)).
- The scripted customer task suite (`scripts/cx_tasks.sh`) and the copy linter (`scripts/anti_tells.py`) are committed, with baselines.

## Correctness and safety of the scanner

- Auto-run files can't crash the scan, slip past AUTO-VSCODE, or hide in a nested folder.
- No file in a scanned folder or release can hang the scanner or exhaust its memory.
- Lookalike names graded by edit strength and metadata, safe for established names offline; scan quotes the name and the line.
- One verdict per finding (hold, review, watch, note), upkeep is never a threat, one default gate, brand words in the SQL.
- Exit codes mean one thing each, nothing ends in a traceback, output can't crash on encoding, every dependency knows its line.
- The Action fails closed, keeps runs and comments apart, works on fork PRs and shallow checkouts, and installs nothing unpinned.
- check never shows a row as clear when a signal or a declared line wasn't checked, and says which, why and how to fix it.
- scan reads where attackers hide code, bounds its walk, and lists everything it didn't read.

## The brand on every surface, and fewer rough edges

- Commit the brand and apply it to every surface: terminal, errors, help, PR comment, job summary, annotations, README, action.yml, dashboard, rule text.
- Every rule says what to do and where it has been seen, with a source; a guide for people who already opened the folder.
- Read requirements files the way pip does, check the lines wp-09 lists, and explain the files check can't read.
- Assess the version and source pip installs: Poetry constraints, direct URLs, pins that don't exist.
- Scan the .zip or .tar.gz a recruiter sent without extracting it, and say what to do with a link.
- Catch the other ways a take-home runs code: dev containers, hooks that run local files, fetch-then-eval loaders.
- check reads the wheel pip would install and every file in it, with no allowlist or BOM bypass for .pth, and no string-literal false positive.
- Accept a reviewed finding or upkeep label with a reason and an expiry, from your own policy file, shown in every report.
- The same result on Windows, macOS, non-UTF-8 streams, narrow terminals and without colour.
- Docs that match behaviour: a working install line, documented limits, a comparison with other tools, a roadmap for users.

## Outputs other tools can use, and proof in CI

- Results other tools can build on: a versioned JSON envelope, baselines and a PR diff view.
- First run without surprises: an offline demo, doctor, init, a pre-commit hook, and no data left in your project.
- Ways to report, dispute and contribute: SECURITY, SUPPORT, PRIVACY, CONTRIBUTING, CHANGELOG, issue forms, a page for flagged maintainers.
- Proof that stays true: the task suite and both benchmarks in CI, a held-out set behind the precision claims, research docs generated from them.

## Later

- Lockfiles and transitive dependency paths (uv.lock, poetry.lock).
- npm dependency trees.
- Continuous monitoring of new PyPI releases, with alerts when a dependency's verdict changes.
- Real user sessions with the kit in docs/research, reported separately from the simulated studies.
