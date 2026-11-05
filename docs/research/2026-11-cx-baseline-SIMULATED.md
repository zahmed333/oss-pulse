# Customer experience baseline, November 2026 (simulated research)

This baseline rests on simulated research: six walkthroughs written and run by AI personas, and a scripted task suite run against fresh installs. 0 real users took part, and nobody was interviewed. The report was drafted with AI assistance on 2026-11-05.

It records the "before" that later changes are measured against. The suite's rows are the numbers to compare; the walkthroughs explain where the rows came from.

## Method

The walkthroughs ran on 2026-11-04 against commit 2410415. Each persona installed oss-pulse in a sandbox, ran scan on inert fixtures (VS Code tasks that run `echo`, URLs on `example.invalid`) and check on requirements files, some of them listing real PyPI packages, and logged its commands, the output, the problems it hit and its own scores. Four personas played people who would use the tool or be affected by it. Two were evaluation lenses rather than customers: a UX heuristic review and a portfolio review. A synthesis step, also run by an AI agent, merged their 143 issues into 48 backlog items, 10 of them P0, and re-ran some of the claims by command. The walkthroughs also wrote quotes and feelings for each step. This report leaves them out; a later report that needs one labels it "written by an AI persona, not said by a person".

The task suite is [scripts/cx_tasks.sh](../../scripts/cx_tasks.sh). It installs a source tree fresh and non-editable into a new virtual environment, the way the GitHub Action installs it, writes its own fixtures, and prints one PASS or FAIL row per task with the exit code and a line of evidence. The first version had 13 tasks; this baseline uses 32.

- T01 to T13 are the first version's tasks. Four criteria were reworded, and the script's header says how and why: three matched wording that the brand changes rather than behaviour, and T13 passed for any document under docs/ that used two words, this report included. At 2410415 and 34bdad4 the reworded rows give the same results as the originals.
- T14 to T30 cover failures found by the walkthroughs and by the plan review. All of them fail at both commits, and at 34bdad4, where install and scan work, each fails for the reason in its name.
- T31 and T32 are guardrails. An ordinary husky and TypeScript take-home has to pass the default gate, and 8,000 decoy strings have to scan in under 10 seconds. Both pass at 34bdad4, so a change that breaks either is a regression.

Two drafted tasks already passed at 34bdad4 as first worded, so they couldn't show the fix they were written for. A URL containing `//` next to a `folderOpen` task was caught by a substring fallback, so T16 now writes `folderOpen` with a JSON escape. A dev container's `initializeCommand` that pipes curl into sh was caught by the generic CODE-DLEXEC rule, so T30 asks for an auto-run finding (AUTO-DEVCONTAINER).

Each TSV header records the commit, the date, the OS, the Python version and the SHA-256 of the script (tasks_sha256). Two runs are comparable only when that hash matches, and a criterion is never changed in the change that makes its task pass.

The copy linter is [scripts/anti_tells.py](../../scripts/anti_tells.py). It keeps its first version's eight rules, from emoji and hype words to em dashes and shouted words, and now reads 68 files at 34bdad4, where the first version read 9. Its docstring lists where it looks.

Everything ran in one Linux x86_64 sandbox with Python 3.13.18 and no GitHub token. pypi.org and files.pythonhosted.org were reachable; api.github.com, api.osv.dev and api.securityscorecards.dev were blocked, so `check` ran without those sources and T04 passes with them reported as not checked.

## Participants

| Participant | Role in the study | Issue ids | Real or simulated |
|---|---|---|---|
| Real users | none were recruited | | 0 real users |
| Maya (fictional) | bootcamp graduate deciding whether to open a recruiter's take-home | AJS-01 to AJS-17 | simulated customer |
| Daniel (fictional) | security lead at a 50-person company, evaluating a rollout to every repository | SLE-01 to SLE-27 | simulated customer |
| Priya (fictional) | maintainer of a small PyPI package flagged in someone else's PR comment | CX-FM-01 to CX-FM-17 | simulated, affected third party |
| Support engineer | first month after launch, working 13 likely tickets | SD-00 to SD-18 | simulated, staff role |
| UX designer | heuristic review of the CLI, the reports, the Action and the docs | UXH-01 to UXH-28 | simulated evaluation lens, not a customer |
| Head of engineering | review of the repository as a hiring portfolio | CX-01 to CX-35 | simulated evaluation lens, not a customer |

The merged backlog uses ids CXB-01 to CXB-48. The transcripts are not in this repository; the ids are kept so that commits and later reports can refer to them.

## P0 findings

Ten backlog items were rated P0. "Now" is the state at 8f9ef74, checked with the suite on 2026-11-05; "rows" are the tasks that measure each item.

| Id | What the walkthroughs found | Raised by | Now | Rows |
|---|---|---|---|---|
| CXB-01 | A fresh, non-editable install crashed. scan failed with FileNotFoundError because the bundled list of popular PyPI names was never committed, and check failed with "dbt build failed" because the dbt project wasn't in the wheel. | AJS-01, SLE-01, CX-FM-11, UXH-01, SD-01, CX-01 | fixed in 348ba5b | T03, T04, T05 |
| CXB-02 | An `.osspulseignore` containing `*`, planted in the scanned folder, turned 4 findings and exit 1 into 0 findings and exit 0, with no notice. | AJS-03, SLE-02, UXH-02, SD-02, CX-03 | fixed in 34bdad4 | T06 |
| CXB-03 | A task one folder down, a task in a `.code-workspace` file, a payload in a committed `node_modules/` and one in a file over 5 MB all gave no findings, and a report with no findings said nothing about what had been read. | AJS-07, AJS-12, CX-06, UXH-06 | open | T11, T14, T15, T24, T25 |
| CXB-04 | Nothing tells someone who already opened the folder what to do next, and the one warning can be read as the opposite of what it means. | AJS-05, AJS-06, SD-11, UXH-13, CX-08, CX-27 | open | none yet |
| CXB-05 | Exit 1 meant both "at or above the gate" and every crash, and the Action reported any non-zero exit as supply-chain risk above an empty job summary. | SLE-05, UXH-04, SD-08, CX-02, CX-FM-11, CX-13 | open | T10, T20, T21 |
| CXB-06 | Public PR comments describe a fresh release of someone else's package in the language of an incident, and gaps in oss-pulse's own data read as facts about the package. | CX-FM-02, CX-FM-05, CX-FM-07, CX-FM-14, CX-FM-16, CX-30 | open | none yet |
| CXB-07 | Severities are out of proportion for other people's packages: an archived repository is critical, the same level as a package OSV lists as malicious, and typed, on PyPI since 2013, is a high-severity lookalike of typer. | CX-FM-03, CX-FM-04, CX-FM-06, CX-FM-08, SLE-06, UXH-09 | open | none yet |
| CXB-08 | There is no way to report a wrong result: no SECURITY.md, no issue forms and no link in any report. | AJS-15, SLE-25, CX-FM-01, CX-FM-02, SD-12, CX-10, UXH-16 | open | T09, T12 |
| CXB-09 | The README's install line has a `<you>` placeholder, which bash reads as a redirect. There was no public repository, and the name oss-pulse is unclaimed on PyPI. | AJS-02, AJS-14, SLE-04, CX-FM-02, CX-FM-12, UXH-15, SD-17, CX-04 | open; the repository is now public at github.com/zahmed333/oss-pulse | T01 |
| CXB-10 | Nothing says what leaves the machine. dbt's anonymous usage stats were on, and no document says that check sends package names, internal ones included, to pypi.org. | SLE-10, SD-10, CX-12, CX-28 | dbt stats off since 348ba5b; the rest is open | T13 |

## What was re-checked by command

Not every finding was re-run. These were, by the synthesis on 2026-11-04, by the plan review at 34bdad4, or by the suite on 2026-11-05.

| Finding | How it was re-checked | Result |
|---|---|---|
| CXB-01 | `git check-ignore`, a wheel built from the tree and a fresh clone running the tests (synthesis); T02 to T05 at both commits | crashes at 2410415; install, scan and check work at 34bdad4 |
| CXB-02 | the trap scanned with and without a planted ignore file (synthesis, in the editable environment); T06 | hidden at 2410415 and at 348ba5b, reported at 34bdad4 |
| CXB-03 | a nested folder and a workspace file (synthesis); nested, workspace, `node_modules/` and 2.1 MB bundle probes (plan review); T11, T14, T15, T24, T25 | no findings at 34bdad4 |
| CXB-05 | the Action's run step replayed against a fresh install (synthesis); cp1252, empty-file and lockfile runs; T10, T20, T21 | tracebacks with exit 1 at 34bdad4 |
| CXB-07 | the lookalike check run offline on typed, jinja and dateparse (synthesis) | all three flagged high |
| CXB-08 | `ls -a .github` (synthesis); T09, T12 | still missing at 34bdad4 |
| CXB-09 | `pip show`, `git tag` and the README line (synthesis); T01 | the placeholder is still there at 8f9ef74 |
| CXB-10 | dbt's logged settings (synthesis); T13 | stats off since 348ba5b; no data-flow statement |

CXB-04 and CXB-06 were checked by reading the code and docs; no command observes them yet. Findings that needed network access the sandbox blocked were taken from persona logs without re-running: the false positives on requests, numpy and docutils, the 365-day REL-001 replay, the PROV-002 moved-repository case and the GitHub rate-limit stub.

## Baselines

The first version of the suite, kept verbatim in [cx-tasks/original/](cx-tasks/original/) with its script:

| Commit | Run (UTC) | Passed |
|---|---|---|
| 2410415 | 2026-11-04 19:53 | 1 of 13 |
| 348ba5b | 2026-11-04 20:33 | 4 of 13 |
| 34bdad4 | 2026-11-04 22:01 | 5 of 13 |

The 32-task suite, run on 2026-11-05 with tasks_sha256 `6f61709103f019052841c93834f2d9b054f9e1bb89faabfb372aededf09f4845`:

| Commit | Passed | Raw output |
|---|---|---|
| 2410415 | 1 of 32 | [baseline-2410415.tsv](cx-tasks/baseline-2410415.tsv) |
| 34bdad4 | 7 of 32 | [baseline-34bdad4.tsv](cx-tasks/baseline-34bdad4.tsv) |
| 8f9ef74 | 7 of 32 | [run-8f9ef74.tsv](cx-tasks/run-8f9ef74.tsv) |

8f9ef74 is the commit this work builds on. It only changes where dbt writes its build files, and its rows match those of 34bdad4.

In the table, "the trap" is a folder whose `.vscode/tasks.json` runs `echo hi` when the folder is opened. The evidence column of each TSV gives the reason for every row; at 2410415 most rows fail on the same FileNotFoundError as T03.

| Task | What a person does or needs | 2410415 | 34bdad4 |
|---|---|---|---|
| T01 | pastes the README's install command into a shell | FAIL | FAIL |
| T02 | installs from source into a new virtual environment | PASS | PASS |
| T03 | scans a folder with nothing in it to find | FAIL | PASS |
| T04 | checks a requirements file that lists one common package | FAIL | PASS |
| T05 | scans the trap with `--fail-on high` and gets exit 1 | FAIL | PASS |
| T06 | scans the trap with an ignore file planted in it | FAIL | PASS |
| T07 | sees the lookalike name and its line in the report | FAIL | FAIL |
| T08 | asks for the version | FAIL | FAIL |
| T09 | finds where to report a wrong result, in the report | FAIL | FAIL |
| T10 | checks an empty file and gets a plain error, not exit 1 | FAIL | FAIL |
| T11 | reads, in a report with no findings, how much was read and that it isn't an audit | FAIL | FAIL |
| T12 | finds SECURITY, SUPPORT, CHANGELOG, CONTRIBUTING and issue forms | FAIL | FAIL |
| T13 | finds a privacy statement that names the hosts contacted | FAIL | FAIL |
| T14 | scans the trap one folder down | FAIL | FAIL |
| T15 | scans the trap written in a `.code-workspace` file | FAIL | FAIL |
| T16 | scans the trap with `folderOpen` as a JSON escape, and sees its URL quoted | FAIL | FAIL |
| T17 | scans the trap after a stray string in the tasks list | FAIL | FAIL |
| T18 | scans the trap next to a workflow with an unusual `on:` | FAIL | FAIL |
| T19 | scans the trap with no options and gets exit 1 | FAIL | FAIL |
| T20 | scans the trap with output redirected under cp1252 | FAIL | FAIL |
| T21 | checks `uv.lock` and gets exit 2 with a plain error | FAIL | FAIL |
| T22 | adds `-v` after the command | FAIL | FAIL |
| T23 | scans a `conftest.py` that downloads code and runs it | FAIL | FAIL |
| T24 | scans a 2.1 MB bundle with a payload on line 1 | FAIL | FAIL |
| T25 | scans a payload in a committed `node_modules/` | FAIL | FAIL |
| T26 | scans on a terminal and gets terminal text rather than Markdown | FAIL | FAIL |
| T27 | asks `oss-pulse rules AUTO-VSCODE` about one rule | FAIL | FAIL |
| T28 | scans the trap as the `.zip` it arrived in | FAIL | FAIL |
| T29 | scans JavaScript that fetches a script and evaluates the response | FAIL | FAIL |
| T30 | scans a dev container whose `initializeCommand` pipes a download into sh | FAIL | FAIL |
| T31 | guardrail: scans an ordinary husky and TypeScript take-home and gets exit 0 | FAIL | PASS |
| T32 | guardrail: scans 8,000 decoy strings in under 10 seconds | FAIL | PASS |

## Copy baseline

At 34bdad4 the linter finds 45 hits in its 68 files: 33 emoji (the README's example table, the ROADMAP's status marks and the severity icons in check.py and scan.py), 11 bold lead-in bullets in the README, and one shouted word in scan's `--help`. The first version found the same 45 in its 9 files, so nothing else in the wider scope was flagged. In code the linter skips patterns given to `re` and single bare words; without that, two regex lookaheads and a character class read as exclamation marks. The output is saved in [anti-tells-34bdad4.txt](anti-tells-34bdad4.txt), and this command exits 0 when a change adds no new hits:

```sh
python scripts/anti_tells.py --baseline docs/research/anti-tells-34bdad4.txt .
```

The baseline holds each change to "nothing new" until the brand work rewrites the flagged copy and the linter runs at zero.

## Model-generated scores (not survey data)

Each walkthrough scored itself. These numbers were written by the model playing the persona; nobody answered a survey. Tasks done uses each walkthrough's own stages as the denominator, so the rows can't be compared with each other. On a fresh install no report was produced at all, so the minutes come from the maintainer's editable environment.

| Walkthrough | Tasks done | Minutes to first report | Steps | Errors | Would recommend, 0 to 10 | Confidence in the result, 1 to 5 |
|---|---|---|---|---|---|---|
| Maya, take-home | 18% | 8.25 | 12 | 5 | 2 | 2 |
| Daniel, rollout | 14% | 25 | 7 | 6 | 2 | 4 |
| Priya, flagged package | 22% | 7 | 5 | 4 | 2 | 4 |
| Support engineer | 8% | 3 | 3 | 9 | 3 | 4 |
| UX heuristic lens | 27% | 2 | 3 | 12 | 3 | 4 |
| Portfolio lens | 18% | 2 | 3 | 11 | 4 | 4 |

## Limitations

- No real users took part. The quotes, feelings and scores in the walkthroughs are model-generated judgments, not observations.
- Two of the six walkthroughs are lenses, not customers. The portfolio lens shares the author's goal of a convincing repository, which biases what it rewards.
- The personas, the fixtures and the synthesis came from agents that had read the code and the README, so they knew where to look. Real people would hit other problems first.
- The suite is in-sample. Most of the new tasks encode problems this study found, so passing them shows those problems are fixed, not that the product is easy to use. The two guardrails cover cases that already worked.
- Each commit was measured once, on one machine, on one day. T02's time depends on the network and pip's cache, and rules about release age depend on the date.
- GitHub's API, OSV and Scorecard were blocked, so findings that needed them come from persona logs, and T04 passes without them. In CI, where they are reachable, T04's evidence will differ.
- The Action never ran on GitHub during the study. Fork pull requests, comment rendering and the job summary were inferred from action.yml and from replaying its steps.
- Windows was approximated on Linux with `PYTHONIOENCODING=cp1252`. No Windows, macOS or screen-reader session took place.
- The fixtures are small and hand-made, so false-positive and miss counts from the walkthroughs are anecdotes, not rates.
- One agent assigned the severities and priorities, and nobody has checked them independently.
- The copy linter matches a short list of patterns. No hits doesn't mean the copy reads well.

## Re-running

```sh
git worktree add /tmp/oss-pulse-34bdad4 34bdad4
bash scripts/cx_tasks.sh /tmp/oss-pulse-34bdad4 "$(mktemp -d)"
```

The second argument is the work folder. It keeps the virtual environment, the fixtures and every command's raw output.
