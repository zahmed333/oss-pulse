#!/usr/bin/env bash
# Scripted CX tasks for OSS Pulse. Run the SAME script, with the SAME fixtures, before and
# after a change, and compare the rows. The before/after claim then rests on this output.
#
# Usage: cx_tasks.sh <path-to-oss-pulse-source> [workdir]
#
# - Installs the source as a fresh, NON-editable install (the way action.yml installs it),
#   so it tests what a customer gets rather than the maintainer's working tree.
# - Fixtures are inert: nothing in them is executed, and they make no network calls.
# - Only T04 needs network (pypi.org). Everything is written under workdir; the source
#   tree is only read.
set -u
SRC=$(cd "${1:?usage: cx_tasks.sh <oss-pulse-src> [workdir]}" && pwd)
WORK=${2:-$(mktemp -d)}
mkdir -p "$WORK" && cd "$WORK" || exit 2
SHA=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
if git -C "$SRC" status --porcelain 2>/dev/null | grep -q .; then SHA="$SHA+dirty"; fi
pass=0; total=0
row() { total=$((total + 1)); [ "$2" = PASS ] && pass=$((pass + 1)); printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; }
op() { env -u GITHUB_TOKEN -u GH_TOKEN timeout 300 "$WORK/venv/bin/oss-pulse" "$@"; }
# Evidence: for a crash, the exception line; otherwise the first line matching the pattern.
first_line() {
  if grep -q Traceback "$1"; then grep -E '^[A-Za-z]+(Error|Exception)\b' "$1" | tail -1 | cut -c1-140
  else grep -v '^\s*$' "$1" | grep -m1 -E "$2" | cut -c1-140; fi
}

# ---- inert fixtures ------------------------------------------------------------------
rm -rf fx && mkdir -p fx/clean fx/trap/.vscode fx/trap-ignored/.vscode fx/typo fx/empty
printf 'print("hello")\n' > fx/clean/main.py
printf 'requests>=2.31\n' > fx/clean/requirements.txt
for d in fx/trap fx/trap-ignored; do
  printf '{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}\n' > "$d/.vscode/tasks.json"
done
printf '*\n' > fx/trap-ignored/.osspulseignore          # planted by the repo's author
printf 'requets==1.0\n' > fx/typo/requirements.txt      # one letter off 'requests'
: > fx/empty/requirements.txt

printf '# OSS Pulse scripted CX tasks\tsource=%s@%s\tdate=%s\n' "$SRC" "$SHA" "$(date -u +%FT%TZ)"
printf 'task\tresult\tmeasure\tevidence\n'

# T01 The README install command can be copy-pasted (no <placeholders> for the shell to misread)
line=$(grep -m1 -E '^\s*pip install' "$SRC/README.md" || true)
if [ -n "$line" ] && ! grep -q '[<>]' <<<"$line"; then r=PASS; else r=FAIL; fi
row T01-readme-install-copy-pastes "$r" "-" "${line:-no 'pip install' line in README}"

# T02 Fresh install succeeds (time, package count, size)
rm -rf venv && python3 -m venv venv
t0=$(date +%s); venv/bin/pip install --quiet "$SRC" > pip.log 2>&1; rc=$?; t1=$(date +%s)
n=$(venv/bin/pip list 2>/dev/null | tail -n +3 | wc -l); mb=$(du -sm venv | cut -f1)
[ $rc -eq 0 ] && r=PASS || r=FAIL
row T02-fresh-install "$r" "$((t1 - t0))s, $n packages, $mb MB" "pip rc=$rc"

# T03 Fresh install: scan a clean folder
op scan fx/clean > t03.out 2>&1; rc=$?
if [ $rc -eq 0 ] && ! grep -q Traceback t03.out; then r=PASS; else r=FAIL; fi
row T03-fresh-scan-clean-folder "$r" "rc=$rc" "$(first_line t03.out 'Error|findings')"

# T04 Fresh install: check a benign requirements file (needs pypi.org)
t0=$(date +%s); op check fx/clean/requirements.txt --data-dir "$WORK/lake" > t04.out 2> t04.err; rc=$?; t1=$(date +%s)
if [ $rc -eq 0 ] && grep -q 'Supply-chain risk report' t04.out; then r=PASS; else r=FAIL; fi
row T04-fresh-check-benign-deps "$r" "rc=$rc, $((t1 - t0))s" "$(tail -1 t04.err | cut -c1-140)"

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
row T09-report-has-feedback-link "$r" "-" "$(grep -m1 -o '<sub>.*' t05.out | cut -c1-140)"

# T10 A user error gets a plain message and an exit code that is not 'risk found' (1)
op check fx/empty/requirements.txt > t10.out 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 1 ] && ! grep -q Traceback t10.out; then r=PASS; else r=FAIL; fi
row T10-user-error-not-risk-exit "$r" "rc=$rc" "$(first_line t10.out 'Error|error')"

# T11 A clean scan report says what was covered and that clean is not a guarantee
if grep -qi 'scanned' t03.out && grep -Eqi 'no known|not a guarantee|not .?safe' t03.out; then r=PASS; else r=FAIL; fi
row T11-clean-report-coverage-and-caveat "$r" "-" "$(first_line t03.out 'findings|Error')"

# T12 Help, security, change and feedback paths exist
missing=""
for f in SECURITY.md SUPPORT.md CHANGELOG.md CONTRIBUTING.md .github/ISSUE_TEMPLATE; do
  [ -e "$SRC/$f" ] || missing="$missing $f"
done
[ -z "$missing" ] && r=PASS || r=FAIL
row T12-help-security-changelog-feedback "$r" "-" "missing:${missing:- none}"

# T13 A privacy / data-flow statement names the hosts contacted
if grep -rlis 'privacy' "$SRC/README.md" "$SRC/docs" 2>/dev/null | xargs -r grep -l 'pypi.org' | grep -q .; then r=PASS; else r=FAIL; fi
row T13-privacy-statement "$r" "-" "$(ls "$SRC"/docs 2>/dev/null | tr '\n' ' ')"

printf '# passed %d of %d\n' "$pass" "$total"
