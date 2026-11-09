# One-line installer for oss-pulse.
#
#   curl -fsSL https://raw.githubusercontent.com/zahmed333/oss-pulse/main/install.sh -o oss-pulse-install.sh
#   sh oss-pulse-install.sh
#
# It creates a virtual environment under ~/.local/share/oss-pulse, installs the package
# into it and links `oss-pulse` into ~/.local/bin. Nothing else is touched; to uninstall,
# remove those two paths.
#
# Environment:
#   OSS_PULSE_EXTRAS  extras to install, default "scan" ("check" adds duckdb and dbt)
#   OSS_PULSE_REF     git ref to install, default main; set a commit SHA to pin it
#   OSS_PULSE_HOME    where the venv lives, default ~/.local/share/oss-pulse
#   OSS_PULSE_BIN     where the launcher goes, default ~/.local/bin

set -eu

PACKAGE="oss-pulse"
EXTRAS="${OSS_PULSE_EXTRAS:-scan}"
REF="${OSS_PULSE_REF:-main}"
VENV_DIR="${OSS_PULSE_HOME:-$HOME/.local/share/oss-pulse}"
BIN_DIR="${OSS_PULSE_BIN:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done
[ -n "$PYTHON" ] || die "Python 3.11 or newer is required (python3 --version)"

say "oss-pulse installer"
say "  python  $($PYTHON --version 2>&1)"
say "  into    $VENV_DIR"
say "  extras  $EXTRAS"
say ""

# A venv keeps Scripts/ on Windows and bin/ everywhere else.
venv_python() {
    if [ -x "$VENV_DIR/bin/python" ]; then echo "$VENV_DIR/bin/python"
    else echo "$VENV_DIR/Scripts/python.exe"; fi
}

mkdir -p "$VENV_DIR" "$BIN_DIR"
if [ ! -x "$(venv_python)" ]; then
    "$PYTHON" -m venv "$VENV_DIR" || die "could not create a virtual environment"
fi
PY="$(venv_python)"
[ -x "$PY" ] || die "the virtual environment at $VENV_DIR has no python"

# "scan" installs the scanner alone; "check" adds DuckDB, PyArrow and dbt.
"$PY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
"$PY" -m pip install --quiet \
    "${PACKAGE}[${EXTRAS}] @ git+https://github.com/zahmed333/oss-pulse@${REF}" \
    || die "pip install failed (offline? try OSS_PULSE_EXTRAS=scan)"

if [ -x "$VENV_DIR/bin/oss-pulse" ]; then
    ln -sf "$VENV_DIR/bin/oss-pulse" "$BIN_DIR/oss-pulse"
else
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$VENV_DIR/Scripts/oss-pulse.exe" > "$BIN_DIR/oss-pulse"
    chmod +x "$BIN_DIR/oss-pulse"
fi

say "installed: $BIN_DIR/oss-pulse"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say ""
       say "Add it to your PATH:"
       say "  export PATH=\"$BIN_DIR:\$PATH\""
       say "  # or append that line to ~/.zshrc or ~/.bashrc" ;;
esac
say ""
say "Then, before you open a folder someone sent you:"
say "  oss-pulse scan ~/Downloads/the-take-home"
