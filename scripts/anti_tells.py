"""Flag the copy habits that make oss-pulse read as machine-written.

usage: python scripts/anti_tells.py [--baseline FILE] [REPO]

Read-only. It prints one line per hit and exits 1 if there is any. With --baseline FILE
it prints only the hits FILE doesn't list, and exits 1 only for those, so a change can be
held to "nothing new" while the old hits wait for the change that fixes them. A baseline
is this script's own output, saved; docs/research/anti-tells-2bc3e4f.txt is the run at
commit 2bc3e4f. Hits match on file, kind and quoted text, not on line number, so moving a
line doesn't make it new and editing a flagged line does.

The rules are the first version's, unchanged: emoji, hype words, "not just X", bold
lead-in bullets, title-case headings, exclamation marks, em dashes and shouted words. The
brand guide bans more than this; when its full list lands, the baseline mode goes.

What changed is where it looks. The first version read README.md, ROADMAP.md, docs/*.md,
action.yml and the string literals of four files under src/, so new copy anywhere else
went unchecked. Paths are relative to REPO:

  *.md in REPO, docs/**/*.md, and *.md under action/, dashboard/ and .github/
      every line; inside a code fence only emoji count
  action.yml, and *.yml and *.yaml under action/, dashboard/ and .github/
      name: and description: values, block scalars included, and ::error or ::warning
  *.py under src/, dashboard/, action/ and .github/
      every string literal; docstrings are skipped, except a Typer command's, which is
      its --help text
  transform/**/*.sql
      every '...' literal; comments are skipped
  shell and JavaScript under action/, dashboard/ and .github/
      every string literal and heredoc, without $VAR, ${...} or $(...); comments skipped

Two kinds of string in code are code rather than copy, and are skipped: a pattern given to
re (so "(?!" isn't an exclamation mark), and a single bare word such as a dict key, an
environment variable or an HTTP method (so "READTHEDOCS" isn't shouting).

Exit status: 0 when nothing (new) is flagged, 1 when something is, 2 when a file in
scope couldn't be read.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections import Counter
from pathlib import Path

# ------------------------------------------------------------ the rules, as first written

# Pictographs, then dingbats and symbols (U+2600 to U+27BF), then U+2B00 to U+2BFF. Arrows
# (U+2190 and up) are fine.
EMOJI = re.compile(r"[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U00002B00-\U00002BFF]")
HYPE = re.compile(
    r"\b(seamless(ly)?|robust|leverag\w*|empower\w*|comprehensive|delve|unlock\w*|elevat\w*|"
    r"cutting[- ]edge|game[- ]changer|blazing\w*|powerful|effortless\w*|supercharg\w*|"
    r"revolution\w*|world[- ]class|best[- ]in[- ]class|state[- ]of[- ]the[- ]art|"
    r"next[- ]gen)\b",
    re.I,
)
NOT_JUST = re.compile(r"\b(not just|isn't just|more than just)\b", re.I)
BOLD_LEAD = re.compile(r"^\s*([-*]|\d+\.) \*\*[^*]+\*\*")
SHOUT = re.compile(r"\b[A-Z]{4,}\b")
RULE_ID = re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]+)+\b")  # OSV-VULN, GHA-CACHE-RELEASE
ACRONYMS = {
    "JSON", "HTTP", "HTTPS", "GHSA", "DPRK", "YAML", "TOML", "UUID", "NOTE", "TODO",
    "WARNING", "CAUTION", "SPDX", "SBOM", "SARIF", "PYPI", "GITHUB", "README", "ROADMAP",
    "MIT", "UTC", "ISO", "AST", "CVSS", "HTML", "WOFF", "DEBUG", "INFO", "ERROR", "TOKEN",
}  # fmt: skip
TITLE_CASE = re.compile(r"^#{1,4} (?:[A-Z][\w'-]*\s+){2,}[A-Z][\w'-]*\s*$")
EM_DASH = "\U00002014"

KINDS = (
    "emoji",
    "hype word",
    "not-just-X",
    "bold lead-in bullet",
    "title case heading",
    "exclamation",
    "em dash",
    "shouting",
)


def prose_kinds(line: str, in_code: bool = False) -> list[str]:
    """A line of Markdown, or a user-facing line of YAML."""
    kinds = ["emoji"] if EMOJI.search(line) else []
    if in_code:
        return kinds
    if HYPE.search(line):
        kinds.append("hype word")
    if NOT_JUST.search(line):
        kinds.append("not-just-X")
    if BOLD_LEAD.search(line):
        kinds.append("bold lead-in bullet")
    if TITLE_CASE.match(line):
        kinds.append("title case heading")
    if "!" in re.sub(r"\[!\w+\]|!\[|!=|`[^`]*`|<!--.*?-->", "", line):
        kinds.append("exclamation")
    if EM_DASH in line:
        kinds.append("em dash")
    return kinds


def string_kinds(s: str) -> list[str]:
    """A string literal from code."""
    kinds = ["emoji"] if EMOJI.search(s) else []
    if HYPE.search(s):
        kinds.append("hype word")
    if "!" in re.sub(r"!=|\[!\w+\]|<!--.*?-->", "", s) and len(s) > 3:
        kinds.append("exclamation")
    shouted = SHOUT.findall(RULE_ID.sub("", s))
    if any(w not in ACRONYMS and not w.startswith(("MAL", "GHSA")) for w in shouted):
        kinds.append("shouting")
    if EM_DASH in s:
        kinds.append("em dash")
    return kinds


# ------------------------------------------------------------ where the copy is

READERS = {
    ".md": "md", ".py": "py", ".sql": "sql", ".yml": "yaml", ".yaml": "yaml",
    ".sh": "shell", ".bash": "shell", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
}  # fmt: skip
ROOTS = {
    "docs": {".md"},
    "src": {".py"},
    "transform": {".sql"},
    **dict.fromkeys(("action", "dashboard", ".github"), set(READERS)),
}
SKIP_DIRS = {"node_modules", "__pycache__"}

YAML_KEY = re.compile(r"^(\s*)(?:-\s+)?(?:description|name):")
YAML_BLOCK = re.compile(r":\s*[|>][-+0-9]*\s*(?:#.*)?$")
YAML_COMMAND = re.compile(r"::(?:error|warning)")

RE_FUNCTIONS = {
    "compile", "search", "match", "fullmatch", "sub", "subn", "split", "findall", "finditer",
}  # fmt: skip
BARE_WORD = re.compile(r"[A-Za-z_][\w.:/+-]*")
SQL_TOKEN = re.compile(r"--[^\n]*|/\*.*?\*/|\{#.*?#\}|'(?:[^']|'')*'", re.S)
SHELL_TOKEN = re.compile(
    r"(?:^|(?<=[\s;&|()]))#[^\n]*"  # a comment: '#' at the start of a word
    r"|<<-?[ \t]*(['\"]?)(\w+)\1[^\n]*\n(?P<heredoc>.*?)^[ \t]*\2[ \t]*$"
    r"|\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\""
    r"|\\.",  # an escaped character outside quotes
    re.S | re.M,
)
JS_TOKEN = re.compile(
    r"//[^\n]*|/\*.*?\*/"
    r"|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"|`(?:[^`\\]|\\.)*`",
    re.S,
)
SHELL_EXPANSION = re.compile(r"\$(?:\{[^}]*\}|\([^)]*\)|[A-Za-z_]\w*|[0-9@#?*!$-])")
JS_EXPANSION = re.compile(r"\$\{[^}]*\}")


def files_in_scope(repo: Path):
    """(path, reader) for every file the linter covers."""
    yield from ((p, "md") for p in sorted(repo.glob("*.md")))
    if (repo / "action.yml").is_file():
        yield repo / "action.yml", "yaml"
    for root in sorted(ROOTS):
        for p in sorted((repo / root).rglob("*")):
            ext = p.suffix.lower()
            skipped = SKIP_DIRS & set(p.relative_to(repo).parts)
            if p.is_file() and ext in ROOTS[root] and not skipped:
                yield p, READERS[ext]


def markdown_lines(text: str):
    in_code = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_code = not in_code
        yield i, line, in_code


def yaml_lines(text: str):
    """The lines a person reads: name and description values, and workflow messages."""
    block = None  # indent of a key whose value is a block scalar (description: >)
    for i, line in enumerate(text.splitlines(), 1):
        if block is not None and (not line.strip() or len(line) - len(line.lstrip()) > block):
            yield i, line, False
            continue
        block = None
        key = YAML_KEY.match(line)
        if key and YAML_BLOCK.search(line):
            block = len(key.group(1))
        if key or YAML_COMMAND.search(line):
            yield i, line, False


def _is_typer_command(fn: ast.AST) -> bool:
    for d in getattr(fn, "decorator_list", []):
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute) and target.attr in {"command", "callback"}:
            return True
    return False


def _is_re_call(node: ast.AST) -> bool:
    f = getattr(node, "func", None)
    return (
        isinstance(node, ast.Call)
        and isinstance(f, ast.Attribute)
        and isinstance(f.value, ast.Name)
        and f.value.id in {"re", "regex"}
        and f.attr in RE_FUNCTIONS
    )


def python_strings(source: bytes, is_cli: bool):
    tree = ast.parse(source)
    scopes = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    skip = {
        id(n.body[0].value)
        for n in ast.walk(tree)
        if isinstance(n, scopes)
        and n.body
        and isinstance(n.body[0], ast.Expr)
        and isinstance(n.body[0].value, ast.Constant)
    }
    for call in filter(_is_re_call, ast.walk(tree)):
        patterns = call.args[:1] + [k.value for k in call.keywords if k.arg == "pattern"]
        skip |= {id(c) for p in patterns for c in ast.walk(p)}
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip:
            yield n.lineno, n.value
    # A command's docstring is its --help text, so it counts.
    functions = (ast.FunctionDef, ast.AsyncFunctionDef)
    for n in ast.walk(tree):
        if isinstance(n, functions) and (is_cli or _is_typer_command(n)) and ast.get_docstring(n):
            yield n.lineno, ast.get_docstring(n)


def sql_strings(text: str):
    for m in SQL_TOKEN.finditer(text):
        if m.group().startswith("'"):
            yield text.count("\n", 0, m.start()) + 1, m.group()[1:-1].replace("''", "'")


def code_strings(text: str, token: re.Pattern, expansion: re.Pattern):
    """String literals of shell or JavaScript, from a tokenizer that skips comments."""
    for m in token.finditer(text):
        tok = m.group()
        if tok.startswith("<<"):
            body, start = m.group("heredoc"), text.index("\n", m.start()) + 1
        elif tok.startswith("$'"):
            body, start = tok[2:-1], m.start()
        elif tok[0] in "'\"`":
            body, start = tok[1:-1], m.start()
        else:
            continue  # a comment, or an escaped character
        yield text.count("\n", 0, start) + 1, expansion.sub(" ", body)


def hits_in(path: Path, reader: str):
    """(line, kind, text) for every hit in one file."""
    if reader == "py":
        strings = python_strings(path.read_bytes(), is_cli=path.name == "cli.py")
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
        if reader in {"md", "yaml"}:
            lines = markdown_lines(text) if reader == "md" else yaml_lines(text)
            for i, line, in_code in lines:
                for kind in prose_kinds(line, in_code):
                    yield i, kind, line
            return
        if reader == "sql":
            strings = sql_strings(text)
        elif reader == "shell":
            strings = code_strings(text, SHELL_TOKEN, SHELL_EXPANSION)
        else:
            strings = code_strings(text, JS_TOKEN, JS_EXPANSION)
    for line, s in strings:
        if not BARE_WORD.fullmatch(s):
            for kind in string_kinds(s):
                yield line, kind, s


# ------------------------------------------------------------ report and baseline

HIT_LINE = re.compile(
    r"^(?P<path>.+?):\d+\s+(?P<kind>"
    + "|".join(map(re.escape, KINDS))
    + r")(?:\s+(?P<text>.*?))?\s*$"
)


def quote(text: str) -> str:
    """One line of at most 90 characters, with control characters shown as escapes."""
    one = " ".join(text.split())
    shown = "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in one)
    return shown[:90].rstrip()


def collect(repo: Path) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Every hit as (path:line, kind, quoted text), and the files that couldn't be read."""
    hits, errors = [], []
    for path, reader in files_in_scope(repo):
        rel = path.relative_to(repo).as_posix()
        try:
            found = sorted(hits_in(path, reader), key=lambda h: h[0])
        except (SyntaxError, ValueError, OSError) as exc:
            errors.append(f"can't read {rel}: {exc}")
            continue
        hits += [(f"{rel}:{line}", kind, quote(text)) for line, kind, text in found]
    return hits, errors


def read_baseline(path: Path) -> Counter:
    """How often each (path, kind, text) appears in a saved run."""
    keys: Counter = Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        if m := HIT_LINE.match(line):
            keys[(m["path"], m["kind"], m["text"] or "")] += 1
    return keys


def baseline_key(hit: tuple[str, str, str]) -> tuple[str, str, str]:
    where, kind, text = hit
    return where.rsplit(":", 1)[0], kind, text


def plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def tally(hits) -> str:
    counts = Counter(kind for _, kind, _ in hits)
    return ", ".join(f"{kind} {n}" for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anti_tells.py", description="Flag copy that reads as machine-written."
    )
    parser.add_argument("repo", nargs="?", default=".", type=Path, help="default: .")
    parser.add_argument(
        "--baseline", type=Path, metavar="FILE", help="report only hits that FILE doesn't list"
    )
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # the same bytes on every platform
    try:
        baseline = read_baseline(args.baseline) if args.baseline else None
    except OSError as exc:
        print(f"error: can't read the baseline: {exc}", file=sys.stderr)
        return 2
    hits, errors = collect(args.repo.resolve())

    new = hits
    if baseline is not None:
        left = Counter(baseline)
        new = []
        for hit in hits:
            if left[baseline_key(hit)] > 0:
                left[baseline_key(hit)] -= 1
            else:
                new.append(hit)
    for where, kind, text in new:
        print(f"{where:<36} {kind:<20} {text}")
    if new:
        print()

    if baseline is None:
        print(f"{plural(len(hits), 'hit')}: {tally(hits)}" if hits else "nothing flagged")
    else:
        known = len(hits) - len(new)
        gone = sum(baseline.values()) - known
        head = f"{plural(len(new), 'new hit')}: {tally(new)}" if new else "nothing new"
        tail = f"; {gone} of its hits are gone" if gone > 0 else ""
        print(f"{head}. {plural(known, 'hit')} already in the baseline{tail}.")
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        return 2
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
