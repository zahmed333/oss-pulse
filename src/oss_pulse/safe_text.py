"""Untrusted text in reports.

Evidence snippets, file names and package metadata come from the code being vetted, so
they get the same treatment as user input in a web app. Everything a detector quotes goes
through one of these helpers before it reaches a terminal, a PR comment or a CI log:

- `visible()` turns control characters, bidirectional overrides and zero-width characters
  into visible escapes such as `\\x1b` and `\\u202e`. A scanned file can't send escape
  sequences to your terminal, can't start a new line in a CI log (where `::error::` and
  friends are workflow commands), and Trojan Source tricks show up instead of hiding.
- `md_code()` wraps text in a Markdown code span it can't break out of.
- `md_text()` escapes Markdown and HTML in prose and defuses @mentions, so a file name
  can't add a link, an image, raw HTML or a ping to a PR comment.

If you render with rich, never pass untrusted text as markup: use `rich.text.Text` or
`rich.markup.escape()`.
"""

from __future__ import annotations

import re
import unicodedata

# Format characters that change how text displays without being visible themselves.
_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Cs"}
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~^])")
_MENTION = re.compile(r"@(?=[A-Za-z0-9_-])")
_BACKTICKS = re.compile(r"`+")


def _escape(ch: str) -> str:
    if ch == "\t":
        return " "
    if unicodedata.category(ch) not in _CATEGORIES:
        return ch
    cp = ord(ch)
    if ch == "\n":
        return "\\n"
    if ch == "\r":
        return "\\r"
    return f"\\x{cp:02x}" if cp <= 0xFF else f"\\u{cp:04x}"


def visible(text: object, limit: int | None = None) -> str:
    """One line of text with every invisible or control character shown as an escape."""
    out = "".join(_escape(ch) for ch in str(text))
    if limit is not None and len(out) > limit:
        out = out[: max(limit - 1, 0)] + "…"
    return out


def md_text(text: object, limit: int | None = None) -> str:
    """Prose for a Markdown document or table cell: no links, images, HTML or mentions."""
    out = _MD_SPECIAL.sub(r"\\\1", visible(text, limit))
    return _MENTION.sub("@\u200b", out)


def md_code(text: object, limit: int | None = None, *, in_table: bool = True) -> str:
    """A Markdown code span that holds `text` verbatim, whatever backticks it contains."""
    body = visible(text, limit)
    if in_table:
        body = body.replace("|", "\\|")
    longest = max((len(run) for run in _BACKTICKS.findall(body)), default=0)
    fence = "`" * (longest + 1)
    if not body or body[0] == "`" or body[-1] == "`" or body[0] == " " or body[-1] == " ":
        body = f" {body} "
    return f"{fence}{body}{fence}"
