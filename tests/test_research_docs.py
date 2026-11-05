"""Research docs must never pass simulated research off as real.

Every persona study behind this project was simulated by AI, and no real user has been
interviewed. These checks keep each report in docs/research/ honest as it is edited:

- its title and first sentence say the research was simulated;
- it says how many real users took part, in those words: "0 real users";
- every line that quotes a persona says it was written by an AI persona. Blockquotes are
  kept for persona lines, so every blockquote line counts, and so does any line that puts
  three or more words in double quotes next to a persona's name or the word persona.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RESEARCH = Path(__file__).resolve().parents[1] / "docs" / "research"
REPORTS = sorted(RESEARCH.glob("*.md"))
LABEL = "written by an AI persona"
OPEN, CLOSE = '["\U0000201c]', '["\U0000201d]'  # straight or curly double quotes
INSIDE = '[^"\U0000201d\n]'
QUOTED = re.compile(f"{OPEN}{INSIDE}*?\\w+\\s+\\w+\\s+\\w+{INSIDE}*{CLOSE}")
PERSONA = re.compile(r"\b(?:personas?|Maya|Daniel|Priya)\b", re.I)


def title_and_first_sentence(text: str) -> tuple[str, str]:
    lines = text.splitlines()
    i, title = next((i, line) for i, line in enumerate(lines) if line.startswith("# "))
    paragraph = []
    for line in lines[i + 1 :]:
        if line.strip():
            paragraph.append(line.strip())
        elif paragraph:
            break
    first = re.split(r"(?<=[.?!])\s", " ".join(paragraph), maxsplit=1)[0]
    return title, first


def unlabelled_persona_lines(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        quotes = line.lstrip().startswith(">") or (QUOTED.search(line) and PERSONA.search(line))
        if quotes and LABEL not in line:
            found.append(line)
    return found


def test_there_is_a_baseline_report():
    assert RESEARCH / "2026-11-cx-baseline-SIMULATED.md" in REPORTS


@pytest.mark.parametrize("report", REPORTS, ids=[p.name for p in REPORTS])
def test_title_and_first_sentence_say_simulated(report):
    title, first = title_and_first_sentence(report.read_text(encoding="utf-8"))
    assert re.search("simulated", title, re.I), title
    assert re.search("simulated", first, re.I), first


@pytest.mark.parametrize("report", REPORTS, ids=[p.name for p in REPORTS])
def test_says_how_many_real_users_took_part(report):
    assert "0 real users" in report.read_text(encoding="utf-8")


@pytest.mark.parametrize("report", REPORTS, ids=[p.name for p in REPORTS])
def test_every_persona_quote_is_labelled(report):
    assert unlabelled_persona_lines(report.read_text(encoding="utf-8")) == []


def test_the_quote_check_catches_unlabelled_lines():
    doc = "\n".join(
        [
            '> "I would never open this folder." Maya, written by an AI persona, not a person.',
            '> "I would never open this folder."',
            'Daniel said "this would be too noisy for us" after the second run.',
            'The persona wrote "roll it out next quarter", written by an AI persona.',
            'The report says "clear means no rule matched" in its footer.',
        ]
    )
    assert unlabelled_persona_lines(doc) == [doc.splitlines()[1], doc.splitlines()[2]]
