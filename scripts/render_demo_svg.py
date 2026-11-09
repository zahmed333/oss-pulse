"""Render a real `oss-pulse scan` run as an animated terminal SVG.

The output is the actual report, captured by running the scanner against
`examples/take-home` (an inert fixture), then laid out as terminal text with
syntax colours and revealed line by line with SMIL. No screenshot, no mock-up:
what the SVG shows is what the command printed.

    python scripts/render_demo_svg.py            # writes docs/brand/demo.svg
    python scripts/render_demo_svg.py --no-animate

GitHub shows animated SVG in a README when it is referenced with <img>.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "examples" / "take-home"
OUT = ROOT / "docs" / "brand" / "demo.svg"

COLS, ROWS = 112, 17
FONT_SIZE = 14
LINE = 20
PAD = 18
TITLEBAR = 34
WIDTH = COLS * 8 + PAD * 2
HEIGHT = TITLEBAR + PAD + ROWS * LINE + PAD

BG = "#0d1117"
BAR = "#161b22"
DIM = "#8b949e"
FG = "#c9d1d9"
RED = "#ff6b6b"
WHITE = "#f0f6fc"
GREY = "#6e7681"
GREEN = "#3fb950"
CYAN = "#79c0ff"

TYPED = "sh install.sh"
COMMAND = "oss-pulse scan ./take-home"


def capture() -> list[str]:
    """Run the scanner for real and return its lines."""
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": str(ROOT / "src"),
    }
    proc = subprocess.run(
        [sys.executable, "-c", "from oss_pulse.cli import app; app()", "scan", str(FIXTURE)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if "hold" not in proc.stdout:
        raise SystemExit(f"the fixture no longer produces a hold verdict:\n{proc.stdout}")
    text = proc.stdout + ("\n" + proc.stderr.strip() if proc.stderr.strip() else "")
    return text.replace("\r\n", "\n").rstrip("\n").split("\n")


def clip(text: str, width: int) -> str:
    """Shorten to `width` characters, marking the cut with an ellipsis."""
    return text if len(text) <= width else text[: width - 1] + "…"


def colour_of(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith(("hold", "review", "note", "clear")):
        return {"h": RED, "r": WHITE, "n": GREY, "c": GREEN}[stripped[0]]
    if stripped.startswith("["):
        return CYAN
    if stripped.startswith(('"', "build:", "(")):
        return DIM
    if stripped.startswith(("Don't", "It is", "It contains")):
        return WHITE
    if stripped.startswith(("next", "1.", "2.", "3.")):
        return FG
    return DIM


def build(animate: bool) -> str:
    report = capture()
    screen: list[tuple[str, str, float]] = []  # (text, colour, delay)
    t = 0.4
    screen.append((f"$ {TYPED}", DIM, t))
    t += 0.9
    screen.append(("", FG, t))
    t += 0.2
    screen.append((f"$ {COMMAND}", GREEN, t))
    t += 0.7
    for line in report:
        if line.strip()[:2] in {"1.", "2.", "3."} or line.strip() == "next":
            continue  # the advice lives in docs/if-you-opened-it.md; the clip needs the room
        screen.append((line, colour_of(line), t))
        # the verdict lands slowly, the evidence types fast
        t += 0.06 if line.startswith((" ", "")) else 0.55
    body = []
    y0 = TITLEBAR + PAD + FONT_SIZE
    for i, (text, colour, delay) in enumerate(screen[:ROWS]):
        text = escape(clip(text, COLS).rstrip())
        if not text.strip():
            continue
        node = (
            f'<text x="{PAD}" y="{y0 + i * LINE}" fill="{colour}" '
            f'xml:space="preserve">{text}</text>'
        )
        if animate:
            node = (
                f'<g opacity="0"><animate attributeName="opacity" from="0" to="1" '
                f'begin="{delay:.2f}s" dur="0.18s" fill="freeze"/>{node}</g>'
            )
        body.append(node)

    cursor = ""
    if animate:
        cy = y0 + min(len(screen), ROWS) * LINE - 14
        cursor = (
            f'<rect x="{PAD}" y="{cy}" width="8" height="16" fill="{FG}">'
            f'<animate attributeName="opacity" values="0.9;0;0.9" dur="1.1s" '
            f'repeatCount="indefinite"/></rect>'
        )

    dots = "".join(
        f'<circle cx="{PAD + 8 + i * 18}" cy="{TITLEBAR / 2}" r="5" fill="{c}"/>'
        for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840"))
    )
    title = "take-home — oss-pulse scan"
    mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    label = "oss-pulse holds a fake take-home assignment"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" \
viewBox="0 0 {WIDTH} {HEIGHT}" font-family="{mono}" font-size="{FONT_SIZE}" role="img" \
aria-label="{label}">
  <rect width="{WIDTH}" height="{HEIGHT}" rx="10" fill="{BG}"/>
  <path d="M0 10a10 10 0 0 1 10-10h{WIDTH - 20}a10 10 0 0 1 10 10v{TITLEBAR - 10}H0z" fill="{BAR}"/>
  {dots}
  <text x="{WIDTH / 2}" y="{TITLEBAR / 2 + 5}" fill="{DIM}" text-anchor="middle" font-size="12">\
{escape(title)}</text>
  {"".join(body)}
  {cursor}
</svg>
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-animate", action="store_true", help="static frame only")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    svg = build(animate=not args.no_animate)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(svg, encoding="utf-8")
    print(f"wrote {args.out} ({len(svg):,} bytes)")


if __name__ == "__main__":
    main()
