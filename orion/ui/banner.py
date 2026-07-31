"""
orion.ui.banner
==============

ORION's console banner — HexStrike-inspired: chunky pixel-glyph wordmark with a
CRT scanline effect, sitting above a bordered "intelligence core" info box.

Palette is ORION's own: neon orange (#FF8C00) over gunmetal grey, so it stays on
brand with the GitHub banner.

    from orion.ui.banner import print_banner
    print_banner()

    # or:  python -m orion.ui.banner
"""
from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

# --------------------------------------------------------------------------- #
# Palette                                                                      #
# --------------------------------------------------------------------------- #
ORANGE = "#FF8C00"          # neon orange — primary / scanline bright
ORANGE_HOT = "#FFB042"      # highlight
ORANGE_DEEP = "#B4500C"     # scanline dim / recessed
GUNMETAL = "grey42"         # smoky frame
GUNMETAL_DIM = "grey30"     # deep shadow
STEEL = "grey66"            # secondary text
STEEL_DIM = "grey50"        # separators

# --------------------------------------------------------------------------- #
# Pixel font — 7 rows, 5 cells wide. '#' = lit pixel, ' ' = dark.              #
# Each lit pixel renders as a 2-char block for that chunky arcade look.        #
# --------------------------------------------------------------------------- #
_GLYPHS: dict[str, list[str]] = {
    "O": [
        "#####",
        "#   #",
        "#   #",
        "#   #",
        "#   #",
        "#   #",
        "#####",
    ],
    "R": [
        "#### ",
        "#   #",
        "#   #",
        "#### ",
        "# #  ",
        "#  # ",
        "#   #",
    ],
    "I": [
        "#####",
        "  #  ",
        "  #  ",
        "  #  ",
        "  #  ",
        "  #  ",
        "#####",
    ],
    "N": [
        "#   #",
        "##  #",
        "# # #",
        "# # #",
        "# # #",
        "#  ##",
        "#   #",
    ],
}

_ROWS = 7
_PIXEL = "██"          # a lit pixel
_DARK = "  "           # an unlit pixel
_LGAP = "  "           # gap between letters


def _wordmark(word: str = "ORION") -> Text:
    """
    Render the pixel wordmark with a horizontal CRT scanline: even pixel-rows
    burn bright orange, odd rows drop to deep orange.
    """
    art = Text()
    for r in range(_ROWS):
        style = f"bold {ORANGE}" if r % 2 == 0 else ORANGE_DEEP
        line = Text(style=style)
        for ch in word:
            grid = _GLYPHS[ch]
            line.append("".join(_PIXEL if c == "#" else _DARK for c in grid[r]))
            line.append(_LGAP)
        art.append_text(line)
        art.append("\n")
    art.rstrip()
    return art


# --------------------------------------------------------------------------- #
# Info box (the "intelligence core" strip, à la HexStrike)                     #
# --------------------------------------------------------------------------- #
def _info_box() -> Panel:
    def line(icon: str, head: str, tail: str) -> Text:
        t = Text()
        t.append(f"{icon} ", style=f"bold {ORANGE}")
        t.append(head, style=f"bold {ORANGE_HOT}")
        t.append(tail, style=STEEL)
        return t

    def piped(icon: str, parts: list[str]) -> Text:
        t = Text()
        t.append(f"{icon} ", style=f"bold {ORANGE}")
        for i, p in enumerate(parts):
            if i:
                t.append(" | ", style=STEEL_DIM)
            t.append(p, style=STEEL)
        return t

    body = Group(
        line("▚", "ORION", " — Tactical Offensive Intelligence Core"),
        piped("⚡", ["AI-Automated Recon", "Exploitation", "Analysis Pipeline"]),
        piped("☰", ["Bug Bounty", "CTF", "Red Team", "Zero-Day Research"]),
    )
    return Panel(
        body,
        box=box.SQUARE,
        border_style=ORANGE_DEEP,
        padding=(0, 1),
        expand=False,
        subtitle=Text("v1.0.0-beta", style=GUNMETAL_DIM),
        subtitle_align="right",
    )


# --------------------------------------------------------------------------- #
# Composition                                                                  #
# --------------------------------------------------------------------------- #
def build_banner() -> Group:
    return Group(
        Text(""),
        _wordmark(),
        Text(""),
        _info_box(),
        Text(""),
    )


def print_banner(console: Console | None = None) -> None:
    (console or Console()).print(build_banner())


if __name__ == "__main__":
    print_banner()
