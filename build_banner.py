#!/usr/bin/env python3
"""Generate the ORION GitHub banner (tactical / brushed-metal style)."""
from __future__ import annotations

W, H = 1280, 470

# --------------------------------------------------------------------------- #
# Pixel wordmark grids (1 = lit pixel), 7 rows tall.                           #
# --------------------------------------------------------------------------- #
GLYPHS = {
    "O": [
        ".1111.",
        "111111",
        "11..11",
        "11..11",
        "11..11",
        "111111",
        ".1111.",
    ],
    "R": [
        "11111.",
        "111111",
        "11..11",
        "111111",
        "11111.",
        "11.11.",
        "11..11",
    ],
    "I": [
        "1111",
        "1111",
        ".11.",
        ".11.",
        ".11.",
        "1111",
        "1111",
    ],
    "N": [
        "11...11",
        "111..11",
        "1111.11",
        "11.1111",
        "11..111",
        "11...11",
        "11...11",
    ],
}
WORD = "ORION"


def pixel_wordmark(x0: int, y0: int, cell: int, gap: int) -> str:
    """Emit <rect>s for the pixel wordmark starting at (x0, y0)."""
    out = []
    cx = x0
    step = cell + gap
    for ch in WORD:
        grid = GLYPHS[ch]
        rows = len(grid)
        cols = len(grid[0])
        for r in range(rows):
            for c in range(cols):
                if grid[r][c] == "1":
                    px = cx + c * step
                    py = y0 + r * step
                    out.append(
                        f'<rect x="{px}" y="{py}" width="{cell}" height="{cell}" '
                        f'rx="1.5" fill="url(#pix)"/>'
                    )
        cx += cols * step + step  # inter-letter gap = one extra cell
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Brushed-metal horizontal striations                                         #
# --------------------------------------------------------------------------- #
def brushed_lines() -> str:
    out = []
    for i, y in enumerate(range(0, H, 3)):
        op = 0.035 if i % 2 == 0 else 0.02
        out.append(
            f'<line x1="0" y1="{y}" x2="{W}" y2="{y}" stroke="#ffffff" '
            f'stroke-opacity="{op}" stroke-width="1"/>'
        )
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Faceted metal arrowhead pointing right                                       #
# --------------------------------------------------------------------------- #
def arrowhead() -> str:
    cy = 235
    # Outline vertices (clockwise from the tip).
    T   = (1236, cy)
    Uin = (1040, 150)
    Uout= (1006, 58)
    Nku = (952, 176)
    Sut = (686, 214)
    Sub = (686, 256)
    Nkl = (952, 294)
    Lout= (1006, 412)
    Lin = (1040, 320)
    ML  = (686, cy)      # mid-left, on the centerline

    def poly(pts, **attr):
        p = " ".join(f"{x},{y}" for x, y in pts)
        a = " ".join(f'{k.replace("_","-")}="{v}"' for k, v in attr.items())
        return f'<polygon points="{p}" {a}/>'

    parts = []
    # Soft drop shadow.
    parts.append(
        poly([T, Uin, Uout, Nku, Sut, Sub, Nkl, Lout, Lin],
             fill="#000000", fill_opacity="0.45",
             transform="translate(10,14)", filter="url(#blur)")
    )
    # Upper facet (lit).
    parts.append(poly([T, Uin, Uout, Nku, Sut, ML], fill="url(#steelTop)"))
    # Lower facet (shadow).
    parts.append(poly([T, ML, Sub, Nkl, Lout, Lin], fill="url(#steelBot)"))

    # Central ridge / shaft beam (diamond cross-section look).
    beam_top = [(706, cy - 22), (1120, cy - 22), (1180, cy), (706, cy)]
    beam_bot = [(706, cy), (1180, cy), (1120, cy + 22), (706, cy + 22)]
    parts.append(poly(beam_top, fill="url(#ridgeTop)"))
    parts.append(poly(beam_bot, fill="url(#ridgeBot)"))
    # Groove line down the ridge.
    parts.append(f'<line x1="712" y1="{cy}" x2="1176" y2="{cy}" stroke="#0c0d0e" '
                 f'stroke-width="2" stroke-opacity="0.7"/>')

    # Specular steel highlight just inside the upper edge.
    parts.append(f'<path d="M {Sut[0]+30},{Sut[1]+6} L {Nku[0]+6},{Nku[1]+4} '
                 f'L {Uout[0]+10},{Uout[1]+16} L {Uin[0]-4},{Uin[1]+8} L {T[0]-40},{T[1]-4}" '
                 f'fill="none" stroke="#c7ccd2" stroke-width="2.5" stroke-opacity="0.5" '
                 f'stroke-linejoin="round"/>')

    # Orange rim light on the top-facing / leading edges.
    rim_top = f"M {Sut[0]},{Sut[1]} L {Nku[0]},{Nku[1]} L {Uout[0]},{Uout[1]} " \
              f"L {Uin[0]},{Uin[1]} L {T[0]},{T[1]}"
    parts.append(f'<path d="{rim_top}" fill="none" stroke="url(#edge)" '
                 f'stroke-width="4" stroke-linejoin="round" stroke-linecap="round"/>')
    # Fainter rim on the lower leading edge.
    rim_bot = f"M {T[0]},{T[1]} L {Lin[0]},{Lin[1]} L {Lout[0]},{Lout[1]}"
    parts.append(f'<path d="{rim_bot}" fill="none" stroke="#B4500C" '
                 f'stroke-width="3" stroke-opacity="0.8" stroke-linejoin="round"/>')

    # A couple of engraved facet lines for tactical detail.
    parts.append(f'<line x1="{Nku[0]+8}" y1="{Nku[1]+6}" x2="1150" y2="200" '
                 f'stroke="#0c0d0e" stroke-width="2" stroke-opacity="0.5"/>')
    parts.append(f'<line x1="{Nkl[0]+8}" y1="{Nkl[1]-6}" x2="1150" y2="270" '
                 f'stroke="#0c0d0e" stroke-width="2" stroke-opacity="0.4"/>')

    # Engraved wordmark on the blade.
    parts.append(
        f'<text x="1055" y="300" font-family="DejaVu Sans Mono, monospace" '
        f'font-size="15" letter-spacing="3" fill="#9aa0a6" fill-opacity="0.35" '
        f'transform="rotate(-27 1055 300)">RECON ENGINEERED</text>'
    )
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Assemble                                                                     #
# --------------------------------------------------------------------------- #
SVG = f"""<svg width="{W}" height="{H}" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="ORION - Tactical Bug Hunting Framework">
  <defs>
    <radialGradient id="bg" cx="46%" cy="42%" r="85%">
      <stop offset="0%" stop-color="#202225"/>
      <stop offset="60%" stop-color="#131417"/>
      <stop offset="100%" stop-color="#0a0a0b"/>
    </radialGradient>
    <linearGradient id="sheen" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#ffffff" stop-opacity="0.05"/>
      <stop offset="45%" stop-color="#ffffff" stop-opacity="0"/>
      <stop offset="100%" stop-color="#000000" stop-opacity="0.14"/>
    </linearGradient>
    <linearGradient id="pix" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#F0912A"/>
      <stop offset="55%" stop-color="#D9741E"/>
      <stop offset="100%" stop-color="#B35810"/>
    </linearGradient>
    <linearGradient id="steelTop" x1="0" y1="0" x2="0.15" y2="1">
      <stop offset="0%" stop-color="#9298a0"/>
      <stop offset="50%" stop-color="#5c6167"/>
      <stop offset="100%" stop-color="#3b3f44"/>
    </linearGradient>
    <linearGradient id="steelBot" x1="0" y1="0" x2="0.15" y2="1">
      <stop offset="0%" stop-color="#4c5157"/>
      <stop offset="55%" stop-color="#303338"/>
      <stop offset="100%" stop-color="#1b1d20"/>
    </linearGradient>
    <linearGradient id="ridgeTop" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#b3b8bf"/>
      <stop offset="100%" stop-color="#5a5f65"/>
    </linearGradient>
    <linearGradient id="ridgeBot" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#4a4e54"/>
      <stop offset="100%" stop-color="#232528"/>
    </linearGradient>
    <linearGradient id="edge" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#FFB042"/>
      <stop offset="60%" stop-color="#FF8C00"/>
      <stop offset="100%" stop-color="#FFC46B"/>
    </linearGradient>
    <filter id="blur" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="7"/>
    </filter>
  </defs>

  <rect width="{W}" height="{H}" fill="url(#bg)"/>
  <g>{brushed_lines()}</g>
  <rect width="{W}" height="{H}" fill="url(#sheen)"/>
  <rect x="14" y="14" width="{W-28}" height="{H-28}" rx="10" fill="none"
        stroke="#3a3d42" stroke-opacity="0.5" stroke-width="1.5"/>

  <!-- wordmark -->
  {pixel_wordmark(x0=70, y0=150, cell=15, gap=2)}

  <!-- tagline -->
  <text x="74" y="316" font-family="DejaVu Sans, Segoe UI, Arial, sans-serif"
        font-size="26" font-weight="600" letter-spacing="7" fill="#9a9ea3">TACTICAL BUG HUNTING FRAMEWORK</text>

  <!-- arrowhead -->
  <g transform="translate(14,0)">{arrowhead()}</g>
</svg>
"""

with open("assets/orion-banner.svg", "w") as f:
    f.write(SVG)
print("wrote assets/orion-banner.svg")
