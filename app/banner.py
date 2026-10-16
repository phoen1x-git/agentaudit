#!/usr/bin/env python
"""The banner: what the tool looks like when you open it.

Four variants, so the one you prefer is a one-word change rather than a redesign:

    python app/banner.py                 # preview all of them
    python app/banner.py --variant glyph # preview one

Everything here is drawn from a small bitmap, not typed by hand, so the columns line up. Two
renderings of each shape are defined: Unicode (block elements and box drawing) and a pure
ASCII fallback for fonts and terminals that cannot show the former.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from core import __version__
except Exception:                        # pragma: no cover - only if run out of tree
    __version__ = "?"

# ---------------------------------------------------------------------------
# A compact 5x5 font. Only the letters the name needs.
# ---------------------------------------------------------------------------
FONT = {
    "A": [" ### ", "#   #", "#   #", "#####", "#   #"],
    "G": [" ####", "#    ", "# ###", "#   #", " ### "],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "U": ["#   #", "#   #", "#   #", "#   #", " ### "],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    " ": ["  ", "  ", "  ", "  ", "  "],
}


# Characters used to probe the terminal and to separate the tagline. The middle dot is
# ambiguous-width too, so even the separator has to change with the rendering.
_PROBE = "\u256d\u2588\u00b7\u25c8"
_SEP = {True: "\u00b7", False: "-"}

# Fonts that draw ambiguous-width characters two cells wide.
_CJK_FACES = ("simsun", "nsimsun", "mingliu", "ms gothic", "batang", "malgun", "gulim",
              "\u5b8b", "\u65b0\u5b8b", "\u9ed1\u4f53", "\u5b8b\u4f53")


def _word(word: str, fill: str) -> list[str]:
    rows = ["", "", "", "", ""]
    for ch in word.upper():
        glyph = FONT.get(ch)
        if glyph is None:
            continue
        for i in range(5):
            rows[i] += glyph[i] + (" " if fill == "#" else "  ")
    return [r.rstrip() for r in rows]


def _ascii(word: str) -> list[str]:
    return _word(word, "#")


def _block(word: str) -> list[str]:
    """The ASCII bitmap, with the ink turned into solid blocks."""
    art = _word(word, "#")
    return [line.replace("#", "\u2588") for line in art]


# ---------------------------------------------------------------------------
# Variants
# ---------------------------------------------------------------------------
def variant_wordmark(unicode: bool = True) -> str:
    """The name, big, with one line of what it is underneath."""
    art = _block("AGENTAUDIT") if unicode else _ascii("AGENTAUDIT")
    bar = "\u2500" * len(art[0]) if unicode else "-" * len(art[0])
    tag = f"code audit for AI agents  {_SEP[unicode]}  candidates, not conclusions"
    return "\n".join(art) + f"\n{bar}\n{tag}"


def _lens(unicode: bool = True) -> list[str]:
    """A lens: a box with a terminal prompt in it, and a handle going down and right."""
    if unicode:
        return [
            " \u256d\u2500\u2500\u2500\u2500\u2500\u256e",
            " \u2502 >_  \u2502",
            " \u2570\u2500\u2500\u2500\u2500\u2500\u256f",
            "    \u2572",
            "     \u2572___",
        ]
    return [
        " .-----.",
        " | >_  |",
        " '-----'",
        "    \\",
        "     \\___",
    ]


def variant_glyph(unicode: bool = True) -> str:
    """The lens, with the name beside it. For opening a session."""
    art = _lens(unicode)
    text = [
        "agentaudit",
        "code audit for AI agents",
        "candidates, not conclusions",
    ]
    out = []
    for i, line in enumerate(art):
        out.append(line + ("   " + text[i] if i < len(text) else ""))
    return "\n".join(x.rstrip() for x in out)


def variant_lens(unicode: bool = True) -> str:
    """The lens alone -- for a header where the name is already on screen."""
    return "\n".join(_lens(unicode))


def variant_boxed(unicode: bool = True) -> str:
    """The name inside a frame. The most 'finished-looking' of the four."""
    art = _block("AGENTAUDIT") if unicode else _ascii("AGENTAUDIT")
    # Rows come out of the font with different lengths (trailing blanks trimmed); the frame
    # needs them all the same width or the right border goes ragged.
    art_w = max(len(line) for line in art)
    art = [line.ljust(art_w) for line in art]

    tag = f"code audit for AI agents  {_SEP[unicode]}  candidates, not conclusions"
    ver = f"v{__version__}"
    inner = max(art_w, len(tag), len(ver))
    pad = 2
    width = inner + pad * 2 + 2          # + 2 for the two border columns

    if unicode:
        tl, tr, bl, br, h, v = "\u256d", "\u256e", "\u2570", "\u256f", "\u2500", "\u2502"
    else:
        tl = tr = bl = br = "+"
        h, v = "-", "|"

    def row(text: str = "") -> str:
        return v + " " * pad + text.center(inner) + " " * pad + v

    out = [tl + h * (width - 2) + tr, row()]
    out += [row(line) for line in art]
    out += [row(), row(tag), row(ver), bl + h * (width - 2) + br]
    return "\n".join(out)


def variant_bar(unicode: bool = True) -> str:
    """One line. For the top of every scan, where a banner would be noise."""
    # The ASCII mark is the prompt from the lens above. An earlier version used "[]", which
    # readers took for a missing glyph rather than a mark.
    mark = "\u25c8" if unicode else ">_"
    rule = "\u2500" * 66 if unicode else "-" * 66
    return f"{mark} agentaudit  {_SEP[unicode]}  code audit for AI agents\n{rule}"


VARIANTS = {
    "wordmark": variant_wordmark,
    "boxed": variant_boxed,
    "glyph": variant_glyph,
    "lens": variant_lens,
    "bar": variant_bar,
}

# ★ Pick the one you want here. Everything else follows.
DEFAULT = "boxed"
# The one-liner used above the usage text, where a full banner would be noise.
COMPACT = "bar"


def supports_unicode() -> bool:
    """Whether the terminal can take block and box-drawing characters.

    Two separate questions are folded in here, and they fail differently:

    * **Encoding** -- can the character leave Python at all? On Windows this is true more often
      than people expect: console output is written as UTF-8 and converted by the console, so
      the code page is not the limiting factor.
    * **Font** -- will the character be drawn one cell wide? Block elements and box drawing are
      East-Asian-Width "ambiguous", and a CJK font draws them two cells wide, which turns a
      tidy frame into a staircase.

    `AGENTAUDIT_ASCII=1` forces the fallback.
    """
    import os
    if os.environ.get("AGENTAUDIT_ASCII") == "1":
        return False
    enc = getattr(sys.stdout, "encoding", "") or ""
    try:
        _PROBE.encode(enc)
    except (UnicodeEncodeError, LookupError, TypeError):
        return False
    return not cjk_console()


def cjk_console() -> bool:
    """Whether the terminal is likely to draw ambiguous-width characters double-width."""
    import os
    if os.name != "nt":
        lang = (os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE")
                or os.environ.get("LANG") or "").lower()
        return lang.startswith(("zh", "ja", "ko"))
    try:
        import ctypes
        from ctypes import wintypes

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class FONT_INFOEX(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.ULONG), ("nFont", wintypes.DWORD),
                        ("dwFontSize", COORD), ("FontFamily", wintypes.UINT),
                        ("FontWeight", wintypes.UINT), ("FaceName", ctypes.c_wchar * 32)]

        kernel32 = ctypes.windll.kernel32
        info = FONT_INFOEX()
        info.cbSize = ctypes.sizeof(info)
        if not kernel32.GetCurrentConsoleFontEx(kernel32.GetStdHandle(-11), False,
                                                ctypes.byref(info)):
            return False
        face = (info.FaceName or "").lower()
    except Exception:
        return False
    return any(k in face for k in _CJK_FACES)




def render(variant: str = "", unicode: bool | None = None) -> str:
    name = variant or DEFAULT
    if unicode is None:
        unicode = supports_unicode()
    return VARIANTS.get(name, variant_boxed)(unicode)


def main() -> int:
    ap = argparse.ArgumentParser(description="preview the banner")
    ap.add_argument("--variant", default="", choices=[""] + sorted(VARIANTS))
    ap.add_argument("--ascii", action="store_true", help="force the ASCII fallback")
    a = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    names = [a.variant] if a.variant else list(VARIANTS)
    for name in names:
        print(f"\n===== {name} {'(ascii)' if a.ascii else ''} " + "=" * 40)
        print(render(name, unicode=not a.ascii))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
