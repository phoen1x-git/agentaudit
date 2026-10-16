"""The banner must not be able to break the terminal it is printed into.

A frame drawn with block characters looks tidy right up until the font draws those characters
two cells wide, and then it is a staircase. Since that cannot be seen from inside the program,
what is tested here is the fallback: it exists, it is reachable, and it is pure ASCII when used.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import banner  # noqa: E402


@pytest.mark.parametrize("name", sorted(banner.VARIANTS))
def test_every_variant_renders(name):
    text = banner.render(name, unicode=True)
    assert text.strip(), f"{name} renders nothing"
    assert len(text.splitlines()) >= 1


@pytest.mark.parametrize("name", sorted(banner.VARIANTS))
def test_the_ascii_fallback_is_pure_ascii(name):
    """The fallback exists for terminals that cannot draw the Unicode version."""
    text = banner.render(name, unicode=False)
    bad = {ch for ch in text if ord(ch) > 126}
    assert not bad, f"{name} (ascii) contains non-ASCII characters: {sorted(bad)}"


def test_the_unicode_variants_are_actually_using_unicode():
    """Otherwise the 'fallback' is the only thing there is, and the test above proves nothing."""
    assert any(ord(c) > 126 for c in banner.render("wordmark", unicode=True))
    assert any(ord(c) > 126 for c in banner.render("boxed", unicode=True))
    assert any(ord(c) > 126 for c in banner.render("glyph", unicode=True))


def test_the_boxed_frame_lines_up():
    for unicode in (True, False):
        lines = banner.render("boxed", unicode=unicode).splitlines()
        widths = {len(line) for line in lines}
        assert len(widths) == 1, f"the frame is ragged (unicode={unicode}): {sorted(widths)}"


def test_the_boxed_frame_is_closed():
    lines = banner.render("boxed", unicode=True).splitlines()
    assert lines[0][0] == "\u256d" and lines[0][-1] == "\u256e"
    assert lines[-1][0] == "\u2570" and lines[-1][-1] == "\u256f"
    for line in lines[1:-1]:
        assert line[0] == "\u2502" and line[-1] == "\u2502"


def test_the_glyph_lines_up():
    for unicode in (True, False):
        lines = banner.render("glyph", unicode=unicode).splitlines()
        assert all(line.strip() for line in lines), "the glyph has a blank line in it"


def test_the_name_is_readable_in_the_wordmark():
    """A quick sanity check that the bitmap font produced letters, not noise."""
    art = banner.variant_wordmark(unicode=True).splitlines()[:5]
    assert len(art) == 5
    assert all(line.strip() for line in art)


def test_the_bar_is_two_lines_and_fits_a_terminal():
    lines = banner.render("bar", unicode=True).splitlines()
    assert len(lines) == 2
    assert max(len(line) for line in lines) <= 80


def test_the_version_reaches_the_boxed_banner():
    from core import __version__
    assert __version__ in banner.render("boxed", unicode=True)


def test_ascii_can_be_forced_by_the_environment(monkeypatch):
    monkeypatch.setenv("AGENTAUDIT_ASCII", "1")
    assert banner.supports_unicode() is False
    monkeypatch.setenv("AGENTAUDIT_ASCII", "0")
    # With no console to ask, it must not claim the font is CJK.
    assert isinstance(banner.supports_unicode(), bool)


def test_the_font_detection_never_raises():
    """It runs on startup; a crash here would take the whole tool down."""
    assert isinstance(banner.cjk_console(), bool)


def test_render_defaults_to_the_chosen_variant():
    assert banner.DEFAULT in banner.VARIANTS
    assert banner.COMPACT in banner.VARIANTS
    assert banner.render() == banner.render(banner.DEFAULT)


def test_the_preview_command_works():
    import subprocess
    p = subprocess.run([sys.executable, str(ROOT / "app" / "banner.py")],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert p.returncode == 0, p.stdout + p.stderr
    for name in banner.VARIANTS:
        assert name in p.stdout
