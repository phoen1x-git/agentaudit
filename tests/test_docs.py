"""Documentation stays in sync with the code.

The English README drifted ahead of the Chinese one twice: new features were added, the
English README was updated, and the Chinese one silently went stale. Nobody notices that by
reading; a test notices immediately.
"""
from __future__ import annotations

import functools
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EN = ROOT / "README.md"
ZH = ROOT / "README.zh-CN.md"
CHANGELOG = ROOT / "CHANGELOG.md"
# The floor CONTRIBUTING.md claims. Raise it when the suite grows past it.
FLOOR_TESTS = 120
CONTRIBUTING = ROOT / "CONTRIBUTING.md"

H2 = re.compile(r"^## (.+)$", re.M)
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)#:]+?)(?:#[^)]*)?\)")


def _h2(path: Path) -> list[str]:
    return H2.findall(path.read_text(encoding="utf-8"))


def test_both_readmes_exist():
    assert EN.exists() and ZH.exists()


def test_the_two_readmes_have_the_same_section_structure():
    en, zh = _h2(EN), _h2(ZH)
    assert len(en) == len(zh), (
        f"README.md has {len(en)} top-level sections and README.zh-CN.md has {len(zh)}; one of "
        f"them is behind.\n  en: {en}\n  zh: {zh}")


@pytest.mark.parametrize("readme", [EN, ZH], ids=["en", "zh"])
def test_every_command_is_documented(readme):
    from app.cli import COMMANDS
    text = readme.read_text(encoding="utf-8")
    missing = [name for name in COMMANDS if f"agentaudit {name}" not in text]
    # `scan` is the front door and appears in every example; the rest must be named too.
    assert not missing, f"{readme.name} never mentions: {missing}"


@pytest.mark.parametrize("readme", [EN, ZH], ids=["en", "zh"])
def test_relative_links_resolve(readme):
    broken = []
    for target in MD_LINK.findall(readme.read_text(encoding="utf-8")):
        if target.startswith(("http", "mailto:", "#")):
            continue
        if not (ROOT / target).exists():
            broken.append(target)
    assert not broken, f"{readme.name} links to missing paths: {sorted(set(broken))}"


@functools.lru_cache(maxsize=1)
def _scan_options() -> tuple[str, ...]:
    """Every long option the main entry point accepts, read from argparse itself.

    Cached: this shells out, and starting a Python process on Windows is not cheap. The
    options cannot change during a test run.
    """
    p = subprocess.run([sys.executable, str(ROOT / "app" / "scan.py"), "--help"],
                       capture_output=True, text=True, cwd=str(ROOT))
    options = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", p.stdout))
    return tuple(sorted(options))


@pytest.mark.parametrize("readme", [EN, ZH], ids=["en", "zh"])
def test_every_option_of_the_main_entry_point_is_documented(readme):
    """A flag added to `scan` but not to the READMEs is a flag nobody will find.

    This is the same failure as the section drift above, one level down: it happened with
    `--no-unknown-downgrade`, which shipped undocumented.
    """
    text = readme.read_text(encoding="utf-8")
    missing = [o for o in _scan_options() if o not in text]
    assert not missing, f"{readme.name} never documents: {missing}"


def test_the_option_list_is_not_trivially_empty():
    assert len(_scan_options()) >= 10, "the help output could not be parsed"


@pytest.mark.parametrize("readme", [EN, ZH], ids=["en", "zh"])
def test_the_documented_files_exist(readme):
    """Every script named in the docs is a real script."""
    text = readme.read_text(encoding="utf-8")
    named = set(re.findall(r"\b((?:app|tools|core|scripts)/[\w./-]+\.(?:py|sh))", text))
    missing = sorted(n for n in named if not (ROOT / n).exists())
    assert not missing, f"{readme.name} documents scripts that do not exist: {missing}"


def test_the_changelog_documents_the_current_version():
    from core import __version__
    text = CHANGELOG.read_text(encoding="utf-8")
    assert f"## {__version__}" in text, f"CHANGELOG.md has no entry for {__version__}"


@functools.lru_cache(maxsize=1)
def _rule_count() -> int:
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "validate_config.py"), "--table"],
                       capture_output=True, text=True, cwd=str(ROOT))
    return p.stdout.count("\n| `")


def _suite_count() -> int:
    return len(list((ROOT / "tools").glob("selftest_*.py")))


@functools.lru_cache(maxsize=1)
def _test_count() -> int:
    """How many tests pytest collects. `--collect-only` never runs them, so no recursion."""
    p = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "tests"],
                       capture_output=True, text=True, cwd=str(ROOT))
    m = re.search(r"(\d+) tests? collected", p.stdout)
    assert m, f"could not read the test count:\n{p.stdout[-800:]}"
    return int(m.group(1))


def test_the_rule_count_is_true():
    """A count in a README is marketing until something verifies it, so this one is checked."""
    n_rules = _rule_count()
    en, zh = EN.read_text(encoding="utf-8"), ZH.read_text(encoding="utf-8")
    assert f"{n_rules} dangerous-call rules" in en, f"README.md does not say {n_rules} rules"
    assert f"{n_rules} 条危险调用规则" in zh, f"README.zh-CN.md does not say {n_rules} rules"
    assert n_rules > 10, "the check would pass on zero rules"


def test_the_contributing_guide_states_the_real_test_count():
    """The suite and test counts live where a contributor needs them, not in the README.

    They are checked here rather than in the README on purpose: a number a *user* cannot act
    on is decoration, and it drifts every time a test is added.
    """
    n_suites, n_tests = _suite_count(), _test_count()
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert f"{n_suites} rule self-test suites" in text, \
        f"CONTRIBUTING.md does not say {n_suites} suites"
    # A lower bound, not the exact count: pinning the exact number means every new test makes
    # CI red until somebody edits a document nobody reads for that. `more than N` still fails
    # if tests are deleted, and never needs touching when they are added.
    assert f"more than {FLOOR_TESTS} tests" in text, \
        f"CONTRIBUTING.md should say 'more than {FLOOR_TESTS} tests'"
    assert n_tests > FLOOR_TESTS, f"only {n_tests} tests collected; the claim is now false"
    assert n_suites >= 5, "the check would pass on zero suites"



def test_every_switch_the_code_reads_is_documented():
    """Eleven variables used to exist with no mention in any document.

    The README deliberately lists only the ones a user normally sets, so the check is against
    CONFIGURING.md, which is the complete reference.
    """
    conf = (ROOT / "CONFIGURING.md").read_text(encoding="utf-8")
    seen: set[str] = set()
    for pkg in ("app", "core", "tools"):
        for path in (ROOT / pkg).rglob("*.py"):
            body = path.read_text(encoding="utf-8", errors="replace")
            seen |= set(re.findall(r"""environ(?:\.get)?\(?[\[\(]?["\']((?:AF|AGENTAUDIT)_[A-Z0-9_]+)["\']""", body))
    assert len(seen) > 15, f"the scan found only {len(seen)} switches; the pattern is probably wrong"
    missing = sorted(k for k in seen if k not in conf)
    assert not missing, f"read by the code but not listed in CONFIGURING.md: {missing}"


ASCII_ANCHOR = re.compile(r"^[a-z0-9-]+$")


def _slug(heading: str) -> str:
    """The anchor a renderer generates for a heading, when the heading is ASCII.

    Only ASCII headings are considered. A CJK heading is not given a usable anchor by every
    renderer -- the first version of this test assumed GitHub's behaviour (CJK kept as-is) and
    passed while the link was broken in the renderer the README was actually read in. A check
    built on an assumption about a renderer cannot verify anything about that renderer.
    """
    text = re.sub(r"`([^`]*)`", r"\1", heading)              # code spans lose their backticks
    text = re.sub(r"\[([^]]*)]\([^)]*\)", r"\1", text)           # links keep their label
    text = text.strip().lower()
    text = re.sub(r"[^\w\s\-]", "", text)
    return re.sub(r"\s+", "-", text)


def _all_markdown():
    """Every Markdown file, not just the two READMEs: a broken anchor in CONFIGURING.md is
    just as broken."""
    skip = {".git", ".workbuddy", "out", "data", "_targets", "__pycache__"}
    return sorted(p for p in ROOT.rglob("*.md")
                  if not any(x in p.relative_to(ROOT).parts for x in skip))


@pytest.mark.parametrize("readme", _all_markdown(), ids=lambda p: p.name)
def test_in_document_links_point_at_a_real_heading(readme):
    """Two rules, and the first one is the important one.

    1. An anchor must be ASCII. `#\u6279\u91cf\u626b\u63cf` works on GitHub and does not work
       everywhere else, so a heading in another script gets an explicit `<a id="...">` target.
    2. It must point at something: either a heading that slugs to it, or one of those ids.
    """
    text = readme.read_text(encoding="utf-8")
    anchors = set(re.findall(r"]\(#([^)]+)\)", text))
    if readme in (EN, ZH):
        # the two READMEs are known to have one; if this trips, the pattern is wrong
        assert anchors, f"{readme.name} has no in-document links; the pattern may be wrong"
    if not anchors:
        return

    non_ascii = sorted(a for a in anchors if not ASCII_ANCHOR.match(a))
    assert not non_ascii, (
        f"{readme.name} uses anchors that are not ASCII: {non_ascii}. "
        'Give the heading an explicit `<a id="ascii-name"></a>` and link to that.')

    targets = {_slug(h) for h in re.findall(r"^#{1,6}\s+(.+)$", text, re.M)}
    targets |= set(re.findall(r'<a id="([^"]+)"></a>', text))
    broken = sorted(a for a in anchors if a not in targets)
    assert not broken, f"{readme.name} links to headings that do not exist: {broken}"


def test_the_anchor_targets_are_ascii_too():
    """The ids themselves, not just the links, must be ASCII -- otherwise the same problem
    comes back from the other side."""
    for readme in _all_markdown():
        ids = re.findall(r'<a id="([^"]+)"></a>', readme.read_text(encoding="utf-8"))
        for i in ids:
            assert ASCII_ANCHOR.match(i), f"{readme.name} declares a non-ASCII anchor id: {i!r}"
