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


def test_the_headline_numbers_are_true():
    """The table at the top of both READMEs is a claim, so it is checked like one.

    A count in a README is marketing until something verifies it. These three can be
    verified, so they are.
    """
    n_rules, n_suites, n_tests = _rule_count(), _suite_count(), _test_count()
    en, zh = EN.read_text(encoding="utf-8"), ZH.read_text(encoding="utf-8")
    assert f"{n_rules} dangerous-call rules" in en, f"README.md does not say {n_rules} rules"
    assert f"{n_rules} 条危险调用规则" in zh, f"README.zh-CN.md does not say {n_rules} rules"
    assert f"{n_suites} rule suites, {n_tests} tests" in en, \
        f"README.md does not say {n_suites} suites / {n_tests} tests"
    assert f"{n_suites} 套规则自测、{n_tests} 个测试" in zh, \
        f"README.zh-CN.md does not say {n_suites} suites / {n_tests} tests"


def test_the_numbers_are_not_accidentally_tiny():
    """Guards against a check that passes because it read zero of something."""
    assert _rule_count() > 10
    assert _suite_count() >= 5
    assert _test_count() > 20

