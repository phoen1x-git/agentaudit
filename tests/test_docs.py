"""Documentation stays in sync with the code.

The English README drifted ahead of the Chinese one twice: new features were added, the
English README was updated, and the Chinese one silently went stale. Nobody notices that by
reading; a test notices immediately.
"""
from __future__ import annotations

import re
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


def test_the_readme_states_the_same_version_independent_facts():
    """Numbers that appear in both READMEs should agree."""
    import subprocess
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "validate_config.py"), "--table"],
                       capture_output=True, text=True, cwd=str(ROOT))
    n_rules = p.stdout.count("\n| `")
    en = EN.read_text(encoding="utf-8")
    zh = ZH.read_text(encoding="utf-8")
    assert f"{n_rules} dangerous-call rules" in en, f"README.md does not say {n_rules} rules"
    assert f"{n_rules} 条危险调用规则" in zh, f"README.zh-CN.md does not say {n_rules} rules"
