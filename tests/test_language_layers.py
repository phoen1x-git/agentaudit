"""Which layer a reader actually opens, and in which language it is written.

The public face of this tool is the command line, the report, and the HTML index. Someone
deciding whether to trust it reads those files, and reads English. `core/` and `tools/` are
the engine and the bench: they record what was tried and what went wrong, and they are
written in Chinese, which is the language the author thinks in.

So this is a layer rule, not a word list. A word list could not express it: banning a
Chinese word does nothing for a reader who cannot read the sentence around it.

The rule:
  app/     English, except the files listed below (they render the zh-CN locale by design)
  tests/   English comments; assertions may quote Chinese output, because that output is
           what the test is checking
  core/    unconstrained
  tools/   unconstrained
"""
from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

CJK = re.compile(r"[\u4e00-\u9fff]")

# Files in app/ that carry Chinese on purpose. Each one is a reason, not a permission slip.
ZH_ALLOWED = {
    "app/make_index.py": "renders the zh-CN variant of the HTML index; the strings are a locale",
    "app/make_report.py": "renders the zh-CN report draft; the strings are a locale",
    "app/prepare_targets.py": "debt: Chinese comments in a file that ships with the package",
}


def _files(folder: str):
    return [p for p in sorted((ROOT / folder).glob("*.py")) if p.name != "__init__.py"]


def _comments_and_docstrings(path: Path) -> list[tuple[int, str]]:
    """Chinese in comments and docstrings -- the part written for a maintainer."""
    found = []
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError):
        pytest.fail(f"{path.relative_to(ROOT)} does not tokenize")
    prev_significant = None
    for tok in toks:
        if tok.type == tokenize.COMMENT and CJK.search(tok.string):
            found.append((tok.start[0], tok.string.strip()))
        elif tok.type == tokenize.STRING and CJK.search(tok.string):
            # A bare string statement is a docstring; an assigned or asserted string is a
            # value, and values are allowed to be Chinese (a test may quote the output it
            # is checking for).
            if prev_significant is None or prev_significant.type in (
                tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.NL):
                found.append((tok.start[0], tok.string.strip()[:80]))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev_significant = tok
    return found


def _any_chinese(path: Path) -> list[tuple[int, str]]:
    return [(i, line.strip())
            for i, line in enumerate(path.read_text(encoding="utf-8",
                                                    errors="replace").splitlines(), 1)
            if CJK.search(line)]


def test_app_is_written_for_the_reader():
    """`agentaudit scan` and friends are what a stranger opens first."""
    offenders = []
    for path in _files("app"):
        rel = path.relative_to(ROOT).as_posix()
        if rel in ZH_ALLOWED:
            continue
        for lineno, line in _any_chinese(path):
            offenders.append(f"{rel}:{lineno}  {line[:100]}")
    assert not offenders, (
        "app/ is the layer a reader opens, and it is written in English. "
        "These lines are not:\n" + "\n".join(offenders[:20]))


def test_tests_explain_themselves_in_english():
    """A test's failure message is read by whoever breaks it; that reader is not assumed
    to read Chinese. Assertions may still quote Chinese output -- that is data."""
    offenders = []
    for path in _files("tests"):
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in _comments_and_docstrings(path):
            offenders.append(f"{rel}:{lineno}  {line[:100]}")
    assert not offenders, (
        "comments and docstrings in tests/ are English:\n" + "\n".join(offenders[:20]))


def test_the_allowed_list_has_no_stale_entries():
    """An entry that no longer contains Chinese is a permission nobody needs; drop it.

    Without this, the list only grows, and a list that only grows is how a rule stops
    meaning anything.
    """
    stale = []
    for rel, _reason in ZH_ALLOWED.items():
        path = ROOT / rel
        assert path.exists(), f"{rel} is listed but does not exist"
        if not _any_chinese(path):
            stale.append(rel)
    assert not stale, (
        "these files no longer contain Chinese; remove them from ZH_ALLOWED:\n"
        + "\n".join(stale))


# ---------------------------------------------------------------------------- what it prints
#
# The directory rule above is necessary and not sufficient. `core/` owns no user-facing file,
# yet it prints: a scan once emitted one Chinese status line between two English ones, from a
# rule that lived in core/. No rule about directories could see it. So this one runs the
# commands and reads the terminal.

PRINTED_COMMANDS = [
    (["doctor"], "the screen a new user runs first"),
    (["--help"], "the command list"),
    (["selftest"], "the rules' own tests"),
    (["targets", "--help"], "the batch path, which was the last Chinese help page"),
    (["candidates", "--help"], "the contract command"),
    (["scan", "--demo", "--tag", "lang-check", "--no-log"], "the demo scan"),
]


@pytest.mark.parametrize("argv,why", PRINTED_COMMANDS, ids=[c[0][0] for c in PRINTED_COMMANDS])
def test_what_a_command_prints_is_english(argv, why, tmp_path):
    import os
    import subprocess
    import sys

    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    proc = subprocess.run(
        [sys.executable, "-m", "app.cli", *argv],
        cwd=str(tmp_path),               # output lands in the test's own directory
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=env, timeout=180,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    offenders = [ln for ln in output.splitlines() if CJK.search(ln)]
    assert not offenders, (
        f"`agentaudit {' '.join(argv)}` ({why}) prints Chinese. Whatever reaches the "
        f"terminal is read by the same stranger as the README:\n"
        + "\n".join(offenders[:15]))

