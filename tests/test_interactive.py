"""Interactive mode must work when there is a terminal, and stay out of the way when there is not.

The important property is the second one: a tool that waits for input in CI hangs a pipeline.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTERACTIVE = ROOT / "app" / "interactive.py"
CLI = ROOT / "app" / "cli.py"


def _run(script: Path, *args: str, stdin: str = "", forced: bool = True):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    env["AGENTAUDIT_INTERACTIVE"] = "1" if forced else "0"
    return subprocess.run([sys.executable, str(script), *args], input=stdin,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=str(ROOT), env=env, timeout=120)


def test_no_terminal_prints_usage_instead_of_waiting():
    p = _run(CLI, forced=False)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "usage: agentaudit" in p.stdout


def test_no_terminal_via_a_pipe_also_exits():
    """The real case: output piped somewhere. Must not block."""
    p = subprocess.run([sys.executable, str(CLI)], input="", capture_output=True, text=True,
                       cwd=str(ROOT), timeout=60,
                       env={k: v for k, v in os.environ.items() if k != "AGENTAUDIT_INTERACTIVE"})
    assert p.returncode == 0
    assert "usage: agentaudit" in p.stdout


def test_quitting_from_the_menu_is_clean():
    p = _run(INTERACTIVE, stdin="0\n")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "agentaudit" in p.stdout
    assert "bye" in p.stdout


def test_the_menu_lists_every_action():
    p = _run(INTERACTIVE, stdin="0\n")
    for label in ("Scan a target", "Open a previous round", "self-tests", "Scan statistics"):
        assert label in p.stdout, f"the menu does not offer {label!r}"


def test_listing_the_commands_works_from_the_menu():
    p = _run(INTERACTIVE, stdin="6\n\n0\n")           # 6 = list commands, blank = dismiss pause
    assert p.returncode == 0, p.stdout + p.stderr
    from app.cli import COMMANDS
    for name in COMMANDS:
        assert f"  {name}" in p.stdout, f"{name} is not listed"


def test_an_unknown_option_is_reported_and_the_menu_continues():
    p = _run(INTERACTIVE, stdin="nonsense\n0\n")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "no such option" in p.stdout
    assert "bye" in p.stdout


def test_end_of_input_does_not_crash_the_menu():
    """Ctrl-D at the prompt is a normal way to leave a CLI."""
    p = _run(INTERACTIVE, stdin="")
    assert p.returncode == 0, p.stdout + p.stderr


def test_scanning_from_the_menu_produces_a_round(tmp_path):
    """Drive option 1 -> 1 (the bundled sample), give a tag, skip the LLM, then quit.

    Also checks the echoed command, because seeing the command line is the point of the menu:
    whatever it runs, you are meant to be able to type it yourself. Both checks share one
    session — each one costs a full scan.
    """
    from core import workspace
    out = tmp_path / "out"
    env = dict(os.environ, PYTHONIOENCODING="utf-8", AGENTAUDIT_INTERACTIVE="1",
               AGENTAUDIT_HOME=str(tmp_path))
    p = subprocess.run(
        [sys.executable, str(INTERACTIVE)],
        input="1\n1\nmenu-test\nn\n\n0\n",
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(ROOT), env=env, timeout=180)
    assert p.returncode == 0, p.stdout + p.stderr
    assert (out / "round-menu-test" / "findings.tsv").exists(), p.stdout[-2000:]
    assert "app/scan.py" in p.stdout and "--demo" in p.stdout, "the command was not echoed"
