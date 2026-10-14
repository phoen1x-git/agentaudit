"""The single entry point forwards to the right script and returns its exit code."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "app" / "cli.py"


def _cli(*args, **kw):
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True,
                          cwd=str(ROOT), **kw)


def test_help_lists_every_command():
    p = _cli("--help")
    assert p.returncode == 0, p.stderr
    from app.cli import COMMANDS
    for name in COMMANDS:
        assert name in p.stdout, f"{name} is not listed in the help"


def test_version():
    p = _cli("--version")
    assert p.returncode == 0
    from core import __version__
    assert p.stdout.strip() == __version__


def test_unknown_command_fails_loudly():
    p = _cli("definitely-not-a-command")
    assert p.returncode == 2
    assert "unknown command" in p.stderr


def test_subcommand_arguments_are_forwarded():
    """`agentaudit validate` must behave exactly like `python tools/validate_config.py`."""
    p = _cli("validate")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "config ok" in p.stdout


def test_subcommand_exit_code_survives():
    """A non-zero exit from the script has to become a non-zero exit from the CLI."""
    p = _cli("log", "--clear")            # harmless, and never fails
    assert p.returncode == 0, p.stdout + p.stderr
    p = _cli("explain", str(ROOT / "does-not-exist"))
    assert p.returncode != 0


def test_scan_and_explain_via_the_cli(tmp_path):
    rd = tmp_path / "out"
    p = _cli("scan", "--demo", "--tag", "cli-test", "--out", str(rd), "--no-log")
    assert p.returncode == 0, p.stdout + p.stderr
    assert (rd / "round-cli-test" / "index.html").exists()

    p = _cli("explain", str(rd / "round-cli-test"), "--index", "1")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "this check" in p.stdout
