"""The rule self-test suites all pass.

`tools/run_selftests.py` drives ten suites of labelled cases. They are the regression net for
the checks themselves; if one of them fails, no scan result should be trusted.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_rule_self_tests_pass():
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "run_selftests.py")],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert p.returncode == 0, p.stdout + p.stderr
    assert "all suites passed" in p.stdout


def test_every_selftest_file_is_registered():
    """A suite that exists on disk but is not run is the same as not having it."""
    from pathlib import Path as _P

    on_disk = {p.name for p in (ROOT / "tools").glob("selftest_*.py")}
    runner = (ROOT / "tools" / "run_selftests.py").read_text(encoding="utf-8")
    missing = sorted(n for n in on_disk if n not in runner)
    assert not missing, f"these suites are never run: {missing}"


def test_offline_scan_needs_no_optional_dependencies():
    """`--demo` promises to work with only PyYAML installed."""
    p = subprocess.run([sys.executable, str(ROOT / "app" / "scan.py"), "--demo",
                        "--tag", "ci-check", "--out", str(ROOT / "out")],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert p.returncode == 0, p.stdout + p.stderr
    assert "offline" in p.stdout
