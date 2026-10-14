"""The unknown-source downgrade.

A candidate judged `vuln` whose `arg_source` is unknown or empty is not stable across
repeats, so it must not be presented as a reportable finding. It is downgraded to
`needs_human` instead -- a conservative move that keeps the original verdict around.

These tests pin the boundaries of that rule: which sources count as "known", which
verdicts are left alone, and that running it twice changes nothing the second time.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import consistency  # noqa: E402
from core.finding import Finding  # noqa: E402

KNOWN_SOURCES = ("llm_output", "user_input", "tool_arg", "memory", "config", "constant")


def _finding(verdict: str, arg_source: str) -> Finding:
    f = Finding(project="demo", sink_func="open", sink_uri="a.py", sink_line=1)
    f.ai_verdict = verdict
    f.arg_source = arg_source
    f.ai_reason = "original reason"
    return f


def test_unknown_source_is_downgraded():
    f = _finding("vuln", "unknown")
    changed = consistency.apply_unknown_downgrade([f])
    assert len(changed) == 1
    assert changed[0]["from"] == "vuln" and changed[0]["to"] == "needs_human"
    assert f.ai_verdict == "needs_human"


def test_empty_source_counts_as_unknown():
    f = _finding("vuln", "")
    assert consistency.apply_unknown_downgrade([f])
    assert f.ai_verdict == "needs_human"


def test_original_reason_is_preserved():
    f = _finding("vuln", "unknown")
    consistency.apply_unknown_downgrade([f])
    assert "original reason" in f.ai_reason
    assert f.ai_reason.startswith("[unknown-source downgrade]")


def test_known_sources_are_left_alone():
    for src in KNOWN_SOURCES:
        f = _finding("vuln", src)
        assert consistency.apply_unknown_downgrade([f]) == []
        assert f.ai_verdict == "vuln"


def test_other_verdicts_are_left_alone():
    for v in ("not_vuln", "needs_human", "error", ""):
        f = _finding(v, "unknown")
        assert consistency.apply_unknown_downgrade([f]) == []
        assert f.ai_verdict == v


def test_case_and_whitespace_do_not_matter():
    for src in ("Unknown", " UNKNOWN ", "none", "n/a"):
        f = _finding("vuln", src)
        assert consistency.apply_unknown_downgrade([f]), src
        assert f.ai_verdict == "needs_human"


def test_running_twice_changes_nothing():
    f = _finding("vuln", "unknown")
    consistency.apply_unknown_downgrade([f])
    assert consistency.apply_unknown_downgrade([f]) == []
    assert f.ai_verdict == "needs_human"


def test_empty_input_is_fine():
    assert consistency.apply_unknown_downgrade([]) == []
    assert consistency.apply_unknown_downgrade(None) == []
