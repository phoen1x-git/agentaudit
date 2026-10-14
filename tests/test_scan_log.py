"""The scan log records statistics and nothing that identifies what was scanned.

This is the guard for a promise made to the user: the log exists so that "I scanned one
project" can become a number, and it must never become a list of what was scanned.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import scan_log  # noqa: E402


class _F:
    def __init__(self, rule, verdict=""):
        self.rule = rule
        self.ai_verdict = verdict


def _record(**kw):
    base = dict(mode="offline", n_files=7, elapsed_sec=1.2,
                findings=[_F("ast/dangerous-call"), _F("ast/unauth-endpoint", "vuln")])
    base.update(kw)
    return scan_log.build_record(**base)


def test_record_has_only_statistics():
    rec = _record()
    assert set(rec) <= scan_log.SHAREABLE_KEYS
    assert rec["n_candidates"] == 2
    assert rec["by_rule"] == {"ast/dangerous-call": 1, "ast/unauth-endpoint": 1}
    assert rec["by_verdict"] == {"untriaged": 1, "vuln": 1}


def test_record_carries_no_identifying_field():
    """A scan of a named project must not put the name anywhere in the record."""
    rec = _record()
    for key in ("project", "repo", "target", "targets", "path", "file", "filename", "snippet",
                "fingerprint", "src_root", "source_root", "host", "user"):
        assert key not in rec, f"a record has an identifying field: {key}"
    # Every string value is short and free of separators -- that is what makes it
    # non-identifying, and it is enforced on every write (see the append tests).
    for key, value in rec.items():
        if isinstance(value, str):
            assert "/" not in value and "\\" not in value, f"{key} looks like a path"
            assert len(value) <= scan_log.MAX_STRING


def test_the_audit_catches_a_planted_path():
    dirty = _record()
    dirty["n_files"] = "path/to/something/long/enough/to/look/like/a/real/file/path.py"
    problems = scan_log.audit_shareable(dirty, allowed=scan_log.SHAREABLE_KEYS)
    assert problems, "a path-shaped value was not caught"


def test_the_audit_catches_an_unexpected_key():
    dirty = _record()
    dirty["target_name"] = "something"
    problems = scan_log.audit_shareable(dirty, allowed=scan_log.SHAREABLE_KEYS)
    assert any("unexpected key" in p for p in problems)


def test_append_refuses_a_record_that_is_not_statistics_only(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_log, "log_path", lambda: tmp_path / "log.jsonl")
    dirty = _record()
    dirty["note"] = "/home/someone/secret-project/main.py"
    with pytest.raises(ValueError):
        scan_log.append(dirty)
    assert not (tmp_path / "log.jsonl").exists()


def test_append_then_read_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_log, "log_path", lambda: tmp_path / "log.jsonl")
    scan_log.append(_record())
    scan_log.append(_record(mode="full", elapsed_sec=3.0))
    rows = scan_log.read_all(tmp_path / "log.jsonl")
    assert len(rows) == 2
    assert {r["mode"] for r in rows} == {"offline", "full"}


def test_export_aggregates_and_passes_the_audit():
    rows = [_record(), _record(mode="full"), _record()]
    agg = scan_log.export(rows)
    assert agg["n_scans"] == 3
    assert agg["totals"]["candidates"] == 6
    assert agg["modes"] == {"full": 1, "offline": 2}
    problems = scan_log.audit_shareable(agg, allowed=scan_log.SHAREABLE_AGG_KEYS)
    assert not problems, problems


def test_export_of_nothing_is_still_valid():
    agg = scan_log.export([])
    assert agg["n_scans"] == 0
    assert not scan_log.audit_shareable(agg, allowed=scan_log.SHAREABLE_AGG_KEYS)


def test_logging_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("AGENTAUDIT_NO_LOG", "1")
    assert not scan_log.logging_enabled()
    monkeypatch.setenv("AGENTAUDIT_NO_LOG", "0")
    assert scan_log.logging_enabled()
