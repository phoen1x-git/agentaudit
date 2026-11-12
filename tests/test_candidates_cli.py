"""The contract file, and the rule that makes it worth having.

`candidates.jsonl` is the only thing another tool consumes, so it has three properties that
have to hold together: one line per candidate, stable ids, and no verdict anywhere in it.
The last one is the layering rule: a candidate is a place that deserves a look, a verdict is
what someone concluded about it. Mixing them makes the file un-consumable, because the
consumer can no longer tell which fields it may trust.

These tests run the command the way a user does (`agentaudit candidates`), not by importing
the module, because the failure this guards against is "the feature exists but nobody can
reach it".
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ast_scan  # noqa: E402

VERDICT_KEYS = {"verdict", "vuln", "ai_verdict", "by_design", "scope_exceeds", "guards_real"}


@pytest.fixture(scope="module")
def round_dir(tmp_path_factory):
    findings = ast_scan.scan_dir(ROOT / "demo", "demo-agent")
    out = tmp_path_factory.mktemp("out")
    return ast_scan.write_round(out, "unit", findings,
                                meta_extra={"scanner": "ast-only",
                                            "source_root": str(ROOT / "demo")})


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "app.cli", *args],
                          capture_output=True, text=True, cwd=str(ROOT))


def _export(round_dir: Path, out: Path) -> subprocess.CompletedProcess:
    return _cli("candidates", "--round", str(round_dir), "--repo", "owner/name",
                "--src-root", str(ROOT / "demo"), "--out", str(out))


def test_the_command_is_listed_where_a_reader_looks():
    p = _cli("--help")
    assert p.returncode == 0, p.stderr
    assert "candidates" in p.stdout


def test_it_writes_a_contract_file(round_dir, tmp_path):
    out = tmp_path / "candidates.jsonl"
    p = _export(round_dir, out)
    assert p.returncode == 0, p.stdout + p.stderr
    assert out.exists()

    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows, "the export produced no rows for a round that has candidates"
    for row in rows:
        assert row["schema"] == "candidates/v1"
        assert row["repo"] == "owner/name"
        assert row["file"], "a candidate without a file cannot be re-checked later"
        assert row["sink"]["func"], "the sink name is part of the id"
        assert row["line"] >= 1


def test_no_verdict_was_smuggled_in(round_dir, tmp_path):
    """A candidate says where to look. What was concluded lives in a different file."""
    out = tmp_path / "candidates.jsonl"
    assert _export(round_dir, out).returncode == 0
    for line in out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        leaked = VERDICT_KEYS & set(json.loads(line))
        assert not leaked, f"the contract file carries a judgement: {leaked}"


def test_duplicate_positions_collapse_to_one_line(round_dir, tmp_path):
    """Three rules on the same `eval` are one place to look, not three."""
    out = tmp_path / "candidates.jsonl"
    p = _export(round_dir, out)
    assert p.returncode == 0, p.stderr
    ids = [json.loads(line)["candidate_id"]
           for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(ids) == len(set(ids)), "the same candidate was written twice"


def test_the_validator_accepts_what_the_exporter_writes(round_dir, tmp_path):
    """Exporter and validator disagreeing is worse than either one being wrong."""
    out = tmp_path / "candidates.jsonl"
    assert _export(round_dir, out).returncode == 0
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "check_contract_file.py"), str(out)],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert p.returncode == 0, p.stdout + p.stderr
