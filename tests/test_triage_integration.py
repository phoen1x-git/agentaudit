"""Scan metadata and source-cache lifecycle, without CodeQL or paid model calls."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import scan, run_round  # noqa: E402
from core import llm_judge as LJ  # noqa: E402
from core.finding import Finding  # noqa: E402


@pytest.fixture
def database(tmp_path, monkeypatch):
    src, db = tmp_path / "src", tmp_path / "db"
    src.mkdir()
    (src / "sample.py").write_text("value = 1\n", encoding="utf-8")
    exe = tmp_path / "fake-codeql"
    exe.write_text("not executable", encoding="utf-8")
    monkeypatch.setattr(scan, "_codeql_exe", lambda: str(exe))
    calls = []
    def build(*args, **kwargs):
        calls.append(args)
        db.mkdir(exist_ok=True)
        (db / "codeql-database.yml").write_text("fixture", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(scan.subprocess, "run", build)
    return src, db, exe, calls


def test_database_reuses_only_matching_source_and_tool(database):
    src, db, exe, calls = database
    assert scan.build_db(src, db)
    assert scan.build_db(src, db) and len(calls) == 1
    source = src / "sample.py"
    source.write_text("value = 2\n", encoding="utf-8")
    assert scan.build_db(src, db) and len(calls) == 2
    new = src / "added.py"
    new.write_text("value = 3\n", encoding="utf-8")
    assert scan.build_db(src, db) and len(calls) == 3
    new.unlink()
    assert scan.build_db(src, db) and len(calls) == 4
    exe.write_text("different fake binary", encoding="utf-8")
    assert scan.build_db(src, db) and len(calls) == 5


def test_legacy_database_without_version_is_rebuilt(database):
    src, db, _, calls = database
    db.mkdir()
    (db / "codeql-database.yml").write_text("legacy", encoding="utf-8")
    assert scan.build_db(src, db) and len(calls) == 1
    assert (db / "agentaudit-source.json").exists()


def test_database_changed_while_building_has_no_reusable_stamp(database, monkeypatch):
    src, db, _, _ = database
    def build(*args, **kwargs):
        db.mkdir()
        (db / "codeql-database.yml").write_text("fixture", encoding="utf-8")
        (src / "sample.py").write_text("value = 10\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(scan.subprocess, "run", build)
    assert not scan.build_db(src, db)
    assert not (db / "agentaudit-source.json").exists()


def test_failed_rebuild_cannot_keep_old_valid_stamp(database, monkeypatch):
    src, db, _, _ = database
    assert scan.build_db(src, db)
    (src / "sample.py").write_text("changed = True\n", encoding="utf-8")
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="failed"))
    assert not scan.build_db(src, db)
    assert not (db / "agentaudit-source.json").exists()


def test_database_status_distinguishes_missing_matching_and_stale_versions(database):
    from core.source_version import database_status
    src, db, _, _ = database
    assert database_status(db, str(src))["source_version_status"] == "unverified"
    assert scan.build_db(src, db)
    assert database_status(db, str(src))["source_version_status"] == "matched"
    (src / "sample.py").write_text("changed = 1\n", encoding="utf-8")
    assert database_status(db, str(src))["source_version_status"] == "mismatch"
    (db / "agentaudit-source.json").write_text("not-json", encoding="utf-8")
    assert database_status(db, str(src))["source_version_status"] == "unverified"
    (db / "agentaudit-source.json").write_text('{"source": []}', encoding="utf-8")
    assert database_status(db, str(src))["source_version_status"] == "unverified"


def test_codeql_finalize_attaches_the_database_version(database, monkeypatch):
    from core import static_frontend as SF
    src, db, _, _ = database
    monkeypatch.setattr(SF, "_read_src_prefix", lambda _: str(src))
    def findings():
        return [Finding(project="sample", sink_uri="sample.py", sink_line=1, sink_func="exec")]
    unverified = SF.finalize(findings(), str(db), {}, on_log=lambda _: None)
    assert unverified[0].analysis_provenance["source_version_status"] == "unverified"
    assert scan.build_db(src, db)
    checked = SF.finalize(findings(), str(db), {}, on_log=lambda _: None)
    assert checked[0].analysis_provenance["source_version_status"] == "matched"
    assert checked[0].snippet == "value = 1"


def test_single_scan_records_only_this_run_usage(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    fd = Finding(project="sample", fingerprint="one", sink_uri="sample.py", sink_line=1)
    monkeypatch.setattr(scan.ast_scan, "scan_dir", lambda *a, **kw: [fd])
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    usage = LJ.LC.Usage()
    usage.calls, usage.hit_cache, usage.cny = 20, 4, 2.0
    monkeypatch.setattr(LJ.LC, "USAGE", usage)
    def judge(findings, **kw):
        usage.calls += 2
        usage.hit_cache += 3
        usage.cny += 0.125
        findings[0].ai_verdict = "needs_human"
    monkeypatch.setattr(LJ, "judge", judge)
    monkeypatch.setattr(sys, "argv", ["scan", "--path", str(source), "--tag", "unit",
                                    "--out", str(tmp_path), "--no-codeql", "--llm",
                                    "--no-sarif", "--no-log"])
    assert scan.main() == 0
    meta = json.loads((tmp_path / "round-unit/meta.json").read_text(encoding="utf-8"))
    assert (meta["llm_calls"], meta["llm_cache_hits"], meta["llm_cost_cny"]) == (2, 3, 0.125)
    assert meta["llm_review"] == "AI-assisted, not human-verified"
    assert meta["triage_policy"]["version"] == LJ.T.VERSION


def test_empty_scan_does_not_claim_that_triage_ran(tmp_path, monkeypatch):
    monkeypatch.setattr(scan.ast_scan, "scan_dir", lambda *a, **kw: [])
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    def forbidden(*a, **kw):
        pytest.fail("empty scan must not invoke the judge")
    monkeypatch.setattr(LJ, "judge", forbidden)
    monkeypatch.setattr(sys, "argv", ["scan", "--path", str(tmp_path), "--tag", "empty",
                                    "--out", str(tmp_path), "--no-codeql", "--llm", "--no-sarif", "--no-log"])
    assert scan.main() == 0
    meta = json.loads((tmp_path / "round-empty/meta.json").read_text(encoding="utf-8"))
    assert meta["llm_review"] == "not run" and meta["llm_calls"] == 0


def test_batch_usage_and_effective_prompt_stamp(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("fixture", encoding="utf-8")
    target_file = tmp_path / "targets.yml"
    target_file.write_text("targets:\n  sample:\n    db: " + db.as_posix() + "\n", encoding="utf-8")
    fd = Finding(project="sample", fingerprint="one")
    monkeypatch.setattr(run_round.SF, "run_db_to_findings", lambda *a, **k: [fd])
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
    usage = LJ.LC.Usage()
    usage.calls, usage.hit_cache, usage.cny = 20, 4, 2.0
    monkeypatch.setattr(LJ.LC, "USAGE", usage)
    def judge(findings, **kw):
        usage.calls += 1
        usage.hit_cache += 2
        usage.cny += 0.25
        findings[0].ai_verdict = "needs_human"
    monkeypatch.setattr(LJ, "judge", judge)
    monkeypatch.setattr(run_round, "TARGETS", copy.deepcopy(run_round.TARGETS))
    monkeypatch.setattr(sys, "argv", ["round", "--targets-file", str(target_file), "--tag", "batch",
                                    "--out", str(tmp_path), "--no-gate", "--no-duality",
                                    "--no-consistency", "--no-upstream", "--no-unknown-downgrade"])
    assert run_round.main() == 0
    meta = json.loads((tmp_path / "round-batch/meta.json").read_text(encoding="utf-8"))
    assert (meta["llm_calls"], meta["llm_cache_hits"], meta["llm_cost_cny"]) == (1, 2, 0.25)
    monkeypatch.setenv("AF_JUDGE_REPOCFG", "0")
    first = run_round._cfg_stamp()
    monkeypatch.setenv("AF_JUDGE_REPOCFG", "1")
    assert first["rubric"] != run_round._cfg_stamp()["rubric"]


def test_truncated_response_is_counted_and_raw_attempts_survive(tmp_path, monkeypatch):
    lc = LJ.LC
    monkeypatch.setattr(lc, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(lc, "LOG_PATH", str(tmp_path / "usage.jsonl"))
    monkeypatch.setattr(lc, "read_key", lambda: "dummy-test-value")
    monkeypatch.setattr(lc, "_RUN_CNY", 0)
    monkeypatch.setattr(lc, "_CONSEC_FAIL", 0)
    usage = lc.Usage()
    monkeypatch.setattr(lc, "USAGE", usage)
    replies = [
        {"choices": [{"finish_reason": "length", "message": {"content": "partial"}}],
         "usage": {"prompt_tokens": 10, "completion_tokens": 10}},
        {"choices": [{"finish_reason": "stop", "message": {"content": '{"ok":true}'}}],
         "usage": {"prompt_tokens": 10, "completion_tokens": 10}},
    ]
    def request(*a, **kw):
        return io.BytesIO(json.dumps(replies.pop(0)).encode("utf-8"))
    monkeypatch.setattr(lc.urllib.request, "urlopen", request)
    result = lc.chat("system", "user", max_tokens=100, retries=2)
    assert usage.calls == 2 and usage.out_tok == 20
    assert [r["raw_text"] for r in result["_attempts"]] == ["partial", '{"ok":true}']
    assert result["_request"]["max_tokens"] == 180
    assert len((tmp_path / "usage.jsonl").read_text(encoding="utf-8").splitlines()) == 2
    lc.chat("system", "user", max_tokens=100, retries=2)
    assert usage.calls == 2 and usage.hit_cache == 1
