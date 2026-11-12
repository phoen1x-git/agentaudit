"""Evidence versions, persistence, strict transport and mocked judge integration."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import llm_judge as LJ, round as R, triage_contract as T  # noqa: E402
from core.finding import Finding  # noqa: E402


@pytest.fixture
def sample(tmp_path, monkeypatch):
    for key in ("AF_JUDGE_ARGCTX", "AF_JUDGE_CFGSRC", "AF_JUDGE_MT"):
        monkeypatch.delenv(key, raising=False)
    data = json.loads((ROOT / "tests/fixtures/triage/cases.json").read_text(encoding="utf-8"))
    case = data["cases"][0]
    (tmp_path / "sample.py").write_text(case["source"]["text"], encoding="utf-8")
    fd = Finding(project="sample", fingerprint="sample:one", rule="sample/check",
                 sink_uri="sample.py", sink_line=3, sink_col=4, sink_func="exec",
                 snippet="    return exec(value)", src_root=str(tmp_path), entry="handle",
                 guards=["sample.py#2:4"],
                 arg_sources=[{"i": 0, "kind": "param", "src_file": "sample.py", "src_line": 1,
                               "src_text": "request", "arg_text": "value"}])
    return fd, copy.deepcopy(case["response"])


def completion(raw, model="mock-model"):
    return {"choices": [{"message": {"content": raw}, "finish_reason": "stop"}],
            "model": model, "usage": {"prompt_tokens": 1, "completion_tokens": 1}}


def test_mocked_judge_keeps_exact_transport_and_provenance(sample, monkeypatch):
    fd, response = sample
    raw = json.dumps(response, ensure_ascii=False, indent=3)
    calls = []
    def chat(system, user, **kw):
        calls.append((system, user, kw))
        return completion(raw)
    monkeypatch.setattr(LJ.LC, "chat", chat)
    LJ.judge([fd], on_log=lambda _: None)
    assert fd.ai_verdict == "vuln" and fd.verdict == ""
    assert len(calls) == 1  # Schema checks must not buy extra model votes.
    audit = fd.judge_json["_audit"]
    assert audit["transport"]["raw_text"] == raw
    assert audit["transport"]["response_model"] == "mock-model"
    assert audit["input_sha256"] == T.digest({"system": calls[0][0], "user": calls[0][1]})
    assert audit["source_snapshot"]["files"][0]["sha256"] == hashlib.sha256(
        (Path(fd.src_root) / "sample.py").read_bytes()).hexdigest()
    assert fd.judge_json["_audit"]["raw_response"] == response


def test_schema_error_does_not_retry_or_keep_old_safe_label(sample, monkeypatch):
    fd, response = sample
    fd.ai_verdict = "not_vuln"
    response["confidence"] = "0.99"
    calls = []
    def chat(*a, **kw):
        calls.append(kw)
        return completion(json.dumps(response))
    monkeypatch.setattr(LJ.LC, "chat", chat)
    LJ.judge([fd], on_log=lambda _: None)
    assert fd.ai_verdict == "error" and len(calls) == 1
    assert fd.judge_json["_audit"]["raw_response"] == response
    assert fd.judge_json["_audit"]["transport"]["raw_text"] == json.dumps(response)


@pytest.mark.parametrize("raw", ['{"ai_verdict": "not_vuln"',
                                 '{"key": 1, "key": 2}', 'explanation {"ok":1}'])
def test_strict_parser_does_not_repair_or_trim_outputs(raw, monkeypatch):
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion(raw))
    with pytest.raises(LJ.LC.JSONResponseError) as err:
        LJ.LC.ask_json("system", "user", strict=True, return_meta=True)
    assert [x["raw_text"] for x in err.value.attempts] == [raw, raw]


def test_parser_raw_metadata_is_opt_in_for_legacy_callers(monkeypatch):
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion('```json\n{"ok": 1}\n```'))
    assert LJ.LC.ask_json("system", "user") == {"ok": 1}


@pytest.mark.parametrize("raw", ["null", "[]", '"not_vuln"', "false"])
def test_nonobject_json_is_a_schema_error_without_extra_calls(sample, monkeypatch, raw):
    fd, _ = sample
    calls = []
    def chat(*a, **kw):
        calls.append(kw)
        return completion(raw)
    monkeypatch.setattr(LJ.LC, "chat", chat)
    LJ.judge([fd], on_log=lambda _: None)
    assert fd.ai_verdict == "error" and len(calls) == 1


def test_invalid_json_retries_are_bounded_and_preserved(sample, monkeypatch):
    fd, _ = sample
    raw = '{"ai_verdict": "not_vuln"'
    calls = []
    def chat(*a, **kw):
        calls.append(kw)
        return completion(raw)
    monkeypatch.setattr(LJ.LC, "chat", chat)
    LJ.judge([fd], on_log=lambda _: None)
    assert fd.ai_verdict == "error" and len(calls) == 4
    audit = fd.judge_json["_audit"]
    assert len(audit["retry_error"]["attempts"]) == 2
    assert len(audit["transport_error"]["attempts"]) == 2
    assert all(x["raw_text"] == raw for x in audit["transport_error"]["attempts"])


def test_source_changes_invalidate_snapshot_even_with_same_cache(sample):
    fd, _ = sample
    cache = {}
    a, sa = LJ._build_user(fd, cache)
    path = Path(fd.src_root) / fd.sink_uri
    path.write_text(path.read_text(encoding="utf-8").replace("request.body", '"literal"'), encoding="utf-8")
    b, sb = LJ._build_user(fd, cache)
    assert a != b and sa["files"] != sb["files"]
    fd.arg_sources[0]["kind"] = "local"
    c, _ = LJ._build_user(fd, cache)
    assert b != c and "local 表示未追到来源" in c


def test_changes_outside_displayed_window_still_change_model_cache_key(sample, monkeypatch):
    fd, response = sample
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion(json.dumps(response)))
    first = LJ.judge_one(fd, {})
    path = Path(fd.src_root) / fd.sink_uri
    path.write_text(path.read_text(encoding="utf-8") + '\nSETTING = "changed"\n', encoding="utf-8")
    second = LJ.judge_one(fd, {})
    assert first.snapshot["lines"] == second.snapshot["lines"]
    assert first.audit["input_sha256"] != second.audit["input_sha256"]


def test_ambiguous_source_basename_is_not_resolved_by_guessing(sample):
    fd, _ = sample
    other = Path(fd.src_root) / "other"
    other.mkdir()
    (other / "sample.py").write_text("def unrelated(x):\n    return x\n", encoding="utf-8")
    _, evidence = LJ._build_user(fd, {})
    assert any("不唯一" in x for x in evidence["blocking_gaps"])
    assert not any(r["file"] == "other/sample.py" for r in evidence["lines"])


def test_explicit_relative_source_path_avoids_basename_guess(sample):
    fd, _ = sample
    folder = Path(fd.src_root) / "api"
    folder.mkdir()
    (folder / "origin.py").write_text("def source(request):\n    return request.body\n", encoding="utf-8")
    fd.arg_sources[0].update(src_file="api/origin.py", src_line=1)
    _, evidence = LJ._build_user(fd, {})
    assert "api/origin.py" in {r["file"] for r in evidence["lines"]}


def test_stale_scan_snippet_and_truncated_context_are_explicit(sample):
    fd, _ = sample
    fd.snippet = "outdated code"
    _, evidence = LJ._build_user(fd, {})
    assert any("重新扫描" in x for x in evidence["blocking_gaps"])
    fd.entry, fd.arg_sources, fd.guards = "", [], []
    text = "def handle(request):\n" + "    pass\n" * 150 + "    return exec(request.body)\n"
    (Path(fd.src_root) / fd.sink_uri).write_text(text, encoding="utf-8")
    fd.sink_line, fd.snippet = 152, "    return exec(request.body)"
    _, evidence = LJ._build_user(fd, {})
    assert len(evidence["lines"]) == 120
    assert 152 in {r["line"] for r in evidence["lines"]}
    assert any("局部窗口" in x for x in evidence["blocking_gaps"])


def test_source_is_read_never_imported(sample):
    fd, _ = sample
    path = Path(fd.src_root) / fd.sink_uri
    path.write_text('raise RuntimeError("must never execute")\n\ndef f():\n    exec("test")\n', encoding="utf-8")
    fd.sink_line, fd.snippet = 4, '    exec("test")'
    user, _ = LJ._build_user(fd, {})
    assert 'exec("test")' in user


def test_roundtrip_preserves_full_evidence_and_raw_answer(sample, tmp_path, monkeypatch):
    fd, response = sample
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion(json.dumps(response)))
    LJ.judge([fd], on_log=lambda _: None)
    fd.chain = "a -> " * 100
    fd.verdict = "rejected"
    R.write_findings(tmp_path / "findings.tsv", [fd])
    R.write_findings_json(tmp_path / "findings.json", [fd])
    R.write_verdicts(tmp_path / "verdicts.json", [fd])
    rebuilt, = R.read_findings_json(tmp_path / "findings.json")
    assert rebuilt.arg_sources == fd.arg_sources and rebuilt.guards == fd.guards
    assert rebuilt.snippet == fd.snippet and rebuilt.chain == fd.chain
    assert rebuilt.sink_col == fd.sink_col and rebuilt.verdict == "rejected"
    assert rebuilt.judge_json["_audit"]["raw_response"] == response
    assert rebuilt.judge_json["_audit"]["source_snapshot"] == fd.judge_json["_audit"]["source_snapshot"]


def test_majority_checks_each_vote_and_preserves_all_raw_votes(sample, monkeypatch):
    monkeypatch.setenv("AF_JUDGE_STRICT", "1")   # tests the evidence check, so it has to be on
    fd, response = sample
    raw_votes = [copy.deepcopy(response) for _ in range(3)]
    raw_votes[0].update(ai_verdict="not_vuln", arg_source="unknown", source_trust="unknown")
    responses = iter(raw_votes)
    tags = []
    def chat(*a, **kw):
        tags.append(kw["tag"])
        return completion(json.dumps(next(responses)))
    monkeypatch.setattr(LJ.LC, "chat", chat)
    LJ.judge([fd], votes=3, on_log=lambda _: None)
    assert fd.ai_verdict == "vuln" and len(set(tags)) == 3
    assert fd.judge_json["_votes"] == ["needs_human", "vuln", "vuln"]
    assert [r["_audit"]["raw_response"] for r in fd.judge_json["_vote_records"]] == raw_votes


def test_tie_uses_unresolved_and_invalid_vote_cannot_be_outvoted(sample, monkeypatch):
    fd, response = sample
    other = copy.deepcopy(response)
    other["ai_verdict"] = "needs_human"
    assert LJ._aggregate([response, other])["ai_verdict"] == "needs_human"
    bad = copy.deepcopy(response)
    bad["confidence"] = "bad"
    responses = iter([response, bad])
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion(json.dumps(next(responses))))
    LJ.judge([fd], votes=2, on_log=lambda _: None)
    assert fd.ai_verdict == "error"
    assert fd.judge_json["_audit"]["raw_response"] == bad
    assert len(fd.judge_json["_vote_records"]) == 1


def test_effective_prompt_switches_are_versioned(monkeypatch):
    monkeypatch.setenv("AF_JUDGE_SCOPE2", "0")
    a = LJ.policy_stamp()
    monkeypatch.setenv("AF_JUDGE_SCOPE2", "1")
    b = LJ.policy_stamp()
    assert a["rubric_sha256"] != b["rubric_sha256"]
    assert a["switches"]["AF_JUDGE_SCOPE2"] == "0"


def test_file_changed_since_scan_even_if_sink_line_is_unchanged(sample):
    fd, _ = sample
    path = Path(fd.src_root) / fd.sink_uri
    text = path.read_text(encoding="utf-8")
    fd.analysis_provenance = {"backend": "ast", "source_version_status": "read_at_scan",
                              "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    path.write_text(text + "\nchanged_setting = 1\n", encoding="utf-8")
    _, snapshot = LJ._build_user(fd, {})
    assert any("扫描后已修改" in g for g in snapshot["blocking_gaps"])


def test_legacy_codeql_version_gap_blocks_conclusions(sample, monkeypatch):
    monkeypatch.setenv("AF_JUDGE_STRICT", "1")   # only the evidence check may block a conclusion
    fd, response = sample
    fd.analysis_provenance = {"backend": "codeql", "source_version_status": "unverified"}
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion(json.dumps(response)))
    LJ.judge([fd], on_log=lambda _: None)
    assert fd.ai_verdict == "needs_human"
    assert any("重建数据库" in g for g in fd.judge_json["_audit"]["adjustments"])


def test_source_versions_cannot_be_mixed_by_majority_vote(sample, monkeypatch):
    fd, response = sample
    path = Path(fd.src_root) / fd.sink_uri
    calls = []
    def chat(*a, **kw):
        calls.append(kw)
        if len(calls) == 1:
            path.write_text(path.read_text(encoding="utf-8") + "\nSETTING = 1\n", encoding="utf-8")
        return completion(json.dumps(response))
    monkeypatch.setattr(LJ.LC, "chat", chat)
    LJ.judge([fd], votes=2, on_log=lambda _: None)
    assert fd.ai_verdict == "error" and len(fd.judge_json["_vote_records"]) == 2
    assert "aggregation aborted" in fd.ai_reason


def test_explain_shows_the_recorded_snapshot_after_source_changes(sample, monkeypatch):
    from app.explain import explain_one
    fd, response = sample
    monkeypatch.setattr(LJ.LC, "chat", lambda *a, **kw: completion(json.dumps(response)))
    LJ.judge([fd], on_log=lambda _: None)
    (Path(fd.src_root) / fd.sink_uri).write_text("different_current_source = 1\n", encoding="utf-8")
    text = explain_one(1, 1, fd.fingerprint, fd.to_row(), fd.src_root, fd.judge_json["_audit"])
    assert "saved triage snapshot" in text
    assert "value = request.body" in text and "different_current_source" not in text
