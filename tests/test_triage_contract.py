"""Output-policy boundaries, with fixed responses and no network access."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import llm_judge as LJ, triage_contract as T  # noqa: E402
from core.finding import Finding  # noqa: E402
from tools import eval_triage as EV  # noqa: E402

DATA = ROOT / "tests/fixtures/triage/cases.json"


@pytest.fixture
def response():
    return copy.deepcopy(EV.read_cases(DATA)["cases"][0]["response"])


@pytest.fixture
def snapshot():
    source = EV.read_cases(DATA)["cases"][0]["source"]
    return {"lines": [{"file": source["file"], "line": i, "text": text}
                      for i, text in enumerate(source["text"].splitlines(), 1)], "blocking_gaps": []}


@pytest.mark.parametrize("field,value", [
    ("ai_verdict", "不构成漏洞"), ("ai_verdict", "error"), ("ai_verdict", None),
    ("arg_source", "local"), ("source_trust", "probably"), ("by_design", True),
    ("guards_real", "YES"), ("sink_action", "sql"), ("scope_exceeds", "unknown"),
    ("confidence", float("nan")), ("confidence", float("inf")),
    ("confidence", float("-inf")), ("confidence", True), ("confidence", "0.9"),
    ("confidence", -0.1), ("confidence", 1.1), ("confidence", 10 ** 500),
    ("one_line", ""), ("missing_evidence", "none"), ("missing_evidence", [False]),
    ("evidence", []), ("_audit", {"effective": "not_vuln"}),
])
def test_invalid_outputs_are_errors_and_clear_stale_fields(response, field, value):
    response[field] = value
    fd = Finding(project="sample", ai_verdict="not_vuln", ai_confidence=0.99,
                 arg_source="constant", by_design="yes", scope_exceeds="no", guards_real="yes",
                 verdict="rejected")
    with pytest.raises(T.ContractError):
        LJ._apply(fd, response)
    assert fd.ai_verdict == "error" and fd.ai_confidence == 0
    assert fd.arg_source == fd.by_design == fd.guards_real == fd.scope_exceeds == ""
    assert fd.verdict == "rejected"  # Human data must survive a failed re-judgment.
    assert fd.judge_json["_audit"]["error"]["type"] == "ContractError"
    json.dumps(fd.judge_json, allow_nan=False)


@pytest.mark.parametrize("raw", [[], None, False, "not_vuln", 3])
def test_nonobjects_are_rejected(raw):
    with pytest.raises(T.ContractError):
        T.validate(raw)


@pytest.mark.parametrize("field", list(T.ENUMS) + list(T.TEXT_FIELDS) + ["confidence", "evidence", "missing_evidence"])
def test_missing_contract_fields_are_not_defaulted(response, field):
    del response[field]
    with pytest.raises(T.ContractError):
        T.validate(response)


@pytest.mark.parametrize("reference", [
    {"file": "sample.py", "line": True, "quote": "value = request.body"},
    {"file": "sample.py", "line": 0, "quote": "value = request.body"},
    {"file": "sample.py", "line": 2, "quote": ""},
    {"file": "sample.py", "line": 2},
])
def test_invalid_reference_structure(response, reference):
    response["evidence"]["source"] = [reference]
    with pytest.raises(T.ContractError):
        T.validate(response)


def test_quoted_line_must_be_in_the_displayed_snapshot(response, snapshot):
    response.update(ai_verdict="not_vuln", arg_source="constant", source_trust="trusted")
    response["evidence"]["source"][0]["quote"] = 'value = "safe"'
    out, reasons = T.apply_policy(response, snapshot)
    assert out["ai_verdict"] == "needs_human"
    assert reasons and response["ai_verdict"] == "not_vuln"


def test_partial_quote_does_not_count_as_a_whole_line(response, snapshot):
    response["evidence"]["source"][0]["quote"] = "request.body"
    assert T.apply_policy(response, snapshot)[0]["ai_verdict"] == "needs_human"


def test_unresolved_source_is_not_a_trusted_local(response, snapshot):
    response.update(ai_verdict="not_vuln", arg_source="unknown", source_trust="unknown")
    assert T.apply_policy(response, snapshot)[0]["ai_verdict"] == "needs_human"


def test_trusted_config_requires_a_controller_reference(response, snapshot):
    response.update(ai_verdict="not_vuln", arg_source="config", source_trust="trusted")
    assert T.apply_policy(response, snapshot)[0]["ai_verdict"] == "needs_human"
    response["evidence"]["trust"] = copy.deepcopy(response["evidence"]["source"])
    # This is a model assertion with a valid citation, not an independently proven trust boundary.
    assert T.apply_policy(response, snapshot)[0]["ai_verdict"] == "not_vuln"


def test_all_policy_adjustments_preserve_raw_response(response, snapshot, monkeypatch):
    # This case tests the downgrade the evidence check performs, so that arm has to be
    # switched on. `AF_JUDGE_STRICT` defaults to 0 (see `_apply` in core/llm_judge.py);
    # without it this would exercise a branch that is never reached.
    monkeypatch.setenv("AF_JUDGE_STRICT", "1")
    response.update(ai_verdict="not_vuln", arg_source="config", source_trust="unknown")
    original = copy.deepcopy(response)
    fd = Finding(project="sample")
    LJ._apply(fd, response, snapshot)
    assert fd.ai_verdict == "needs_human"
    assert response == original == fd.judge_json["_audit"]["raw_response"]
    assert fd.judge_json["ai_verdict"] == "not_vuln"
    assert fd.judge_json["_audit"]["effective"]["ai_verdict"] == "needs_human"


def test_missing_source_window_blocks_an_automatic_conclusion(response, snapshot):
    snapshot["blocking_gaps"] = ["source window omitted relevant lines"]
    assert T.apply_policy(response, snapshot)[0]["ai_verdict"] == "needs_human"


def test_policy_does_not_promote_a_model_uncertainty(response, snapshot):
    response["ai_verdict"] = "needs_human"
    out, _ = T.apply_policy(response, snapshot)
    assert out["ai_verdict"] == "needs_human"


def test_replay_dev_is_reproducible(monkeypatch):
    # The fixture expectations were recorded with the evidence check on; align explicitly.
    monkeypatch.setenv("AF_JUDGE_STRICT", "1")
    data = EV.read_cases(DATA)
    a = EV.replay(data)
    b = EV.replay(data)
    assert a == b
    assert a["expected_matches"] == a["n_cases"] == 14
    assert {c["split"] for c in a["cases"]} == {"dev"}


def test_replay_validates_fixture_content_hashes(tmp_path):
    data = EV.read_cases(DATA)
    data["cases"][0]["source"]["text"] += "# modified\n"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert EV.main(["--cases", str(path), "--out", str(tmp_path / "out")]) == 2


def test_replay_mismatch_returns_failure(tmp_path):
    data = EV.read_cases(DATA)
    data["cases"][0]["expected"] = "not_vuln"
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert EV.main(["--cases", str(path), "--out", str(tmp_path / "out")]) == 1
