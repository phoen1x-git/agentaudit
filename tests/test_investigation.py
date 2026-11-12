"""Read-only evidence collection, stopping/resumption and honest relation labels."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.finding import Finding  # noqa: E402
from core.investigation import Investigator, StaleInvestigation  # noqa: E402
from core.source_index import SearchBudget, SourceIndex  # noqa: E402


def make_project(tmp_path):
    (tmp_path / "worker.py").write_text(
        'ALLOWED = {"items"}\n\ndef ensure_allowed(value):\n'
        '    if value not in ALLOWED:\n        raise ValueError("blocked")\n\n'
        'def run(value):\n    ensure_allowed(value)\n    return eval(value)\n', encoding="utf-8")
    (tmp_path / "api.py").write_text(
        'from worker import run as execute\n\ndef endpoint(request):\n'
        '    return execute(request.body)\n\nroutes = {"handler": execute}\n', encoding="utf-8")
    return Finding(project="sample", fingerprint="sample:one", src_root=str(tmp_path),
                   sink_uri="worker.py", sink_line=9, sink_func="eval", snippet="    return eval(value)", entry="run")


def test_finds_callers_bindings_validator_and_module_constants(tmp_path):
    fd = make_project(tmp_path)
    state = Investigator(tmp_path).collect(fd)
    assert state["status"] == "collected"
    callers = [r for r in state["items"] if r["kind"] == "caller"]
    assert any(r["call"]["bindings"] and r["call"]["bindings"][0]["expression"] == "request.body" for r in callers)
    assert any(r["kind"] == "callee" and "ensure_allowed" in r["target"] for r in state["items"])
    assert any(r["kind"] == "module_assignment" and r["names"] == ["ALLOWED"] for r in state["items"])
    assert any(r["kind"] == "function_reference" for r in state["items"])
    assert fd.ai_verdict == fd.verdict == ""
    json.dumps(state, allow_nan=False)


def test_collection_is_deterministic_and_complete_resume_is_idempotent(tmp_path):
    fd = make_project(tmp_path)
    investigator = Investigator(tmp_path)
    a = investigator.collect(fd)
    b = investigator.collect(fd)
    assert a == b
    assert investigator.collect(fd, a) == a


def test_item_budget_can_be_resumed_without_duplicates(tmp_path):
    fd = make_project(tmp_path)
    budget = SearchBudget(max_items=1)
    limited = Investigator(tmp_path, budget).collect(fd)
    assert limited["status"] == "bounded" and limited["stop_reason"] == "item_budget"
    assert len(limited["items"]) == 1 and limited["pending"]
    expanded = Investigator(tmp_path, replace(budget, max_items=48)).collect(fd, limited)
    assert expanded["status"] == "collected"
    assert len({r["id"] for r in expanded["items"]}) == len(expanded["items"])
    assert expanded["items"][0] == limited["items"][0]


@pytest.mark.parametrize("options,reason", [({"max_lines": 1}, "line_budget"),
                                          ({"max_context_bytes": 1}, "context_byte_budget"),
                                          ({"max_symbols": 1}, "symbol_budget")])
def test_collection_budgets_preserve_pending_work(tmp_path, options, reason):
    fd = make_project(tmp_path)
    state = Investigator(tmp_path, SearchBudget(**options)).collect(fd)
    assert state["status"] == "bounded" and state["stop_reason"] == reason
    assert state["pending"]


def test_source_or_candidate_changes_invalidate_resume(tmp_path):
    fd = make_project(tmp_path)
    state = Investigator(tmp_path).collect(fd)
    fd.entry = "different"
    with pytest.raises(StaleInvestigation):
        Investigator(tmp_path).collect(fd, state)
    fd.entry = "run"
    (tmp_path / "worker.py").write_text("def run(x):\n    return x\n", encoding="utf-8")
    with pytest.raises(StaleInvestigation):
        Investigator(tmp_path).collect(fd, state)


@pytest.mark.parametrize("option", ["max_depth", "max_symbols", "max_items", "max_lines", "max_context_bytes"])
def test_lower_resume_budget_cannot_relabel_oversized_saved_evidence(tmp_path, option):
    fd = make_project(tmp_path)
    investigator = Investigator(tmp_path)
    state = investigator.collect(fd)
    original = json.dumps(state, sort_keys=True)
    budget = replace(investigator.budget, **{option: 0 if option == "max_depth" else 1})
    with pytest.raises(StaleInvestigation, match="budgets decreased"):
        Investigator(tmp_path, budget).collect(fd, state)
    assert json.dumps(state, sort_keys=True) == original


def test_missing_caller_does_not_become_a_safety_judgment(tmp_path):
    (tmp_path / "app.py").write_text("def run(x):\n    return eval(x)\n", encoding="utf-8")
    fd = Finding(project="sample", src_root=str(tmp_path), sink_uri="app.py", sink_line=2)
    state = Investigator(tmp_path).collect(fd)
    assert state["status"] == "collected"
    assert any(r["kind"] == "no_caller_found" and "not proof" in r["meaning"] for r in state["limits"])
    assert fd.ai_verdict == ""


def test_untyped_method_candidates_have_no_invented_parameter_bindings(tmp_path):
    (tmp_path / "app.py").write_text("class Parser:\n    def run(self, value):\n        return eval(value)\n"
                                     "def endpoint(obj):\n    return obj.run(1)\n", encoding="utf-8")
    fd = Finding(project="sample", src_root=str(tmp_path), sink_uri="app.py", sink_line=3)
    state = Investigator(tmp_path).collect(fd)
    call, = [r for r in state["items"] if r["kind"] == "caller"]
    assert call["resolution"] == "name_only_candidate"
    assert call["call"]["bindings"] == [] and not call["call"]["binding_complete"]


def test_no_source_in_index_is_explicit(tmp_path):
    fd = make_project(tmp_path)
    fd.sink_uri = "missing.py"
    assert Investigator(tmp_path).collect(fd)["status"] == "no_source_context"


@pytest.mark.parametrize("focused", ["z/api.py", "z.py"])
def test_focused_partial_index_is_validated_in_the_same_order(tmp_path, focused):
    from core import judge_evidence as E

    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "other.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    path = tmp_path / focused
    path.parent.mkdir(exist_ok=True)
    path.write_text("def run(value):\n    return eval(value)\n", encoding="utf-8")
    fd = Finding(project="sample", src_root=str(tmp_path), sink_uri=focused,
                 sink_line=2, sink_func="eval", snippet="    return eval(value)", entry="run")
    budget = SearchBudget(max_files=2 if "/" in focused else 1)
    index = SourceIndex(tmp_path, budget, focus_files=[focused])
    assert focused in index.files and not index.complete
    fd.investigation = Investigator(tmp_path, budget, index).collect(fd)
    _, context = E.build(fd)
    assert context["investigation"]["valid"] is True
    assert context["investigation"]["index_complete"] is False
    assert any("索引覆盖不完整" in gap for gap in context["blocking_gaps"])
    assert any(row["file"] == focused and row["line"] == 2 for row in context["lines"])

    path.write_text("def run(value):\n    return value\n", encoding="utf-8")
    _, changed = E.build(fd)
    assert changed["investigation"]["valid"] is False
