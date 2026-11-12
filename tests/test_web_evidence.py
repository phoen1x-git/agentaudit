"""Ordinary Web/API context without importing a framework or inferring auth safety."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.finding import Finding  # noqa: E402
from core.investigation import Investigator  # noqa: E402
from core.source_index import SourceIndex, SearchBudget  # noqa: E402
from core import judge_evidence as E  # noqa: E402


def test_api_dependency_defaults_include_actual_implementation(tmp_path):
    (tmp_path / "security.py").write_text("def require_access(request):\n    if not request.user:\n        raise PermissionError()\n    return request.user\n", encoding="utf-8")
    (tmp_path / "api.py").write_text("from fastapi import Depends\nfrom security import require_access\n"
                                     "@app.post('/run')\ndef endpoint(body, user=Depends(require_access)):\n"
                                     "    return eval(body.expression)\n", encoding="utf-8")
    fd = Finding(project="web-sample", src_root=str(tmp_path), sink_uri="api.py", sink_line=5,
                 sink_func="eval", snippet="    return eval(body.expression)")
    fd.investigation = Investigator(tmp_path).collect(fd)
    deps = [r for r in fd.investigation["items"] if r["kind"] == "callable_dependency"]
    assert any("require_access" in r["target"] for r in deps)
    user, snapshot = E.build(fd)
    assert "raise PermissionError()" in user and "@app.post('/run')" in user
    assert {r["file"] for r in snapshot["lines"]} == {"api.py", "security.py"}
    assert fd.guards_real == fd.ai_verdict == fd.verdict == ""


def test_explicit_route_registration_is_reference_not_invocation(tmp_path):
    (tmp_path / "api.py").write_text("def endpoint(request):\n    return eval(request.body)\n"
                                     "app.add_api_route('/run', endpoint)\n", encoding="utf-8")
    fd = Finding(project="web-sample", src_root=str(tmp_path), sink_uri="api.py", sink_line=2)
    state = Investigator(tmp_path).collect(fd)
    refs = [r for r in state["items"] if r["kind"] == "function_reference"]
    assert refs and "not an invocation" in refs[0]["meaning"]
    assert any(r["kind"] == "no_caller_found" for r in state["limits"])


def test_parameter_shadowing_does_not_resolve_dependency_to_unrelated_function(tmp_path):
    (tmp_path / "api.py").write_text("def require_access():\n    return True\n"
                                     "def endpoint(require_access, body):\n    callback = require_access\n    return eval(body)\n", encoding="utf-8")
    fd = Finding(project="web-sample", src_root=str(tmp_path), sink_uri="api.py", sink_line=5)
    state = Investigator(tmp_path).collect(fd)
    assert not any(r["kind"] == "callable_dependency" for r in state["items"])


def test_source_index_prioritizes_sink_subtree_under_file_budget(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "other.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "z").mkdir()
    (tmp_path / "z" / "api.py").write_text("def endpoint(x):\n    return eval(x)\n", encoding="utf-8")
    ix = SourceIndex(tmp_path, SearchBudget(max_files=1), focus_files=["z/api.py"])
    assert "z/api.py" in ix.files and not ix.complete


def test_module_level_script_is_not_mistaken_for_missing_source(tmp_path):
    (tmp_path / "script.py").write_text("def read_value():\n    return input()\nvalue = read_value()\nresult = eval(value)\n",encoding="utf-8")
    fd=Finding(project="script-sample",src_root=str(tmp_path),sink_uri="script.py",sink_line=4,
               sink_func="eval",snippet="result = eval(value)")
    fd.investigation=Investigator(tmp_path).collect(fd)
    assert fd.investigation["status"]=="collected" and fd.investigation["seed_locations"]
    user,snapshot=E.build(fd)
    assert snapshot["investigation"]["valid"] and not snapshot["blocking_gaps"]
    assert "result = eval(value)" in user and fd.ai_verdict==""
