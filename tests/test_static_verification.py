"""Limited probes report only observed syntax/order, never a vulnerability verdict."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import judge_evidence as E, round as R  # noqa: E402
from core.finding import Finding  # noqa: E402
from core.static_verification import verify  # noqa: E402


def candidate(tmp_path, text, line):
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    return Finding(project="sample", fingerprint="sample:one", src_root=str(tmp_path),
                   sink_uri="app.py", sink_line=line, sink_func="eval", snippet=text.splitlines()[line-1])


def test_boundary_guard_accepts_call_syntax_but_probe_is_not_executed(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    if value.startswith('[') and value.endswith(']'):\n        return eval(value)\n", 3)
    record = verify(fd)
    probe, = record["observations"]
    assert record["status"] == "observed" and not record["target_code_executed"]
    assert probe["kind"] == "boundary_guard_syntax_probe" and probe["probe"] == "[probe()]"
    assert probe["syntax_contains_call"] and "neither probe nor target executed" in probe["limitation"]
    assert fd.ai_verdict == fd.verdict == ""


def test_unmodeled_predicate_remains_explicit_and_no_full_path_claim(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    if value.startswith('[') and allowed(value):\n        return eval(value)\n", 3)
    record = verify(fd)
    assert record["observations"][0]["unmodeled_clauses"] == [{"line": 2, "expression": "allowed(value)"}]
    assert "full path not tested" in record["observations"][0]["limitation"]


def test_else_branch_is_not_treated_as_positive_guard(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    if value.startswith('['):\n        return None\n    else:\n        return eval(value)\n", 5)
    assert verify(fd)["observations"] == []


def test_type_check_after_eval_is_ordering_observation_only(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    result = eval(value)\n    if not isinstance(result, bool):\n        raise ValueError()\n", 2)
    record = verify(fd)
    obs, = record["observations"]
    assert obs["kind"] == "post_evaluation_type_check" and obs["check_line"] == 3
    assert "runtime binding not established" in obs["limitation"]


def test_type_check_of_result_is_not_a_pre_evaluation_guard(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    if isinstance(eval(value), list):\n        return True\n", 2)
    assert verify(fd)["observations"][0]["kind"] == "type_check_of_eval_result"


def test_earlier_or_other_block_checks_are_not_reported_as_following_eval(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    if not isinstance(value, str):\n        return None\n    result = eval(value)\n    return result\n", 4)
    assert verify(fd)["observations"] == []


def test_target_top_level_and_sink_string_are_never_executed(tmp_path):
    fd = candidate(tmp_path, "raise RuntimeError('must not execute')\ndef run(value):\n    return eval(value)\n", 3)
    assert verify(fd)["status"] == "inconclusive"


def test_finite_literal_rejection_gate_is_a_limited_observation(tmp_path):
    fd=candidate(tmp_path,'def run(value):\n    if value not in ("1","[probe()]"):\n        raise ValueError()\n    return eval(value)\n',4)
    record=verify(fd)
    obs,=record['observations']
    assert obs['kind']=='finite_literal_rejection_gate'
    assert obs['allowed_syntax'][1]['contains_call_syntax'] is True
    assert obs['allowed_syntax'][0]['literal_interpretation']=={'status':'interpreted','python_type':'int','value':1}
    assert obs['allowed_syntax'][1]['literal_interpretation']['status']=='unsupported'
    assert 'no safety conclusion' in obs['limitation']
    assert fd.ai_verdict==fd.verdict=='' and not record['target_code_executed']


@pytest.mark.parametrize('literal,python_type,value', [
    ('[1, -2, (3,)]', 'list', [1, -2, (3,)]),
    ('None', 'NoneType', None),
    ('1.5', 'float', 1.5),
])
def test_bounded_literal_interpreter_handles_only_small_literal_ast(literal,python_type,value):
    from core.static_verification import _literal_observation
    assert _literal_observation(literal)=={'status':'interpreted','python_type':python_type,'value':value}


@pytest.mark.parametrize('literal', [
    'call()', 'object.value', 'name', '[item for item in ()]', '10**10000',
])
def test_bounded_literal_interpreter_does_not_execute_or_expand_general_expressions(literal):
    from core.static_verification import _literal_observation
    assert _literal_observation(literal)['status']=='unsupported'


@pytest.mark.parametrize('middle',['    value=other\n','    del value\n'])
def test_finite_gate_does_not_cover_later_rebinding(tmp_path,middle):
    text='def run(value):\n    if value not in ("1","2"):\n        return None\n'+middle+'    return eval(value)\n'
    fd=candidate(tmp_path,text,len(text.splitlines()))
    assert not any(o['kind']=='finite_literal_rejection_gate' for o in verify(fd)['observations'])


def test_probe_evidence_roundtrip_and_stale_source_check(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    result = eval(value)\n    if isinstance(result, str):\n        return result\n", 2)
    fd.verification = verify(fd)
    R.write_findings_json(tmp_path / "findings.json", [fd])
    rebuilt, = R.read_findings_json(tmp_path / "findings.json")
    assert rebuilt.verification == fd.verification
    user, snapshot = E.build(rebuilt)
    assert snapshot["verification"]["valid"] and "post_evaluation_type_check" in user
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    _, snapshot = E.build(rebuilt)
    assert not snapshot["verification"]["valid"]
    assert any("静态验证" in gap for gap in snapshot["blocking_gaps"])


def test_changed_candidate_or_corrupt_record_does_not_enter_prompt(tmp_path):
    fd = candidate(tmp_path, "def run(value):\n    return eval(value)\n", 2)
    fd.verification = verify(fd)
    fd.verification["status"] = "observed"
    _, snapshot = E.build(fd)
    assert not snapshot["verification"]["valid"]


@pytest.mark.parametrize("file", ["../outside.py", "app.ts"])
def test_outside_root_or_other_language_is_not_probed(tmp_path, file):
    fd = Finding(project="sample", src_root=str(tmp_path), sink_uri=file, sink_line=1)
    assert verify(fd)["status"] in {"not_applicable", "error"}
