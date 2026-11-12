"""Persisted investigations, current source checks and derivative-round CLI behavior."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import judge_evidence as E, round as R  # noqa: E402
from core.finding import Finding  # noqa: E402
from core.investigation import Investigator, validated_evidence  # noqa: E402
from core.investigation_run import collect_batch  # noqa: E402
from core.source_index import SearchBudget  # noqa: E402


@pytest.fixture
def sample(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "worker.py").write_text("def run(value):\n    return eval(value)\n", encoding="utf-8")
    (src / "api.py").write_text("from worker import run\ndef endpoint(request):\n    return run(request.body)\n", encoding="utf-8")
    return Finding(project="sample", fingerprint="sample:one", src_root=str(src),
                   sink_uri="worker.py", sink_line=2, sink_func="eval", snippet="    return eval(value)")


def test_saved_evidence_is_used_with_exact_lines_and_file_versions(sample):
    sample.investigation = Investigator(sample.src_root).collect(sample)
    user, snapshot = E.build(sample)
    assert snapshot["investigation"]["valid"]
    assert {r["file"] for r in snapshot["lines"]} == {"api.py", "worker.py"}
    assert any(r["text"] == "    return run(request.body)" for r in snapshot["lines"])
    assert "import_binding" in user and '"parameter": "value"' in user
    assert "未找到调用方不证明不可达" in user


@pytest.mark.parametrize("change", ["modify", "add", "remove", "candidate", "engine"])
def test_stale_dependencies_are_rejected_before_triage(sample, change):
    sample.investigation = Investigator(sample.src_root).collect(sample)
    src = Path(sample.src_root)
    if change == "modify":
        (src / "api.py").write_text("pass\n", encoding="utf-8")
    elif change == "add":
        (src / "other.py").write_text("pass\n", encoding="utf-8")
    elif change == "remove":
        (src / "api.py").unlink()
    elif change == "candidate":
        sample.entry = "different"
    else:
        sample.investigation["engine_sha256"] = "old"
    user, snapshot = E.build(sample)
    assert not snapshot["investigation"]["valid"]
    assert any("过期" in g for g in snapshot["blocking_gaps"])
    assert "request.body" not in {r["text"] for r in snapshot["lines"]}


def test_corrupt_passage_is_not_accepted_as_source(sample):
    sample.investigation = Investigator(sample.src_root).collect(sample)
    passage = next(iter(sample.investigation["passages"].values()))
    passage["lines"][0]["text"] = "invented evidence"
    assert not validated_evidence(sample)[1]["valid"]


def test_budget_limits_and_index_coverage_are_visible_to_judge(sample):
    sample.investigation = Investigator(sample.src_root, SearchBudget(max_items=1)).collect(sample)
    _, snapshot = E.build(sample)
    assert snapshot["investigation"]["valid"]
    assert any("预算" in g for g in snapshot["blocking_gaps"])


def test_investigation_roundtrip_retains_queue_and_original_verdict(sample, tmp_path):
    sample.investigation = Investigator(sample.src_root, SearchBudget(max_items=1)).collect(sample)
    sample.ai_verdict = "needs_human"
    R.write_findings_json(tmp_path / "findings.json", [sample])
    rebuilt, = R.read_findings_json(tmp_path / "findings.json")
    assert rebuilt.investigation == sample.investigation
    assert rebuilt.ai_verdict == "needs_human" and rebuilt.verdict == ""


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "app/cli.py"), "investigate", *map(str, args)],
                          capture_output=True, text=True, cwd=ROOT)


def parent_round(sample, path):
    path.mkdir()
    R.write_findings_json(path / "findings.json", [sample])
    R.write_findings(path / "findings.tsv", [sample])
    return path


def test_cli_is_offline_preserves_parent_and_resumes(sample, tmp_path):
    parent = parent_round(sample, tmp_path / "parent")
    original = {p.name: p.read_bytes() for p in parent.iterdir()}
    out = tmp_path / "out"
    result = cli(parent, "--out", out, "--tag", "evidence", "--max-items", 1)
    assert result.returncode == 0, result.stdout + result.stderr
    dest = out / "round-evidence"
    first, = R.read_findings_json(dest / "findings.json")
    assert first.investigation["status"] == "bounded"
    result = cli(parent, "--out", out, "--tag", "evidence", "--resume")
    assert result.returncode == 0, result.stdout + result.stderr
    final, = R.read_findings_json(dest / "findings.json")
    assert final.investigation["status"] == "collected" and final.ai_verdict == ""
    meta = json.loads((dest / "meta.json").read_text(encoding="utf-8"))
    assert meta["write_complete"] and meta["llm_calls"] == 0
    assert meta["investigation_summary"]["target_code_executed"] is False
    assert {p.name: p.read_bytes() for p in parent.iterdir()} == original
    assert cli(parent, "--out", out, "--tag", "evidence").returncode == 2


def test_cli_changed_source_requires_refresh(sample, tmp_path):
    parent = parent_round(sample, tmp_path / "parent")
    out = tmp_path / "out"
    assert cli(parent, "--out", out, "--tag", "evidence").returncode == 0
    (Path(sample.src_root) / "api.py").write_text("pass\n", encoding="utf-8")
    failed = cli(parent, "--out", out, "--tag", "evidence", "--resume")
    assert failed.returncode == 1 and "changed" in failed.stdout
    refreshed = cli(parent, "--out", out, "--tag", "evidence", "--resume", "--refresh")
    assert refreshed.returncode == 0, refreshed.stdout + refreshed.stderr


def test_batch_budget_retains_remaining_and_complete_checkpoints_do_not_starve_queue(sample, tmp_path):
    second = replace(sample, fingerprint="sample:two")
    checkpoints = tmp_path / "checkpoints"
    a = collect_batch([sample, second], max_findings=1, checkpoints=checkpoints, on_log=lambda _: None)
    assert a["remaining"] == [second.fingerprint]
    b = collect_batch([sample, second], max_findings=1, checkpoints=checkpoints, resume=True, on_log=lambda _: None)
    assert b["remaining"] == [] and b["unchanged"] == 1
    assert second.investigation["status"] == "collected"


def test_engine_or_excerpt_changes_require_new_queue(sample):
    budget = SearchBudget(max_items=1)
    state = Investigator(sample.src_root, budget).collect(sample)
    with pytest.raises(ValueError):
        Investigator(sample.src_root, replace(budget, excerpt_lines=10)).collect(sample, state)


def test_resume_preserves_human_column_edits_in_derivative_round(sample, tmp_path):
    parent = parent_round(sample, tmp_path / "parent")
    out = tmp_path / "out"
    assert cli(parent, "--out", out, "--tag", "human").returncode == 0
    dest = out / "round-human"
    edited, = R.read_findings_json(dest / "findings.json")
    edited.verdict = "rejected"
    R.write_findings(dest / "findings.tsv", [edited])
    assert cli(parent, "--out", out, "--tag", "human", "--resume").returncode == 0
    rebuilt, = R.read_findings_json(dest / "findings.json")
    assert rebuilt.verdict == "rejected"


def test_model_checkpoints_reuse_only_matching_source_and_policy(sample, tmp_path, monkeypatch):
    from core import llm_judge as LJ
    from core.investigation_run import triage_batch
    from core.llm_budget import RequestBudget
    sample.investigation = Investigator(sample.src_root).collect(sample)
    calls = []
    def judge(findings, **kwargs):
        calls.append(findings[0].fingerprint)
        findings[0].ai_verdict = "needs_human"
        findings[0].judge_json = {"mock": True}
    monkeypatch.setattr(LJ, "judge", judge)
    checks = tmp_path / "judgments"
    result = triage_batch([sample], request_budget=RequestBudget(), checkpoints=checks, on_log=lambda _: None)
    assert result["judged"] == 1 and len(calls) == 1
    result = triage_batch([sample], request_budget=RequestBudget(), checkpoints=checks, resume=True, on_log=lambda _: None)
    assert result["reused"] == 1 and len(calls) == 1
    (Path(sample.src_root) / "api.py").write_text("pass\n", encoding="utf-8")
    result = triage_batch([sample], request_budget=RequestBudget(), checkpoints=checks, resume=True, on_log=lambda _: None)
    assert result["skipped"] and len(calls) == 1


def test_missing_model_credentials_preserve_labels_and_complete_offline_work(sample,tmp_path,monkeypatch):
    from app.investigate import main
    from core import llm_judge as LJ
    sample.ai_verdict='needs_human'
    parent=parent_round(sample,tmp_path/'parent')
    monkeypatch.setattr(LJ.LC,'KEY_FILE',str(tmp_path/'absent-key'))
    monkeypatch.setattr(LJ,'judge',lambda *a,**k:pytest.fail('missing credentials cannot dispatch'))
    result=main([str(parent),'--out',str(tmp_path/'out'),'--tag','questions','--llm','--verify'])
    assert result==3
    dest=tmp_path/'out/round-questions'
    meta=json.loads((dest/'meta.json').read_text(encoding='utf-8'))
    assert meta['write_complete'] and meta['llm_calls']==0 and meta['llm_review']=='not run'
    assert meta['llm_unavailable_reason']
    rebuilt,=R.read_findings_json(dest/'findings.json')
    assert rebuilt.ai_verdict=='needs_human' and rebuilt.verdict==''
    assert rebuilt.investigation['inquiry']['questions'] and (dest/'questions.json').is_file()


def test_model_resume_keeps_cycle_history_and_reuses_unchanged_material(sample,tmp_path,monkeypatch):
    from app.investigate import main
    from core import llm_judge as LJ
    parent=parent_round(sample,tmp_path/'parent')
    key=tmp_path/'mock-key'; key.write_text('unused-mock',encoding='utf-8')
    monkeypatch.setattr(LJ.LC,'KEY_FILE',str(key))
    calls=[]
    def judge(findings,**kwargs):
        calls.append(1)
        findings[0].ai_verdict='needs_human'
        findings[0].judge_json={'missing_evidence':['需要查找输入来源']}
    monkeypatch.setattr(LJ,'judge',judge)
    args=[str(parent),'--out',str(tmp_path/'out'),'--tag','reviewed','--llm']
    assert main(args)==0
    assert main(args+['--resume'])==0
    assert len(calls)==1
    meta=json.loads((tmp_path/'out/round-reviewed/meta.json').read_text(encoding='utf-8'))
    assert len(meta['invocations'])==2 and all(run['refinement'] for run in meta['invocations'])
    assert meta['triage_summary']['reused']==1
