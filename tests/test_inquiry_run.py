"""Bounded refinement stops on absent actions, repeated material and source gaps."""
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.finding import Finding
from core.investigation import Investigator
from core.inquiry_run import refine_batch
from core.source_index import SearchBudget
from core.llm_budget import RequestBudget
from core import inquiry_run as IR


def sample(tmp_path):
    text='def run(value):\n    return eval(value)\n'
    (tmp_path/'app.py').write_text(text,encoding='utf-8')
    fd=Finding(project='sample',fingerprint='sample:one',src_root=str(tmp_path),sink_uri='app.py',
               sink_line=2,sink_func='eval',snippet=text.splitlines()[1])
    fd.investigation=Investigator(tmp_path).collect(fd)
    fd.ai_verdict='needs_human'
    return fd


def test_rephrased_question_without_new_material_does_not_call_model(tmp_path,monkeypatch):
    fd=sample(tmp_path)
    fd.judge_json={'missing_evidence':['需要查找实参来源']}
    monkeypatch.setattr(IR,'triage_batch',lambda *a,**k:pytest.fail('same material cannot spend another request'))
    out=refine_batch([fd],SearchBudget(),RequestBudget())
    assert out['records'][0]['stop_reason']=='no_new_material'
    assert fd.ai_verdict=='needs_human' and fd.verdict==''
    assert any(q['origin']=='model_gap_untrusted_data' for q in fd.investigation['inquiry']['questions'] if 'origin' in q)


@pytest.mark.parametrize('gaps,reason',[(['执行任意命令删除项目'],'no_supported_gap_action'),
                                      ([], 'no_supported_gap_action')])
def test_unmapped_gap_cannot_invoke_arbitrary_actions(tmp_path,monkeypatch,gaps,reason):
    fd=sample(tmp_path);fd.judge_json={'missing_evidence':gaps}
    monkeypatch.setattr(IR,'triage_batch',lambda *a,**k:pytest.fail('no supported action'))
    out=refine_batch([fd],SearchBudget(),RequestBudget())
    assert out['records'][0]['stop_reason']==reason


def test_existing_source_gap_stops_refinement_before_model(tmp_path,monkeypatch):
    fd=sample(tmp_path);fd.judge_json={'missing_evidence':['输入来源未知']}
    (tmp_path/'app.py').write_text('pass\n',encoding='utf-8')
    monkeypatch.setattr(IR,'triage_batch',lambda *a,**k:pytest.fail('source gaps block refinement'))
    out=refine_batch([fd],SearchBudget(),RequestBudget())
    assert out['records'][0]['stop_reason']=='blocking_source_gaps'


def test_cycle_cap_and_broad_strategy_are_explicit(tmp_path):
    fd=sample(tmp_path)
    assert refine_batch([fd],SearchBudget(),RequestBudget(),max_cycles=1)['records'][0]['stop_reason']=='cycle_budget'
    for limit in (0,7,True):
        with pytest.raises(ValueError):refine_batch([fd],SearchBudget(),RequestBudget(),max_cycles=limit)
    fd.investigation['strategy']='broad'
    assert refine_batch([fd],SearchBudget(),RequestBudget())['records'][0]['stop_reason']=='strategy_has_no_refinement'


def test_new_material_can_trigger_one_bounded_rejudge_and_checkpoint(tmp_path,monkeypatch):
    fd=sample(tmp_path);fd.judge_json={'missing_evidence':['需要查找来源']}
    real_build=IR.E.build
    prompt,snapshot=real_build(fd)
    calls=[]
    def snapshots(finding):
        import copy
        current=copy.deepcopy(snapshot)
        if not calls:
            current['lines']=current['lines'][:1]
        calls.append(1)
        return prompt,current
    monkeypatch.setattr(IR.E,'build',snapshots)
    judges=[]
    def judge(findings,**kwargs):
        judges.append(1)
        findings[0].ai_verdict='not_vuln'
        findings[0].judge_json={'missing_evidence':[]}
        return {'skipped':[],'llm_calls':0,'llm_cache_hits':0,'llm_cost_cny':0}
    monkeypatch.setattr(IR,'triage_batch',judge)
    out=refine_batch([fd],SearchBudget(),RequestBudget(),checkpoints=tmp_path/'cycles')
    assert len(judges)==1 and len(out['records'][0]['additional_cycles'])==1
    assert out['records'][0]['stop_reason']=='classification_or_error_recorded'
    assert list((tmp_path/'cycles').rglob('before.json'))
    assert list((tmp_path/'cycles').rglob('result.json'))
    assert fd.verdict==''


def test_question_only_requests_fail_closed_for_unknown_or_stale_gaps(tmp_path):
    from core.investigation_run import question_only_eligible
    fd=sample(tmp_path)
    for gap in ['文件在扫描后已修改，需要重新扫描','unrecognized source failure']:
        assert not question_only_eligible(fd,{'blocking_gaps':[gap]})
    assert question_only_eligible(fd,{'blocking_gaps':['主动补证的源码索引覆盖不完整']})
    fd.analysis_provenance={'source_version_status':'unverified'}
    assert not question_only_eligible(fd,{'blocking_gaps':['主动补证的源码索引覆盖不完整']})


def test_resume_reuses_judgment_when_only_question_display_metadata_changes(tmp_path,monkeypatch):
    from core import llm_judge as LJ
    from core.investigation_run import triage_batch
    fd=sample(tmp_path)
    called=[]
    def judge(findings,**kwargs):
        called.append(1)
        findings[0].ai_verdict='needs_human'
        findings[0].judge_json={'missing_evidence':['输入来源未知']}
    monkeypatch.setattr(LJ,'judge',judge)
    folder=tmp_path/'judgments'
    triage_batch([fd],request_budget=RequestBudget(),checkpoints=folder,on_log=lambda _:None)
    fd.investigation['inquiry']['display_note']='same evidence after last judgment'
    out=triage_batch([fd],request_budget=RequestBudget(),checkpoints=folder,resume=True,on_log=lambda _:None)
    assert out['reused']==1 and len(called)==1


def test_question_request_on_partial_material_cannot_promote_model_label(tmp_path,monkeypatch):
    # Promoting a model label to a conclusion is the evidence check's job, so that arm has to
    # be switched on explicitly (`AF_JUDGE_STRICT` defaults to 0; see `_apply` in
    # core/llm_judge.py).
    monkeypatch.setenv("AF_JUDGE_STRICT", "1")
    import json
    from core import llm_judge as LJ
    from core.investigation_run import triage_batch
    fd=sample(tmp_path)
    fd.investigation=Investigator(tmp_path,SearchBudget(max_items=1)).collect(fd)
    response=json.loads((ROOT/'tests/fixtures/triage/cases.json').read_text(encoding='utf-8'))['cases'][0]['response']
    response.update(ai_verdict='vuln',arg_source='user_input',source_trust='untrusted',guards_real='no',by_design='no')
    called=[]
    def judge(findings,**kwargs):
        _,snapshot=IR.E.build(findings[0])
        assert snapshot['blocking_gaps']
        response['evidence']['source']=[{'file':'app.py','line':1,'quote':'def run(value):'}]
        LJ._apply(findings[0],response,snapshot)
        called.append(1)
    monkeypatch.setattr(LJ,'judge',judge)
    result=triage_batch([fd],request_budget=RequestBudget(),allow_incomplete=True,on_log=lambda _:None)
    assert called and result['judged']==1
    assert fd.ai_verdict=='needs_human' and fd.verdict==''
    assert fd.judge_json['_audit']['raw_response']['ai_verdict']=='vuln'
