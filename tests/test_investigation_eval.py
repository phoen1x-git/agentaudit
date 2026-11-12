"""Frozen paired retrieval, honest model status and malformed case rejection."""
from pathlib import Path
import copy
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.eval_investigation import read_cases, evaluate
from core import llm_judge as LJ


def dataset():
    return read_cases(ROOT/'tests/fixtures/investigation/cases.json')


def test_paired_retrieval_compares_same_frozen_inputs_without_model(monkeypatch):
    monkeypatch.setattr(LJ,'judge',lambda *a,**k:pytest.fail('offline evaluation cannot call model'))
    result=evaluate(dataset())
    assert len(result['cases'])==10
    assert result['summary']['focused']['hits']==19
    assert not result['regressions']
    assert result['model_status']=='not_requested' and result['model_usage']['calls']==0
    assert result['independent_labeled_cases']==0 and result['vulnerability_accuracy']=='not_measured'
    for row in result['cases']:
        assert row['reference_label'] is None
        assert all(s['classification'] is None for s in row['strategies'].values())
        assert row['strategies']['focused']['source_snapshot']['investigation']['valid']
        assert row['strategies']['focused']['input_sha256']


def test_explicit_model_eval_records_missing_credentials_and_still_collects(monkeypatch,tmp_path):
    monkeypatch.setattr(LJ.LC,'KEY_FILE',str(tmp_path/'absent-key'))
    monkeypatch.setattr(LJ,'judge',lambda *a,**k:pytest.fail('missing credentials must not dispatch'))
    result=evaluate(dataset(),llm=True,split='reserved')
    assert result['model_status']=='not_run_missing_credentials'
    assert len(result['cases'])==4 and result['summary']['focused']['hits']==9
    assert result['model_usage']['calls']==0


@pytest.mark.parametrize('change',['hash','escape','anchor','duplicate'])
def test_invalid_cases_fail_before_materializing_sources(tmp_path,change):
    import json
    data=dataset()
    if change=='hash':
        data['cases'][0]['sources']['api.py']['sha256']='0'*64
    elif change=='escape':
        data['cases'][0]['sources']['../outside.py']=data['cases'][0]['sources'].pop('api.py')
    elif change=='anchor':
        data['cases'][0]['expected_material'][0]['quote']='invented line'
    else:
        data['cases'].append(copy.deepcopy(data['cases'][0]))
    path=tmp_path/'cases.json';path.write_text(json.dumps(data),encoding='utf-8')
    with pytest.raises(ValueError):
        read_cases(path)
