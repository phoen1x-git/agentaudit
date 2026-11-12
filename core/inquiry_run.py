"""Bounded collect/check/judge cycles. Model gap text selects only fixed actions."""
from __future__ import annotations

import copy
from pathlib import Path

from . import judge_evidence as E
from .inquiry import build_questions, question_seed, topic_for, material_fingerprint
from .investigation import Investigator
from .investigation_run import atomic_json, triage_batch, question_only_eligible
from .source_index import SourceIndex
from .static_verification import verify
from .triage_contract import digest


def material_key(snapshot):
    return material_fingerprint(snapshot)


def refine_batch(findings, budget, request_budget, *, max_cycles=3, checkpoints=None, verify_enabled=False, on_log=print):
    if type(max_cycles) is not int or not 1 <= max_cycles <= 6:
        raise ValueError('max_cycles must be an integer from 1 to 6')
    indexes, records = {}, []
    for fd in findings:
        rounds=[]
        stop='cycle_budget'
        for cycle in range(1,max_cycles):
            if fd.investigation.get('strategy') != 'focused':
                stop='strategy_has_no_refinement';break
            seed=question_seed(fd)
            if fd.ai_verdict!='needs_human':
                stop='classification_or_error_recorded';break
            if request_budget.stopped:
                stop='model_budget';break
            if not seed or not any(topic_for(text) for text in seed):
                stop='no_supported_gap_action';break
            _,before=E.build(fd)
            if before['blocking_gaps'] and not question_only_eligible(fd,before):
                stop='blocking_source_gaps';break
            if seed==fd.investigation.get('question_seed'):
                stop='same_questions';break
            root=str(Path(fd.src_root).resolve())
            if root not in indexes:
                indexes[root]=SourceIndex(root,budget,focus_files=[f.sink_uri for f in findings if str(Path(f.src_root).resolve())==root])
            previous=copy.deepcopy(fd.investigation)
            state=Investigator(root,budget,indexes[root],strategy='focused').collect(fd)
            fd.investigation=state
            if verify_enabled:
                fd.verification=verify(fd)
            _,after=E.build(fd)
            # Question text changing is not new source material. Do not repeatedly
            # pay for a reformulation of an otherwise identical evidence set.
            if material_key(before)==material_key(after):
                fd.investigation=previous
                stop='no_new_material';break
            folder=Path(checkpoints)/digest(fd.fingerprint)/str(cycle) if checkpoints else None
            if folder:
                atomic_json(folder/'before.json',{'investigation':previous,'snapshot':before,'judgment':fd.judge_json})
                atomic_json(folder/'collected.json',{'investigation':state,'snapshot':after})
            summary=triage_batch([fd],request_budget=request_budget,checkpoints=folder,allow_incomplete=True,on_log=on_log)
            rounds.append({'cycle':cycle,'before_material_sha256':material_key(before),
                           'after_material_sha256':material_key(after),'triage':summary})
            if folder:
                atomic_json(folder/'result.json',{'investigation':fd.investigation,'judgment':fd.judge_json,'summary':summary})
            if summary['skipped']:
                stop='blocking_source_gaps';break
        fd.investigation['model_gaps_after_triage']=question_seed(fd)
        fd.investigation['inquiry']=build_questions(fd,fd.investigation)
        records.append({'fingerprint':fd.fingerprint,'additional_cycles':rounds,'stop_reason':stop})
    return {'records':records,'max_cycles':max_cycles,'request_budget':request_budget.summary(),
            'target_code_executed':False,'meaning':'checked model classifications and source material, not confirmed vulnerabilities'}
