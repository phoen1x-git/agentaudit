"""Paired source-retrieval evaluation; live classification is explicit and bounded."""
from __future__ import annotations

import argparse
import copy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import judge_evidence as E, llm_judge as LJ, workspace
from core.finding import Finding
from core.investigation import Investigator, engine_stamp
from core.investigation_run import atomic_json
from core.llm_budget import RequestBudget
from core.source_index import SearchBudget, SourceIndex
from core.triage_contract import digest


def read_cases(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('schema') != 'investigation-eval-v1' or not isinstance(data.get('cases'), list) or not 0 < len(data['cases']) <= 100:
        raise ValueError('invalid investigation case set')
    seen = set()
    for case in data['cases']:
        if case['id'] in seen:
            raise ValueError('duplicate case id')
        seen.add(case['id'])
        if case.get('reference_label') not in {None,'vuln','not_vuln','needs_human'}:
            raise ValueError('invalid reference label')
        basis=case.get('reference_basis') or {}
        if basis.get('independent_review') and not basis.get('evidence'):
            raise ValueError('declared independent labels need review evidence provenance')
        if not isinstance(case.get('origin'), str) or not case['origin']:
            raise ValueError('case origin is required')
        sources = case['sources']
        if not isinstance(sources, dict) or not 0 < len(sources) <= 24:
            raise ValueError('source count outside evaluation bound')
        for rel, source in sources.items():
            parts = PurePosixPath(rel)
            if parts.is_absolute() or '..' in parts.parts or chr(92) in rel or ':' in rel or not rel.endswith('.py'):
                raise ValueError('source paths must be contained Python paths')
            raw = source['text'].encode('utf-8')
            if len(raw) > 512*1024 or hashlib.sha256(raw).hexdigest() != source['sha256']:
                raise ValueError('case source hash mismatch')
        if sum(len(s['text'].encode('utf-8')) for s in sources.values()) > 1024*1024:
            raise ValueError('case source byte limit exceeded')
        for ref in case['expected_material']:
            lines = sources[ref['file']]['text'].splitlines()
            if type(ref['line']) is not int or not 1 <= ref['line'] <= len(lines) or lines[ref['line']-1] != ref['quote']:
                raise ValueError('expected material does not match frozen source')
        loc = case['finding']
        lines = sources[loc['file']]['text'].splitlines()
        if type(loc['line']) is not int or not 1 <= loc['line'] <= len(lines):
            raise ValueError('invalid finding location')
    return data


def evaluate(data, budget=None, *, llm=False, request_budget=None, split='all', on_case=None):
    budget = budget or SearchBudget()
    request_budget = request_budget or RequestBudget()
    credential = Path(LJ.LC.KEY_FILE).is_file() if llm else False
    model_status = 'enabled' if llm and credential else 'not_run_missing_credentials' if llm else 'not_requested'
    result = {'schema':'investigation-comparison-v1', 'dataset_sha256':digest(data),
              'engine_sha256':engine_stamp(), 'policy':LJ.policy_stamp(), 'budget':asdict(budget),
              'scope':'paired retrieval on frozen source; no target execution; labels require independent review',
              'model_status':model_status, 'cases':[], 'target_code_executed':False}
    selected = [c for c in data['cases'] if split=='all' or c.get('split')==split]
    if not selected:
        raise ValueError('selected split is empty')
    before = (LJ.LC.USAGE.calls,LJ.LC.USAGE.hit_cache,LJ.LC.USAGE.cny)
    with tempfile.TemporaryDirectory(prefix='audit-paired-') as temp, request_budget:
        for number,case in enumerate(selected):
            root = Path(temp)/str(number)
            root.mkdir()
            for rel,source in case['sources'].items():
                path=root/rel; path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(source['text'].encode('utf-8'))
            loc=case['finding']
            base=Finding(project='paired-sample',fingerprint=case['id'],src_root=str(root),sink_uri=loc['file'],
                         sink_line=loc['line'],sink_func=loc.get('sink','eval'),
                         snippet=case['sources'][loc['file']]['text'].splitlines()[loc['line']-1])
            index=SourceIndex(root,budget,focus_files=[base.sink_uri])
            row={'id':case['id'],'split':case.get('split','dev'),'origin':case['origin'],
                 'reference_label':case.get('reference_label'), 'reference_basis':case.get('reference_basis'),
                 'expected_count':len(case['expected_material']),'strategies':{}}
            expected={(r['file'],r['line'],r['quote']) for r in case['expected_material']}
            for strategy in ('initial','broad','focused'):
                fd=copy.deepcopy(base); started=time.monotonic()
                if strategy!='initial':
                    fd.investigation=Investigator(root,budget,index,strategy=strategy).collect(fd)
                prompt,snapshot=E.build(fd)
                shown={(r['file'],r['line'],r['text']) for r in snapshot['lines']}
                stats={'hits':len(shown & expected),'missing':[dict(file=f,line=n,quote=t) for f,n,t in sorted(expected-shown)],
                       'blocking_gaps':snapshot['blocking_gaps'],'source_lines':len(shown),
                       'collection_seconds':round(time.monotonic()-started,4),
                       'evidence_valid':snapshot.get('investigation',{}).get('valid'),
                       'usage':fd.investigation.get('usage',{}),'questions':fd.investigation.get('inquiry',{}),
                       'classification':None,'model_status':model_status,
                       'input_sha256':digest({'system':LJ.rubric_text(),'user':prompt,'snapshot':snapshot}),
                       'user_prompt':prompt,'source_snapshot':snapshot}
                if model_status=='enabled' and not request_budget.stopped:
                    LJ.judge([fd],on_log=lambda _:None,tag='paired-'+case['id']+'-'+strategy)
                    stats.update(classification=fd.ai_verdict,judge=fd.judge_json,model_status='attempted')
                elif request_budget.stopped:
                    stats['model_status']='not_run_budget_exhausted'
                row['strategies'][strategy]=stats
            result['cases'].append(row)
            if on_case: on_case(result)
    result['model_usage']={'calls':LJ.LC.USAGE.calls-before[0], 'cache_hits':LJ.LC.USAGE.hit_cache-before[1],
                           'estimated_cny':LJ.LC.USAGE.cny-before[2], 'request_budget':request_budget.summary()}
    result['summary']={s:{'hits':sum(r['strategies'][s]['hits'] for r in result['cases']),
                          'expected':sum(r['expected_count'] for r in result['cases']),
                          'classification_distribution':{label:sum(r['strategies'][s]['classification']==label for r in result['cases'])
                                                         for label in ('vuln','not_vuln','needs_human','error')}}
                       for s in ('initial','broad','focused')}
    result['regressions']=[r['id'] for r in result['cases'] if r['strategies']['focused']['hits']<r['strategies']['broad']['hits']]
    result['manual_review_reduction']='not_measured'
    result['independent_labeled_cases']=sum(bool((r.get('reference_basis') or {}).get('independent_review')) for r in result['cases'])
    result['vulnerability_accuracy']='not_measured'
    labeled=[r for r in result['cases'] if (r.get('reference_basis') or {}).get('independent_review')
             and r.get('reference_label') in {'vuln','not_vuln'}]
    result['declared_reference_metrics']={}
    for strategy in ('initial','broad','focused'):
        observed=[r for r in labeled if r['strategies'][strategy]['classification'] is not None]
        result['declared_reference_metrics'][strategy]={'reference_count':len(labeled),'classified_count':len(observed),
            'false_exclusion':sum(r['reference_label']=='vuln' and r['strategies'][strategy]['classification']=='not_vuln' for r in observed),
            'false_alarm':sum(r['reference_label']=='not_vuln' and r['strategies'][strategy]['classification']=='vuln' for r in observed),
            'unresolved':sum(r['strategies'][strategy]['classification']=='needs_human' for r in observed),
            'errors':sum(r['strategies'][strategy]['classification']=='error' for r in observed),
            'meaning':'counts against dataset-declared reviewed labels; label provenance is not independently authenticated by this tool'}
    return result


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cases',type=Path,default=ROOT/'tests/fixtures/investigation/cases.json')
    ap.add_argument('--out',type=Path,default=workspace()/'out/investigation-eval')
    ap.add_argument('--split',choices=['dev','reserved','all'],default='all')
    ap.add_argument('--llm',action='store_true',help='explicit optional paid paired model requests')
    ap.add_argument('--max-model-calls',type=int,default=12)
    ap.add_argument('--max-model-cny',type=float,default=1.0)
    a=ap.parse_args(argv)
    try:
        data=read_cases(a.cases)
        dest=a.out.resolve()/('comparison-'+a.split+'.json')
        result=evaluate(data,llm=a.llm,split=a.split,request_budget=RequestBudget(a.max_model_calls,a.max_model_cny),
                        on_case=lambda value:atomic_json(dest,value))
        atomic_json(dest,result)
        print('[paired]',json.dumps(result['summary'],ensure_ascii=False))
        print('[paired] model:',result['model_status'],'; regressions:',result['regressions'])
        print('[paired]',dest)
        if a.llm and result['model_status']=='not_run_missing_credentials':
            return 3
        return 1 if result['regressions'] else 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print('[paired]',exc,file=sys.stderr);return 2


if __name__=='__main__':
    raise SystemExit(main())
