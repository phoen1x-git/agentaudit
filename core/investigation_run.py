"""Bounded batch orchestration and atomic evidence checkpoints, without model calls."""
from __future__ import annotations

import json
import math
from pathlib import Path
import time

from .investigation import Investigator, identity
from .source_index import SearchBudget, SourceIndex
from .triage_contract import digest
from .inquiry import material_fingerprint

AI_FIELDS = ("ai_verdict", "ai_confidence", "by_design", "scope_exceeds", "arg_source",
             "guards_real", "ai_reason", "judge_json")


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=1, allow_nan=False), encoding="utf-8")
    temp.replace(path)


def collect_batch(findings, budget=None, *, max_findings=100, max_run_seconds=120,
                  checkpoints=None, resume=False, refresh=False, strategy="focused", on_log=print):
    """Reuse one AST index per root; checkpoint each finding before moving on.

    Time is a cooperative bound, checked between indexing and collection steps.
    Each step also has its own smaller source-search budget.
    """
    if isinstance(max_findings, bool) or not isinstance(max_findings, int) or max_findings <= 0:
        raise ValueError("max_findings must be a positive integer")
    if not math.isfinite(max_run_seconds) or max_run_seconds <= 0:
        raise ValueError("max_run_seconds must be finite and positive")
    budget = budget or SearchBudget()
    groups = {}
    for fd in findings:
        root = str(Path(fd.src_root).resolve()) if fd.src_root else ""
        groups.setdefault(root, []).append(fd)
    started = time.monotonic()
    processed, unchanged, errors, remaining = 0, 0, [], []
    counts = {}
    stop = ""
    for root, group in groups.items():
        index = None
        for fd in group:
            if processed >= max_findings or time.monotonic() - started >= max_run_seconds:
                stop = "finding_budget" if processed >= max_findings else "run_time_budget"
                remaining.append(fd.fingerprint)
                continue
            checkpoint = Path(checkpoints) / (digest(fd.fingerprint) + ".json") if checkpoints else None
            try:
                previous = None
                if resume and not refresh:
                    if checkpoint and checkpoint.exists():
                        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
                        if saved["identity"] != identity(fd):
                            raise ValueError("checkpoint candidate changed; use --refresh")
                        previous = saved["investigation"]
                    elif fd.investigation:
                        previous = fd.investigation
                if not root:
                    raise ValueError("source root is missing; supply --src")
                if index is None:
                    index = SourceIndex(root, budget, focus_files=[f.sink_uri for f in group])
                investigator = Investigator(root, budget, index, strategy=strategy)
                state = investigator.collect(fd, previous)
                fd.investigation = state
                if checkpoint:
                    atomic_json(checkpoint, {"identity": identity(fd), "investigation": state})
                counts[state["status"]] = counts.get(state["status"], 0) + 1
                if previous == state:
                    unchanged += 1
                else:
                    processed += 1
                on_log(f"[investigate] {fd.fingerprint}: {state['status']}; "
                       f"{state['usage']['items']} items, {state['usage']['lines']} lines, "
                       f"{len(state['pending'])} pending ({state['stop_reason'] or 'queue exhausted'})")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                errors.append({"fingerprint": fd.fingerprint, "error": str(exc)})
                if not fd.investigation:
                    fd.investigation = {"status": "error", "error": str(exc)}
                processed += 1
                on_log(f"[investigate] ERROR {fd.fingerprint}: {exc}")
    return {"selected": len(findings), "processed": processed, "unchanged": unchanged,
            "statuses": counts, "errors": errors, "remaining": remaining, "stop_reason": stop,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "max_findings": max_findings, "max_run_seconds": max_run_seconds,
            "model_calls": 0, "target_code_executed": False}


def question_only_eligible(fd, snapshot):
    if fd.analysis_provenance.get('source_version_status') in {'unverified', 'mismatch'}:
        return False
    if snapshot.get('investigation', {}).get('valid') is False or snapshot.get('verification', {}).get('valid') is False:
        return False
    if snapshot.get('diagnostics'):
        return False
    # Fail closed for new gap kinds. Only documented coverage limits are suitable
    # for a question-producing request; stale or unknown input defects are not.
    coverage = ('仅提供局部窗口', '主动补证包含截断', '主动补证的源码索引覆盖不完整',
                '主动补证达到预算或邻接数量限制', '后端关联位置超过',
                '后端源码上下文超过', '后端源码上下文达到')
    return all(any(word in gap for word in coverage) for gap in snapshot['blocking_gaps'])


def triage_batch(findings, *, request_budget, checkpoints=None, resume=False, allow_incomplete=False, on_log=print):
    """Explicit model pass over saved evidence; never run for an offline request."""
    from . import judge_evidence as E, llm_judge as LJ
    policy = LJ.policy_stamp()
    skipped, reused, judged, remaining = [], 0, 0, []
    before = (LJ.LC.USAGE.calls, LJ.LC.USAGE.hit_cache, LJ.LC.USAGE.cny)
    with request_budget:
        for i, fd in enumerate(findings):
            _, snapshot = E.build(fd)
            if snapshot["blocking_gaps"] and not (allow_incomplete and question_only_eligible(fd, snapshot)):
                skipped.append({"fingerprint": fd.fingerprint, "gaps": snapshot["blocking_gaps"]})
                on_log(f"[triage] {fd.fingerprint}: unresolved source gaps; no model request")
                continue
            if snapshot['blocking_gaps']:
                on_log(f'[triage] {fd.fingerprint}: incomplete context; request questions, classification must remain unresolved')
            key = digest({"candidate": identity(fd), "snapshot": snapshot, "policy": policy})
            material = digest({'candidate':identity(fd),'material':material_fingerprint(snapshot),'policy':policy})
            checkpoint = Path(checkpoints) / (digest(fd.fingerprint) + ".json") if checkpoints else None
            previous = {name: getattr(fd, name) for name in AI_FIELDS}
            if resume and checkpoint and checkpoint.exists():
                record = json.loads(checkpoint.read_text(encoding="utf-8"))
                if (record.get("input_sha256") == key or record.get('material_sha256') == material) and record["result"]["ai_verdict"] != "error":
                    for name in AI_FIELDS:
                        setattr(fd, name, record["result"][name])
                    reused += 1
                    continue
            LJ.judge([fd], on_log=on_log)
            judged += 1
            if checkpoint:
                atomic_json(checkpoint, {"input_sha256": key, 'material_sha256':material, "prior": previous,
                                        "result": {name: getattr(fd, name) for name in AI_FIELDS}})
            if request_budget.stopped:
                remaining = [f.fingerprint for f in findings[i:]]
                break
    return {"judged": judged, "reused": reused, "skipped": skipped, "remaining": remaining,
            "llm_calls": LJ.LC.USAGE.calls - before[0],
            "llm_cache_hits": LJ.LC.USAGE.hit_cache - before[1],
            "llm_cost_cny": round(LJ.LC.USAGE.cny - before[2], 8),
            "budget": request_budget.summary()}
