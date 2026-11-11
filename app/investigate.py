"""Collect static source evidence into a derivative round, offline by default."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import round as R, workspace  # noqa: E402
from core.investigation import engine_stamp  # noqa: E402
from core.investigation_run import atomic_json, collect_batch, triage_batch  # noqa: E402
from core.llm_budget import RequestBudget  # noqa: E402
from core.source_index import SearchBudget  # noqa: E402
from core.triage_contract import digest  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="agentaudit investigate",
        description="collect bounded source evidence into a new round, offline")
    ap.add_argument("round_dir", help="existing round containing findings.json")
    ap.add_argument("--src", default="", help="override the source root (one project only)")
    ap.add_argument("--out", default=str(workspace() / "out"), help="output root")
    ap.add_argument("--tag", default="", help="new round name; required with --resume")
    ap.add_argument("--select", choices=["unresolved", "needs_human", "untriaged", "all"], default="unresolved")
    ap.add_argument("--fp", action="append", default=[], help="restrict to a fingerprint; repeatable")
    ap.add_argument("--resume", action="store_true", help="continue the same derivative round")
    ap.add_argument("--refresh", action="store_true", help="discard saved search queues and rebuild evidence")
    ap.add_argument("--strategy", choices=["focused", "broad"], default="focused", help="question/value-focused or original graph expansion")
    ap.add_argument("--max-cycles", type=int, default=3, help="at most 1-6 total judge/collection cycles; only with --llm")
    ap.add_argument("--llm", action="store_true", help="explicitly rerun model triage after collection (API credits)")
    ap.add_argument("--verify", action="store_true", help="run limited Python syntax/statement-order probes; no target execution")
    ap.add_argument("--max-model-calls", type=int, default=12, help="network attempts, including all retries")
    ap.add_argument("--max-model-cny", type=float, default=1.0, help="local estimated-cost bound; not provider billing")
    ap.add_argument("--max-model-tokens", type=int, default=12000, help="maximum requested output tokens per call")
    ap.add_argument("--max-findings", type=int, default=100, help="findings changed per invocation")
    ap.add_argument("--max-run-seconds", type=float, default=120, help="cooperative batch time bound")
    defaults = SearchBudget()
    for name, value in asdict(defaults).items():
        ap.add_argument("--" + name.replace("_", "-"), type=float if name == "max_seconds" else int,
                        default=value, help=f"source search budget (default: {value})")
    a = ap.parse_args(argv)
    parent = Path(a.round_dir).resolve()
    source = parent / "findings.json"
    try:
        findings = R.read_findings_json(source)
        parent_meta = json.loads((parent / "meta.json").read_text(encoding="utf-8")) if (parent / "meta.json").exists() else {}
        if a.src and len({fd.project for fd in findings}) > 1:
            ap.error("--src cannot override a multi-project round")
        for fd in findings:
            fd.src_root = a.src or fd.src_root or parent_meta.get("source_root", "")
        budget = SearchBudget(**{k: getattr(a, k) for k in asdict(defaults)})
        request_budget = RequestBudget(a.max_model_calls, a.max_model_cny, a.max_model_tokens)
        if a.resume and not a.tag:
            ap.error("--resume requires --tag")
        tag = a.tag or parent.name.removeprefix("round-") + "-investigate-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        if not re.fullmatch(r"[\w.-]+", tag) or tag in {".", ".."}:
            ap.error("--tag must be a single directory name")
        dest = Path(a.out).resolve() / ("round-" + tag)
        if dest == parent:
            ap.error("output must differ from the source round")
        parent_hash = digest({name: hashlib.sha256((parent / name).read_bytes()).hexdigest()
                              for name in ("findings.json", "verdicts.json", "meta.json", "findings.tsv")
                              if (parent / name).exists()})
        selection = {"select": a.select, "fingerprints": sorted(a.fp), "llm": a.llm, "verify": a.verify, "strategy": a.strategy}
        history = []
        if dest.exists():
            if not a.resume:
                ap.error("output round exists; choose a new --tag or use --resume")
            saved_meta = json.loads((dest / "meta.json").read_text(encoding="utf-8"))
            history = saved_meta.get("invocations", [])
            if (saved_meta.get("parent_round") != str(parent) or saved_meta.get("parent_sha256") != parent_hash
                    or saved_meta.get("investigation_selection") != selection):
                ap.error("source round or selection changed; create a new derivative round")
        elif a.resume:
            ap.error("cannot resume a missing output round")
        allowed = {"unresolved": {"", "needs_human", "error"}, "needs_human": {"needs_human"},
                   "untriaged": {""}}
        known = {fd.fingerprint for fd in findings}
        if set(a.fp) - known:
            ap.error("unknown fingerprint: " + ", ".join(sorted(set(a.fp) - known)))
        selected = [fd for fd in findings if (a.select == "all" or fd.ai_verdict in allowed[a.select])
                    and (not a.fp or fd.fingerprint in a.fp)]
        # Preserve edits to the human column when the parent TSV is the latest record.
        import csv
        for human_table in [parent / "findings.tsv"] + ([dest / "findings.tsv"] if a.resume else []):
            if human_table.exists():
                with human_table.open(encoding="utf-8-sig", newline="") as stream:
                    human = {r["fingerprint"]: r.get("verdict", "") for r in csv.DictReader(stream, delimiter="\t")}
                for fd in findings:
                    if fd.fingerprint in human:
                        fd.verdict = human[fd.fingerprint]
        # Validate batch bounds before creating any output.
        if not 1 <= a.max_cycles <= 6:
            ap.error("--max-cycles must be from 1 to 6")
        if a.max_findings <= 0 or not 0 < a.max_run_seconds < float("inf"):
            ap.error("batch budgets must be finite and positive")
        dest.mkdir(parents=True, exist_ok=True)
        meta = {"tag": tag, "generated_at": datetime.now().isoformat(timespec="seconds"),
                "parent_round": str(parent), "parent_sha256": parent_hash,
                "investigation_selection": selection, "source_root": a.src or parent_meta.get("source_root", ""),
                "scanner": parent_meta.get("scanner", "saved candidates"), "n_findings": len(findings),
                "investigation_engine_sha256": engine_stamp(), "investigation_budget": asdict(budget),
                "llm_calls": 0, "llm_cache_hits": 0, "llm_cost_cny": 0.0, "llm_review": "not run",
                "prior_triage": "retained from parent; not rerun with new evidence",
                "write_complete": False}
        atomic_json(dest / "meta.json", meta)
        summary = collect_batch(selected, budget, max_findings=a.max_findings,
                                max_run_seconds=a.max_run_seconds, checkpoints=dest / "investigations",
                                resume=a.resume, refresh=a.refresh, strategy=a.strategy)
        # Load untouched checkpointed candidates too, including those beyond this run's budget.
        for fd in selected:
            checkpoint = dest / "investigations" / (digest(fd.fingerprint) + ".json")
            if fd.fingerprint in summary["remaining"] and checkpoint.exists():
                fd.investigation = json.loads(checkpoint.read_text(encoding="utf-8"))["investigation"]
        if a.verify:
            from core.static_verification import verify
            for fd in selected:
                if fd.fingerprint not in summary["remaining"]:
                    fd.verification = verify(fd)
                    atomic_json(dest / "verifications" / (digest(fd.fingerprint) + ".json"), fd.verification)
        triage = None
        refinement = None
        model_unavailable = False
        if a.llm:
            from core import llm_judge as LJ
            model_unavailable = not Path(LJ.LC.KEY_FILE).is_file()
            if model_unavailable:
                meta['llm_unavailable_reason'] = 'configured model credential file is missing; collection completed without model requests'
                print('[triage] configured model credentials unavailable; retained prior labels; no model request')
        if a.llm and not model_unavailable:
            eligible = [fd for fd in selected if fd.fingerprint not in summary["remaining"]
                        and fd.fingerprint not in {r["fingerprint"] for r in summary["errors"]}]
            triage = triage_batch(eligible, request_budget=request_budget, checkpoints=dest / "judgments",
                                  resume=a.resume and not a.refresh, allow_incomplete=True)
            meta.update({k: triage[k] for k in ("llm_calls", "llm_cache_hits", "llm_cost_cny")})
            meta["llm_review"] = "AI-assisted, not human-verified"
            meta["triage_summary"] = triage
            from core.inquiry_run import refine_batch
            refinement = refine_batch(eligible, budget, request_budget, max_cycles=a.max_cycles,
                                      checkpoints=dest / 'cycles' / ('run-' + str(len(history)+1)),verify_enabled=a.verify)
            meta['refinement_summary'] = refinement
            for record in refinement['records']:
                for cycle in record['additional_cycles']:
                    for key in ('llm_calls','llm_cache_hits','llm_cost_cny'):
                        meta[key] += cycle['triage'][key]
            # Persist the final queue as the next invocation's checkpoint.
            from core.investigation import identity
            from core.investigation_run import AI_FIELDS
            from core.inquiry import material_fingerprint
            from core import judge_evidence as E
            skipped = {row['fingerprint'] for row in triage['skipped']} | set(triage['remaining'])
            for fd in eligible:
                atomic_json(dest / 'investigations' / (digest(fd.fingerprint)+'.json'),
                            {'identity':identity(fd),'investigation':fd.investigation})
                if fd.fingerprint not in skipped and fd.judge_json:
                    checkpoint = dest / 'judgments' / (digest(fd.fingerprint)+'.json')
                    saved = json.loads(checkpoint.read_text(encoding='utf-8')) if checkpoint.exists() else {}
                    snapshot = fd.judge_json.get('_audit',{}).get('source_snapshot')
                    if not snapshot:
                        _, snapshot = E.build(fd)
                    policy = LJ.policy_stamp()
                    atomic_json(checkpoint, {**saved,
                        'material_sha256':digest({'candidate':identity(fd),'material':material_fingerprint(snapshot),'policy':policy}),
                        'result':{name:getattr(fd,name) for name in AI_FIELDS}})
        for filename, writer in (("findings.tsv", R.write_findings), ("findings.json", R.write_findings_json),
                                 ("verdicts.json", R.write_verdicts)):
            temp = dest / (filename + ".tmp")
            writer(temp, findings)
            temp.replace(dest / filename)
        atomic_json(dest / "investigation_summary.json", summary)
        atomic_json(dest / "questions.json", {fd.fingerprint: fd.investigation.get("inquiry", {}) for fd in selected})
        meta.update(investigation_summary=summary, write_complete=True)
        meta["invocations"] = history + [{"at": meta["generated_at"], "collection": summary, "triage": triage,
                                            'refinement':refinement}]
        atomic_json(dest / "meta.json", meta)
        print(f"[out] {dest}; {summary['statuses']}; {len(summary['errors'])} errors; "
              f"{len(summary['remaining'])} not processed; {meta['llm_calls']} model responses")
        return 1 if summary["errors"] else 3 if model_unavailable else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"investigate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
