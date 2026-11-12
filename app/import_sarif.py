"""Import external analyzer candidates for local source text into a new round."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import round as R, workspace  # noqa: E402
from core.investigation_run import atomic_json, triage_batch  # noqa: E402
from core.llm_budget import RequestBudget  # noqa: E402
from core.sarif_import import import_file  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="agentaudit import-sarif",
        description="import another analyzer's SARIF output as candidates")
    ap.add_argument("sarif", help="SARIF 2.1.0 output from an existing analyzer")
    ap.add_argument("--src", required=True, help="local source root corresponding to analyzer output")
    ap.add_argument("--project", default="", help="project name (default: source directory name)")
    ap.add_argument("--out", default=str(workspace()/"out"))
    ap.add_argument("--tag", default="", help="new output round name")
    ap.add_argument("--max-results", type=int, default=1000)
    ap.add_argument("--max-bytes", type=int, default=16*1024*1024)
    ap.add_argument("--llm", action="store_true", help="explicit optional model triage (API credits)")
    ap.add_argument("--max-model-calls", type=int, default=12)
    ap.add_argument("--max-model-cny", type=float, default=1.0)
    ap.add_argument("--max-model-tokens", type=int, default=12000)
    a = ap.parse_args(argv)
    try:
        source = Path(a.src).resolve()
        project = a.project or source.name
        tag = a.tag or project+"-import-"+datetime.now().strftime("%Y%m%d-%H%M%S")
        if not re.fullmatch(r"[\w.-]+",tag) or tag in {".",".."}:
            ap.error("--tag must be a single directory name")
        dest = Path(a.out).resolve()/("round-"+tag)
        if dest.exists():
            ap.error("output round already exists; choose a new tag")
        request_budget = RequestBudget(a.max_model_calls,a.max_model_cny,a.max_model_tokens)
        findings, summary = import_file(a.sarif,source,project,max_bytes=a.max_bytes,max_results=a.max_results)
        with Path(a.sarif).open("rb") as stream:
            input_bytes = stream.read(a.max_bytes+1)
        if len(input_bytes) > a.max_bytes or hashlib.sha256(input_bytes).hexdigest() != summary["input_sha256"]:
            raise ValueError("SARIF input changed during import")
        dest.mkdir(parents=True,exist_ok=False)
        meta = {"tag":tag,"generated_at":datetime.now().isoformat(timespec="seconds"),
                "scanner":"external-sarif-import","source_root":str(source),"project":project,
                "n_findings":len(findings),"import_summary":summary,"llm_calls":0,"llm_cache_hits":0,
                "llm_cost_cny":0.0,"llm_review":"not run","write_complete":False}
        atomic_json(dest/"meta.json",meta)
        (dest/"input.sarif").write_bytes(input_bytes)
        from core import judge_evidence as E
        for fd in findings:
            _, fd.backend_evidence = E.build(fd)
        if a.llm:
            triage = triage_batch(findings,request_budget=request_budget,checkpoints=dest/"judgments")
            meta.update({k:triage[k] for k in ("llm_calls","llm_cache_hits","llm_cost_cny")})
            meta.update(triage_summary=triage,llm_review="AI-assisted, not human-verified")
        for filename,writer in (("findings.tsv",R.write_findings),("findings.json",R.write_findings_json),
                                ("verdicts.json",R.write_verdicts)):
            temp=dest/(filename+".tmp")
            writer(temp,findings)
            temp.replace(dest/filename)
        atomic_json(dest/"import_summary.json",summary)
        meta["write_complete"]=True
        atomic_json(dest/"meta.json",meta)
        print(f"[out] {dest}; {len(findings)} candidates; {len(summary['issues'])} import issues; "
              f"{meta['llm_calls']} model responses")
        for issue in summary["issues"][:10]:
            print(f"[import] run {issue['run']} result {issue['result']}: {issue['reason']}")
        return 1 if summary["issues"] else 0
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,AttributeError,RecursionError) as exc:
        print(f"import-sarif: {exc}",file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
