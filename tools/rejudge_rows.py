"""对指定的 (project, file尾段, line) 用 AF_JUDGE_MT=8000 单独复判（铁律）。

用法：
    python tools/rejudge_rows.py --rounds round-maybe,round-c-on \
        --rows "sample-toolkit-v2:sql_runner.py:63,sample-toolkit-v2:base.py:880,sampledelegate:app.py:120"
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.finding as F  # noqa: E402
from core import llm_judge as LJ  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTDIR = os.path.join(ROOT, "data", "target_pool")

sys.path.insert(0, os.path.join(ROOT, "tools"))
from target_map import _SRC_MAP  # noqa: E402


def _mk_finding(rec: dict) -> "F.Finding":
    fd = F.Finding(project=rec.get("project", ""))
    fd.fingerprint = rec.get("fingerprint", "")
    fd.rule = rec.get("rule", "")
    fd.sink_func = rec.get("sink", "")
    fd.sink_uri = rec.get("file", "")
    fd.sink_line = int(rec.get("line") or 0)
    fd.depth = int(rec.get("depth") or 0)
    fd.variants = int(rec.get("variants") or 1)
    fd.entry = rec.get("entry", "")
    fd.entries = rec.get("entries", "")
    fd.snippet = rec.get("snippet", "")
    fd.chain = rec.get("chain", "")
    fd.guards = list(rec.get("guards_list") or [])
    fd.arg_sources = rec.get("arg_sources") or []
    proj = (rec.get("project") or "").lower()
    root = _SRC_MAP.get(proj, "")
    if not root:
        import re as _re
        base = _re.split(r"[-_]\d", proj)[0]
        root = _SRC_MAP.get(base, "")
    fd.src_root = root
    return fd


def find_row(rounds: list[str], proj: str, basename: str, line: int):
    for tag in rounds:
        f = os.path.join(ROOT, "out", tag, "findings.json")
        if not os.path.exists(f):
            continue
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for fp, r in d.items():
            if (r.get("project") != proj):
                continue
            if not (r.get("file") or "").endswith(basename):
                continue
            if int(r.get("line") or 0) != line:
                continue
            r = dict(r)
            r["_round"] = tag
            return r
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", required=True)
    ap.add_argument("--rows", required=True, help="proj:basename:line, ...")
    ap.add_argument("--mt", default="8000")
    ap.add_argument("--tag", default="20261011")
    a = ap.parse_args()

    rounds = a.rounds.split(",")
    os.environ["AF_JUDGE_MT"] = str(a.mt)
    rows = [x.split(":") for x in a.rows.split(",")]
    results = []
    for proj, bn, ln in rows:
        rec = find_row(rounds, proj, bn, int(ln))
        if not rec:
            print(f"★ 找不到 {proj} {bn}:{ln}")
            continue
        fd = _mk_finding(rec)
        cache: dict = {}
        try:
            r = LJ.judge_one(fd, cache, tag=f"rejudge-mt-{a.tag}")
            LJ._apply(fd, r)
            verdict, conf, reason = fd.ai_verdict, fd.ai_confidence, fd.ai_reason
            note = "OK"
        except Exception as e:
            verdict, conf, reason = "error", 0.0, f"{type(e).__name__}: {e}"[:200]
            note = "FAILED"
        results.append({
            "project": proj, "file": rec.get("file"), "line": int(ln),
            "entry": rec.get("entry"), "orig_round": rec.get("_round"),
            "orig_verdict": rec.get("ai_verdict"), "orig_conf": rec.get("conf"),
            "new_verdict": verdict, "new_conf": conf,
            "new_arg_source": fd.arg_source, "new_by_design": fd.by_design,
            "new_scope_exceeds": fd.scope_exceeds, "new_guards_real": fd.guards_real,
            "new_reason": reason, "note": note,
        })
        print(f"\n{proj} {rec.get('file')}:{ln}  entry={rec.get('entry')}")
        print(f"  {rec.get('ai_verdict')}({rec.get('conf')})  →  {verdict} conf={conf:.2f}  [{note}]")
        print(f"  byd={fd.by_design} exc={fd.scope_exceeds} gr={fd.guards_real} asrc={fd.arg_source}")
        print(f"  理由: {reason}")

    os.makedirs(OUTDIR, exist_ok=True)
    out = os.path.join(OUTDIR, f"rejudge_mt_{a.tag}.json")
    json.dump({"_meta": {"mt": a.mt}, "results": results},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\nJSON: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
