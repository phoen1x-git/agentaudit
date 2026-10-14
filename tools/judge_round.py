"""对「已经跑过静态前端、但从未跑判定层」的轮次补判定（零 CodeQL 成本）。

背景：
  有些轮次是用**非显眼形态的开关**跑出来的（`AF_SINKS_PATH` 路径构造 /
  `AF_DUALITY_SDK` SDK 构造 / `AF_SINKS_HTTP` / `AF_SINKS_FS`），
  但当时**没跑判定层**（`ai_verdict` 全空）→ **2141 条候选从未被判定过**。
  ★ 这批是"换形态挖新洞"最便宜的入口：**不需要重跑 CodeQL**，只要补 LLM 判定。

用法：
    python tools/judge_round.py --round round-pathnose_nofs --limit 30
    python tools/judge_round.py --round round-pathnose_nofs --only-projects openbiliclaw,trustgraph
    python tools/judge_round.py --round round-pathnose_nofs --tag mytag
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import core.finding as F  # noqa: E402
from core import llm_judge as LJ  # noqa: E402
from target_map import _SRC_MAP  # noqa: E402

OUTDIR = os.path.join(ROOT, "data", "target_pool")


def _src_root_of(proj: str) -> str:
    import re as _re
    p = (proj or "").lower()
    if p in _SRC_MAP:
        return _SRC_MAP[p]
    base = _re.split(r"[-_]\d", p)[0]
    return _SRC_MAP.get(base, "")


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
    fd.src_root = _src_root_of(rec.get("project", ""))
    return fd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only-projects", default="")
    ap.add_argument("--only-sinks", default="", help="按 sink 名过滤，逗号分隔，如 Attribute.join")
    ap.add_argument("--mt", default="8000")
    ap.add_argument("--tag", default="judged")
    a = ap.parse_args()

    f = os.path.join(ROOT, "out", a.round, "findings.json")
    if not os.path.exists(f):
        print("找不到", f)
        return 2
    d = json.load(open(f, encoding="utf-8"))
    items = list(d.items())
    # 只挑未判定的
    items = [(k, v) for k, v in items if not (v.get("ai_verdict") or "").strip()]
    # ★ 跳过本工具**已经判过**的（读 OUTDIR 里同轮的 judge_*.json），避免重复烧 LLM
    done_fps: set = set()
    for jf in glob.glob(os.path.join(OUTDIR, f"judge_{a.round}_*.json")):
        try:
            jd = json.load(open(jf, encoding="utf-8"))
            for x in jd.get("results", []):
                if x.get("fingerprint"):
                    done_fps.add(x["fingerprint"])
        except Exception:
            pass
    if done_fps:
        items = [(k, v) for k, v in items if k not in done_fps]
        print(f"（跳过已判 {len(done_fps)} 条）")
    if a.only_projects:
        want = {x.strip().lower() for x in a.only_projects.split(",")}
        items = [(k, v) for k, v in items if (v.get("project") or "").lower() in want]
    if a.only_sinks:
        ws = {x.strip() for x in a.only_sinks.split(",")}
        items = [(k, v) for k, v in items if (v.get("sink") or "") in ws]
    if a.limit:
        items = items[:a.limit]
    print(f"待判定 {len(items)} 条（来自 {a.round}）")
    if not items:
        return 0

    os.environ["AF_JUDGE_MT"] = str(a.mt)
    results = []
    for i, (fp, rec) in enumerate(items, 1):
        fd = _mk_finding(rec)
        cache: dict = {}
        try:
            r = LJ.judge_one(fd, cache, tag=f"{a.tag}-{a.round}")
            LJ._apply(fd, r)
            verdict, conf, reason = fd.ai_verdict, fd.ai_confidence, fd.ai_reason
            note = "OK"
        except Exception as e:
            verdict, conf, reason = "error", 0.0, f"{type(e).__name__}: {e}"[:200]
            note = "FAILED"
        results.append({
            "fingerprint": fp, "project": rec.get("project"),
            "file": rec.get("file"), "line": rec.get("line"),
            "sink": rec.get("sink"), "entry": rec.get("entry"),
            "verdict": verdict, "conf": conf,
            "arg_source": fd.arg_source, "by_design": fd.by_design,
            "scope_exceeds": fd.scope_exceeds, "guards_real": fd.guards_real,
            "reason": reason, "note": note,
        })
        mark = "★" if verdict == "vuln" else " "
        print(f"  [{i}/{len(items)}]{mark} {rec.get('project'):<20} "
              f"{os.path.basename(str(rec.get('file')))}:{rec.get('line'):<6} "
              f"{verdict:11} conf={conf:.2f} asrc={fd.arg_source}")

    os.makedirs(OUTDIR, exist_ok=True)
    out = os.path.join(OUTDIR, f"judge_{a.round}_{a.tag}.json")
    json.dump({"_meta": {"round": a.round, "n": len(results), "mt": a.mt},
               "results": results},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    from collections import Counter
    c = Counter(r["verdict"] for r in results)
    print(f"\n分布: {dict(c)}")
    v = [r for r in results if r["verdict"] == "vuln"]
    print(f"★ vuln: {len(v)}/{len(results)}")
    for r in v:
        print(f"    {r['project']:<18} {os.path.basename(str(r['file']))}:{r['line']} "
              f"conf={r['conf']}  {r['reason'][:90]}")
    print(f"\nJSON: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
