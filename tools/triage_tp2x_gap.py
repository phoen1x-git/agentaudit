"""TaintP2X 缺口分诊：把"没命中"的 positive **拆成两类**。

    python tools/triage_tp2x_gap.py --round out/round-tp2xj --repo wxy2ab__akinterpreter

★ 为什么必须拆（docs/171 第三段）：
  探测器对负例 100% 命中 → 零分辨力；全部分辨力来自判定层。
  而判定层只把净分辨力拉到 +6.7pt，因为**口径不同**。
  于是"26.7% 命中"里混着两类完全不同的东西，混在一起算召回**既冤枉我们也无法与论文比**：
    ① **真漏（MISS）**   ：我们**根本没产出候选**（探测器/形态缺口）
    ② **口径分歧（DIFF）**：我们产出了候选，但判定层按**自己的口径判 not_vuln / needs_human**
    ③ **命中（HIT）**    ：判定层判 vuln
  → 只有①才是"工具真的要改"的地方；②是"口径要对齐"的地方。
"""
from __future__ import annotations

import argparse
import ast
import glob as _glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_HERE)
D = os.path.join(_PROJ, "data", "target_pool")
BENCH = os.path.join(D, "taintp2x_benchmark.json")

SOURCE_FN = {
    "create", "one_chat", "text_chat", "chat", "completion", "completions",
    "generate", "generate_text", "stream", "embed", "embedding", "embeddings",
    "ask", "llm_call", "call_llm", "query_llm", "invoke", "invoke_llm",
}


def _norm(p): return (p or "").replace("\\", "/").strip("/")


def _tp_rel(fp):
    parts = _norm(fp).split("/")
    return "/".join(parts[2:]) if len(parts) >= 3 and parts[0] in ("servers", "servers2") else _norm(fp)


def _repo_dir(r): return _norm(r).replace("/", "__")


def _targets():
    out = []
    for y in _glob.glob(os.path.join(_PROJ, "core", "config", "targets*.yml")):
        try:
            import yaml
            d = yaml.safe_load(open(y, encoding="utf-8")) or {}
        except Exception:
            continue
        for k, v in (d.get("targets") or {}).items():
            if isinstance(v, dict):
                out.append({"short": k, "repo": _repo_dir(v.get("repo", "")),
                            "src": os.path.normpath(os.path.join(_PROJ, v["src"])) if v.get("src") else ""})
    return out


_C = {}


def _fr(src, fn):
    key = (src, fn)
    if key in _C:
        return _C[key]
    r = None
    if fn and src and os.path.exists(src):
        try:
            t = ast.parse(open(src, encoding="utf-8", errors="replace").read())
            for n in ast.walk(t):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn:
                    r = (n.lineno, getattr(n, "end_lineno", None) or n.lineno)
                    break
        except Exception:
            r = None
    _C[key] = r
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", required=True)
    ap.add_argument("--repo", default="", help="owner__repo；空=所有跑过的")
    ap.add_argument("--tag", default="gap")
    a = ap.parse_args()

    fj = os.path.join(a.round, "findings.json")
    if not os.path.exists(fj):
        print("[FAIL]", fj)
        return
    fnd = json.load(open(fj, encoding="utf-8"))
    tg = _targets()
    s2r = {t["short"]: t["repo"] for t in tg if t["repo"]}
    s2s = {t["short"]: t["src"] for t in tg if t["src"]}

    projects = {v.get("project") for v in fnd.values()}
    if a.repo:
        projects = {p for p in projects if s2r.get(p) == a.repo}
    print(f"[gap] round={a.round}  靶(短名)={sorted(projects)}")

    # 候选索引：file → [(line, verdict, entry, sink)]
    idx = {}
    for v in fnd.values():
        idx.setdefault(_norm(v.get("file") or ""), []).append((
            int(v.get("line") or 0),
            (v.get("ai_verdict") or "").strip(),
            v.get("entry") or "", v.get("sink")))

    def fm(f, rel):
        x, y = _norm(f), _norm(rel)
        return x == y or x.endswith("/" + y) or y.endswith("/" + x) or os.path.basename(x) == os.path.basename(y)

    bench = json.load(open(BENCH, encoding="utf-8"))["positive"]
    neg_all = json.load(open(BENCH, encoding="utf-8"))["negative"]
    rans = {s2r.get(p, "") for p in projects}
    sub = [it for it in bench if _repo_dir(it["repo"]) in rans]
    print(f"[gap] positive 分母 {len(sub)}")

    def classify(items, label):
        rows = []
        for it in items:
            verdicts: list[str] = []
            n_loc = n_matched_loc = 0
            rels: list[str] = []
            for loc in it.get("locus") or []:
                if (loc.get("function_name") or "").strip() in SOURCE_FN:
                    continue
                n_loc += 1
                rel = _tp_rel(loc.get("file_path") or "")
                rels.append(rel)
                fn = (loc.get("function_name") or "").strip()
                fr = None
                for root in s2s.values():
                    p = os.path.join(root, rel)
                    if os.path.exists(p):
                        fr = _fr(p, fn)
                        break
                hitv = []
                ln0 = int(loc.get("line_number") or 0)
                for f, rr in idx.items():
                    if not fm(f, rel):
                        continue
                    for line, verd, ent, sink in rr:
                        in_fn = (fr and fr[0] <= line <= fr[1])
                        name_ok = bool(fn and ent.split(".")[-1] == fn)
                        near = abs(line - ln0) <= 5
                        if in_fn or name_ok or near:
                            hitv.append(verd or "(未判)")
                if hitv:
                    n_matched_loc += 1
                    verdicts += hitv
            file_has_cand = any(any(fm(f, r) for f in idx) for r in rels)
            # ★★ issue 级口径（路 A）：locus 是"路径点"不是 sink，所以**位置对齐不可靠**；
            #    退一步问："这个 issue 涉及的**文件**里，我们有没有报出 vuln"。
            #    松，但诚实、可复现，且与论文「35 条里报出几条」的口径一致。
            file_vuln = False
            for f, rr in idx.items():
                if any(fm(f, r) for r in rels) and any(v == "vuln" for _, v, _, _ in rr):
                    file_vuln = True
            if any(v == "vuln" for v in verdicts):
                cat = "HIT  命中"
            elif verdicts:
                cat = "DIFF 口径分歧"
            elif file_vuln:
                cat = "HITf 文件级命中(同文件有vuln)"
            elif file_has_cand:
                cat = "MISSa 同文件有候选(位置没对上)"
            else:
                cat = "MISSb 文件里无候选(真缺口)"
            rows.append({"issue": it["issue"], "repo": it["repo"], "cat": cat,
                         "issue_hit": bool(any(v == "vuln" for v in verdicts) or file_vuln),
                         "n_sink_locus": n_loc, "n_matched_locus": n_matched_loc,
                         "verdicts": sorted(set(verdicts)),
                         "loci": [f"{_tp_rel(l.get('file_path','')).split('/')[-1]}:{l.get('line_number')}({l.get('function_name')})"
                                  for l in (it.get("locus") or [])
                                  if (l.get("function_name") or "").strip() not in SOURCE_FN]})
        return rows

    rows = classify(sub, "POS")
    neg_sub = [it for it in neg_all if _repo_dir(it["repo"]) in rans]
    nrows = classify(neg_sub, "NEG")

    from collections import Counter
    c = Counter(r["cat"] for r in rows)
    cn = Counter(r["cat"] for r in nrows)
    print("\n=== 分诊结果（positive）===")
    for k in ("HIT  命中", "DIFF 口径分歧", "HITf 文件级命中(同文件有vuln)",
              "MISSa 同文件有候选(位置没对上)", "MISSb 文件里无候选(真缺口)"):
        print(f"  {k:<32} {c.get(k,0):>3}")
    if rows and nrows:
        pr = c.get("HIT  命中", 0) / len(rows) * 100
        nr = cn.get("HIT  命中", 0) / len(nrows) * 100
        print(f"\n★ [严格口径] 正例 {pr:.1f}% ({c.get('HIT  命中',0)}/{len(rows)})  "
              f"负例 {nr:.1f}% ({cn.get('HIT  命中',0)}/{len(nrows)})  → 净 {pr-nr:+.1f} pt")
        ihp = sum(1 for r in rows if r.get("issue_hit"))
        ihn = sum(1 for r in nrows if r.get("issue_hit"))
        ip = ihp / len(rows) * 100
        inr = ihn / len(nrows) * 100
        print(f"★ [issue级口径 路A] 正例 {ip:.1f}% ({ihp}/{len(rows)})  "
              f"负例 {inr:.1f}% ({ihn}/{len(nrows)})  → 净 {ip-inr:+.1f} pt")
        print("  ★ 负例的命中 = **假阳性**（作者判无洞，我们报了 vuln）")
        print("  ★ 负例命中越少越好；正例−负例 = 净分辨力，>0 才有意义")
    print()
    for r in rows:
        print(f"  [{r['cat'][:4]}] #{r['issue']:<4} sink_locus={r['n_sink_locus']} matched={r['n_matched_locus']} "
              f"verdicts={r['verdicts']}")
        for l in r["loci"][:3]:
            print(f"          · {l}")
    op = os.path.join(D, f"tp2x_gap_{a.tag}.json")
    json.dump({"_meta": {"round": a.round, "repo": a.repo, "n": len(sub)},
               "rows": rows, "summary": dict(c)}, open(op, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\n明细:", op)


if __name__ == "__main__":
    main()
