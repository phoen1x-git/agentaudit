"""B1 · TaintP2X 口径对齐：逐条摊开「它标 positive、我们判 not_vuln」的点。

    python tools/align_tp2x_criteria.py --round out/round-tp2xj --repo wxy2ab__akinterpreter --tag ak
    python tools/align_tp2x_criteria.py --round-dir out/round-tp2x  --tag all      # 多轮合并

★ 为什么必须做（`docs/172`）：
  净分辨力只有 +6.7~+20 pt，而"没命中"里**混着两类完全不同的东西**：
    · **真漏**     = 我们根本没产出候选 → 探测器/形态缺口（真的要改工具）
    · **口径分歧** = 我们产出了候选，但判定层按**自己的口径**判 not_vuln → 要"对齐口径"而不是改工具
  不拆开，召回数字**既冤枉我们，也无法与论文 77.1% 直接比。**

★ 本工具的输出 = 一张**可逐条核对的表**：每条 positive 的每个 sink-locus 上，
  我们是什么判定、理由是什么。**这是"口径决策"（docs/145）的事实基础。**
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
# ★ 漏洞类型表（含 vulnerability_types；benchmark.json 里没存）——
#   用来**给分母分层**：只有"类型落在我们射程内"的 issue 才该被算进召回分母。
STATS_SRC = os.path.join(_PROJ, os.pardir,
                         "_targets", "taintp2x", "gt", "dataset", "real world",
                         "ds_source", "vulnerability_statistics.json")
IN_RANGE = {"Code_Execution", "SSRF", "SQL_Injection"}


def _load_types() -> dict:
    """{(repo, issue#): [types]}；读不到就返回空（退化为不分层）。"""
    try:
        d = json.load(open(STATS_SRC, encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for repo, v in d.items():
        for it in v.get("issues") or []:
            out[(repo, str(it.get("issue_number")))] = it.get("vulnerability_types") or []
    return out

# TaintP2X 的 locus 里混了 source 点（LLM 调用）与 sink 点，见 docs/172 第六节
SOURCE_FN = {
    "create", "one_chat", "text_chat", "chat", "completion", "completions",
    "generate", "generate_text", "stream", "embed", "embedding", "embeddings",
    "ask", "llm_call", "call_llm", "query_llm", "invoke", "invoke_llm",
}


def _norm(p): return (p or "").replace("\\", "/").strip("/")


def _tp_rel(fp):
    ps = _norm(fp).split("/")
    return "/".join(ps[2:]) if len(ps) >= 3 and ps[0] in ("servers", "servers2") else _norm(fp)


def _repo_dir(r): return _norm(r).replace("/", "__")


def _is_test_path(rel: str) -> bool:
    """★ 我们**主动排除**的测试路径（见 core/config/filters.yml：
    path_segments=[tests,test,testing,__tests__] + filename_re=[test_*.py,*_test.py,conftest.py]）。
    → 所以 TaintP2X 标为 positive 的测试文件点位，是**口径分歧**（DIFF-c），不是"漏"。"""
    import re as _re
    segs = _norm(rel).split("/")
    if any(s.lower() in ("tests", "test", "testing", "__tests__") for s in segs[:-1]):
        return True
    return bool(_re.match(r"^(test_.*|.*_test|conftest)\.py$", segs[-1].lower()))


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
    ap.add_argument("--round", default="")
    ap.add_argument("--round-dir", default="", help="合并 out/ 下所有 round-<prefix>* 的 findings")
    ap.add_argument("--repo", default="")
    ap.add_argument("--tag", default="align")
    ap.add_argument("--tol", type=int, default=5)
    ap.add_argument("--in-range-only", action="store_true",
                    help="★ 分母只含『漏洞类型落在我们射程内』的 issue（Code_Execution/SSRF/SQL）—— "
                         "因为 TaintP2X 的 locus 里混了大量非 sink 的路径点，不筛会把 MISS 算膨胀")
    a = ap.parse_args()

    # ---- 载入 findings（可多轮合并）----
    rounds = []
    if a.round:
        rounds = [a.round]
    elif a.round_dir:
        base = os.path.dirname(a.round_dir.rstrip("/\\"))
        pref = os.path.basename(a.round_dir.rstrip("/\\"))
        rounds = sorted(x for x in _glob.glob(os.path.join(base, pref + "*"))
                        if os.path.isdir(x) and os.path.exists(os.path.join(x, "findings.json")))
    fnd = {}
    for r in rounds:
        try:
            for k, v in json.load(open(os.path.join(r, "findings.json"), encoding="utf-8")).items():
                fnd.setdefault(k, v)
        except Exception:
            pass
    print(f"[align] 轮次={len(rounds)}  findings={len(fnd)}")

    tg = _targets()
    s2r = {t["short"]: t["repo"] for t in tg if t["repo"]}
    s2s = {t["short"]: t["src"] for t in tg if t["src"]}

    projects = {v.get("project") for v in fnd.values()}
    if a.repo:
        projects = {p for p in projects if s2r.get(p) == a.repo}
    if not projects:
        print("[align] ★ 没有任何靶匹配 → 检查 --repo / 短名映射")
        return

    idx = {}
    for v in fnd.values():
        if v.get("project") not in projects:
            continue
        idx.setdefault(_norm(v.get("file") or ""), []).append((
            int(v.get("line") or 0), (v.get("ai_verdict") or "").strip(),
            v.get("entry") or "", v.get("sink"), (v.get("ai_reason") or "")[:160]))

    def fm(f, rel):
        x, y = _norm(f), _norm(rel)
        return x == y or x.endswith("/" + y) or y.endswith("/" + x) or os.path.basename(x) == os.path.basename(y)

    bench = json.load(open(BENCH, encoding="utf-8"))
    rans = {s2r.get(p, "") for p in projects}
    types_map = _load_types()
    if a.in_range_only:
        print(f"[align] ★ 射程过滤开启（{sorted(IN_RANGE)}）；类型表 {len(types_map)} 条")

    rows = []
    for kind in ("positive", "negative"):
        for it in bench[kind]:
            if _repo_dir(it["repo"]) not in rans:
                continue
            if a.in_range_only and kind == "positive":
                ts = types_map.get((it["repo"], str(it["issue"])), [])
                if ts and not any(t in IN_RANGE for t in ts):
                    continue          # 类型不在射程 → 不进分母
            for loc in it.get("locus") or []:
                fn = (loc.get("function_name") or "").strip()
                if fn in SOURCE_FN:
                    continue          # 跳过 source 点（不是我们的射程）
                rel = _tp_rel(loc.get("file_path") or "")
                ln = int(loc.get("line_number") or 0)
                fr = None
                for root in s2s.values():
                    p = os.path.join(root, rel)
                    if os.path.exists(p):
                        fr = _fr(p, fn)
                        break
                hits = []
                for f, rr in idx.items():
                    if not fm(f, rel):
                        continue
                    for line, verd, ent, sink, reason in rr:
                        if (fr and fr[0] <= line <= fr[1]) \
                           or (fn and ent.split(".")[-1] == fn) \
                           or abs(line - ln) <= a.tol:
                            hits.append((line, verd, sink, reason))
                rows.append({
                    "kind": kind, "issue": it["issue"], "repo": it["repo"],
                    "rel": rel, "line": ln, "fn": fn,
                    "is_test": _is_test_path(rel),
                    "our_verdicts": sorted({h[1] or "(未判)" for h in hits}),
                    "n_hits": len(hits),
                    "reasons": sorted({h[3] for h in hits if h[3]}),
                })

    # ---- 汇总 ----
    from collections import Counter

    def _diag_sub(r) -> str:
        """把「我们判否」再拆细（★ 2026-10-12 实测发现 DIFF 混了三种完全不同的东西）。"""
        txt = " ".join(r["reasons"])
        if r["is_test"]:
            # ★ DIFF-c：我们**主动排除测试路径**（filters.yml 的 path_segments/filename_re）
            return "DIFF-c 测试文件口径"
        if any(k in txt for k in ("self.base_url", "配置好的", "属设计功能",
                                  "不存在任意地址", "不是本次输入")):
            # ★ DIFF-a：配置归属类 —— TaintP2X 只问"LLM 输出有没有流向外部"，
            #   我们还要问"这个值写在谁的地盘上"（docs/145）
            return "DIFF-a 配置归属口径"
        if any(k in txt for k in ("不在给定代码", "看不到", "需人工确认", "无法判定",
                                  "无 法判定", "证据")):
            # ★ DIFF-b：纯粹是**输入不够**（补一层调用方/被调函数就能判），不是口径问题
            return "DIFF-b 输入不够"
        return "DIFF-x 其他判否"

    def cat(r):
        if r["kind"] == "negative":
            return "NEG-HIT(假阳)" if "vuln" in r["our_verdicts"] else (
                "NEG-DIFF" if r["our_verdicts"] else "NEG-无候选")
        if "vuln" in r["our_verdicts"]:
            return "HIT 命中"
        if r["our_verdicts"]:
            return _diag_sub(r)
        # ★★★ 没候选还要再拆：**"被过滤排除"≠"真漏"**（2026-10-12 实测踩到）
        #   我们的 filters.yml 会在**扫描阶段**就丢掉 tests/ demo/ docs/ 等路径，
        #   所以 TaintP2X 标为 positive 的测试点位**根本不会产生候选** → 会被误算成 MISS。
        if r["is_test"]:
            return "MISS-f 被过滤排除(测试/示例路径)"
        return "MISS 真漏"

    c = Counter(cat(r) for r in rows)
    print("\n=== locus 级分类 ===")
    for k in ("HIT 命中", "DIFF-a 配置归属口径", "DIFF-b 输入不够", "DIFF-c 测试文件口径",
              "DIFF-x 其他判否", "MISS 真漏", "MISS-f 被过滤排除(测试/示例路径)",
              "NEG-HIT(假阳)", "NEG-DIFF", "NEG-无候选"):
        if c.get(k):
            print(f"  {k:<26} {c[k]}")

    for want in ("DIFF-a 配置归属口径", "DIFF-b 输入不够", "DIFF-c 测试文件口径"):
        print(f"\n=== {want} 明细 ===")
        n = 0
        for r in rows:
            if cat(r) == want:
                n += 1
                if n <= 6:
                    print(f"  #{r['issue']:<4} {r['rel'].split('/')[-1]}:{r['line']}({r['fn']}) "
                          f"→ {r['our_verdicts']}")
                    for x in r["reasons"][:1]:
                        print(f"         理由: {x[:120]}")
        if not n:
            print("  （无）")
        elif n > 6:
            print(f"  ...（共 {n} 条）")
    if True:
        pass

    print("\n=== MISS 真漏明细（我们完全没候选）===")
    n = 0
    for r in rows:
        if cat(r) == "MISS 真漏":
            n += 1
            print(f"  #{r['issue']:<4} {r['rel'].split('/')[-1]}:{r['line']}({r['fn']})")
    if not n:
        print("  （无）")

    op = os.path.join(D, f"tp2x_align_{a.tag}.json")
    json.dump({"_meta": {"rounds": rounds, "repo": a.repo, "projects": sorted(projects),
                         "tol": a.tol, "levels": ["func-range", "fn-eq", "line±tol"]},
               "rows": rows, "summary": dict(c)}, open(op, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\n明细:", op)


if __name__ == "__main__":
    main()
