"""TaintP2X 标准评估 v3：★版本对齐（函数级）+ 四级匹配 + 正负对照 + 判定层过滤。

    python tools/eval_taintp2x.py --round out/round-tp2xj --only-vuln --tag j
    python tools/eval_taintp2x.py --round out/round-tp2xq --tag q

★ 演进史（每一步都是被数据逼出来的）：
  v1 只用"文件里有 sink" → 负例命中率(79%) ≥ 正例(71%)，**指标自证无效**（docs/171）。
  v2 加"函数名精确相等" + 正负对照 + --only-vuln。
     → 无判定层时净分辨力仍 −48.6pt；**带判定层后转 +6.7pt**（有效但太弱）。
  v3 ★ **版本对齐**：作者标的 `function_name` 去**我们 clone 的当前版本**里定位函数的行范围，
     再判 finding 是否落在其中 → 绕开"行号漂移"（实测作者标 v2.py:478、我们命中 :393）。

四级匹配（都报，便于看出哪一级才有分辨力）：
  1. file  文件级
  2. ★ func  **版本对齐后的函数级**（主推）
  3. fn     函数名精确相等
  4. line   文件+行号 ±tol
"""
from __future__ import annotations

import argparse
import glob as _glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_HERE)
sys.path.insert(0, _PROJ)

D = os.path.join(_PROJ, "data", "target_pool")
BENCH = os.path.join(D, "taintp2x_benchmark.json")


# ★★ TaintP2X 的 locus 混了两类点：
#   · **source 点** = LLM 调用（它的核心命题是"LLM 输出 = 污点源"）；
#   · **sink 点** = 危险操作（exec / requests / SQL …）。
# 我们的 sink 表**只认 sink**，所以"命中任一 locus"这种口径**天生对我们不利**
# （我们根本没把 `client.chat.completions.create` 当 sink，也不该当）。
# → 本表 = 判定为 **source** 的函数名；`--in-range` 时把它们从 locus 里剔除，
#   并**只统计剔除后仍有 locus 的条目**（= 落在我们射程内的正例）。
SOURCE_FN = {
    "create", "one_chat", "text_chat", "chat", "completion", "completions",
    "generate", "generate_text", "stream", "embed", "embedding", "embeddings",
    "ask", "llm_call", "call_llm", "query_llm", "invoke", "invoke_llm",
}


def _is_source_loc(loc: dict) -> bool:
    return (loc.get("function_name") or "").strip() in SOURCE_FN


def _norm(p: str) -> str:
    return (p or "").replace("\\", "/").strip("/")


def _tp_rel(file_path: str) -> str:
    p = _norm(file_path)
    parts = p.split("/")
    if len(parts) >= 3 and parts[0] in ("servers", "servers2"):
        return "/".join(parts[2:])
    return p


def _fn_of(entry: str) -> str:
    e = (entry or "").strip()
    return e.split(".")[-1].split("@")[0] if e else ""


def _repo_dir(repo: str) -> str:
    return _norm(repo).replace("/", "__")


def _load_targets() -> list[dict]:
    out = []
    for y in _glob.glob(os.path.join(_PROJ, "core", "config", "targets*.yml")):
        try:
            import yaml
            d = yaml.safe_load(open(y, encoding="utf-8")) or {}
        except Exception:
            continue
        for k, v in (d.get("targets") or {}).items():
            if isinstance(v, dict):
                out.append({"short": k, "repo": v.get("repo", ""),
                            "src": os.path.normpath(os.path.join(_PROJ, v["src"])) if v.get("src") else ""})
    return out


_FR_CACHE: dict = {}


def _func_range(src_file: str, func_name: str):
    """在**当前版本**源码里找 func_name 的 (起始行, 结束行)。"""
    key = (src_file, func_name)
    if key in _FR_CACHE:
        return _FR_CACHE[key]
    rng = None
    if func_name and src_file and os.path.exists(src_file):
        import ast
        try:
            tree = ast.parse(open(src_file, encoding="utf-8", errors="replace").read())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                    rng = (node.lineno, getattr(node, "end_lineno", None) or node.lineno)
                    break
        except Exception:
            rng = None
    _FR_CACHE[key] = rng
    return rng


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", required=True)
    ap.add_argument("--tol", type=int, default=5)
    ap.add_argument("--only-vuln", action="store_true",
                    help="★只把判定层判 vuln 的 finding 算命中（真召回口径）")
    ap.add_argument("--tag", default="run")
    ap.add_argument("--in-range", action="store_true",
                    help="★只算'射程内'：剔除 source 类 locus（LLM 调用点），"
                         "并只统计剔除后仍有 sink locus 的条目（更公平的召回口径）")
    a = ap.parse_args()

    fj = os.path.join(a.round, "findings.json")
    if not os.path.exists(fj):
        print("[FAIL] 找不到", fj)
        return
    findings = json.load(open(fj, encoding="utf-8"))
    tg = _load_targets()
    short2repo = {t["short"]: _repo_dir(t["repo"]) for t in tg if t["repo"]}
    short2src = {t["short"]: t["src"] for t in tg if t["src"]}
    ran = {short2repo.get(v.get("project"), "") for v in findings.values()}
    ran.discard("")
    print(f"[eval] round={a.round}  only_vuln={a.only_vuln}")
    print(f"[eval] 跑过的靶: {sorted(ran)}")

    idx: dict[str, list] = {}
    n_used = 0
    for v in findings.values():
        verd = (v.get("ai_verdict") or v.get("verdict") or "").strip()
        if a.only_vuln and verd != "vuln":
            continue
        n_used += 1
        idx.setdefault(_norm(v.get("file") or ""), []).append((
            int(v.get("line") or 0), _fn_of(v.get("entry") or ""), verd, v.get("sink")))
    print(f"[eval] 计入 finding: {n_used} / {len(findings)}")

    def _filematch(f: str, rel: str) -> bool:
        x, y = _norm(f), _norm(rel)
        return x == y or x.endswith("/" + y) or y.endswith("/" + x) \
            or os.path.basename(x) == os.path.basename(y)

    def hit(loc: dict):
        """→ (file, func★, fn, line, detail)"""
        rel = _tp_rel(loc.get("file_path") or "")
        ln = int(loc.get("line_number") or 0)
        want_fn = (loc.get("function_name") or "").strip()
        # ★ 版本对齐：在当前版本源码里定位 want_fn 的行范围
        fr = None
        for root in short2src.values():
            p = os.path.join(root, rel)
            if os.path.exists(p):
                fr = _func_range(p, want_fn)
                break
        fh = fuc = nh = lh = False
        detail = ""
        for f, rows in idx.items():
            if not _filematch(f, rel):
                continue
            fh = True
            for rline, rfn, _v, _s in rows:
                if want_fn and rfn and rfn == want_fn:
                    nh = True
                    detail = detail or f"{os.path.basename(f)}:{rline}(fn={rfn})"
                if fr and fr[0] <= rline <= fr[1]:
                    fuc = True
                    detail = detail or f"{os.path.basename(f)}:{rline}∈{want_fn}[{fr[0]}-{fr[1]}]"
                if abs(rline - ln) <= a.tol:
                    lh = True
        return fh, fuc, nh, lh, detail

    def eval_set(items: list, label: str) -> dict:
        sub = [it for it in items if _repo_dir(it["repo"]) in ran]
        if a.in_range:
            # ★ 只留"剔除 source 后仍有点"的条目 = 落在我们射程内的正例
            sub = [it for it in sub
                   if any(not _is_source_loc(l) for l in (it.get("locus") or []))]
        if not sub:
            print(f"\n【{label}】★ 无条目落在跑过的靶里 → 不报率")
            return {"n": 0}
        n = len(sub)
        c = {"file": 0, "func": 0, "fn": 0, "line": 0}
        det = []
        for it in sub:
            got = [False] * 4
            d0 = ""
            for loc in it.get("locus") or []:
                if a.in_range and _is_source_loc(loc):
                    continue
                x = hit(loc)
                for i in range(4):
                    got[i] = got[i] or x[i]
                d0 = d0 or x[4]
            for i, k in enumerate(c):
                c[k] += got[i]
            if label.startswith("POS") and (got[1] or got[2]):
                det.append(f"#{it['issue']} ← {d0}")
        print(f"\n【{label}】分母 {n}   绝对数 file {c['file']} / func {c['func']} / fn {c['fn']} / line {c['line']}")
        for k, nm in (("file", "文件级"), ("func", "★函数级(版本对齐)"),
                      ("fn", "函数名精确"), ("line", "行号±tol")):
            print(f"    {nm:<18} {c[k]:>3} → {c[k]/n*100:5.1f}%")
        if det:
            print("  ★函数级/函数名命中明细:")
            for x in det[:20]:
                print("    ", x)
        return {"n": n, **c}

    bench = json.load(open(BENCH, encoding="utf-8"))
    rp = eval_set(bench["positive"], "POSITIVE(有洞)")
    rn = eval_set(bench["negative"], "NEGATIVE(无洞)")

    print("\n" + "=" * 64)
    if rp.get("n") and rn.get("n"):
        for k, nm in (("file", "文件级"), ("func", "★函数级(对齐)"),
                      ("fn", "函数名精确"), ("line", "行号±tol")):
            pr = rp[k] / rp["n"] * 100
            nr = rn[k] / rn["n"] * 100
            flag = "✅" if pr > nr else "❌"
            print(f"{flag} [{nm:<16}] 正例 {pr:5.1f}%  负例 {nr:5.1f}%  "
                  f"净分辨力 {pr-nr:+5.1f} pt")
        print("  → 净分辨力 ≤0 的口径**区分不了正负例**，不能当召回看")

    out = {"_meta": {"round": a.round, "tol": a.tol, "only_vuln": a.only_vuln,
                     "ran_repos": sorted(ran), "n_used": n_used,
                     "levels": ["file", "func(version-aligned)", "fn", "line"]},
           "positive": rp, "negative": rn}
    op = os.path.join(D, f"eval_tp2x3_{a.tag}.json")
    json.dump(out, open(op, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("明细:", op)


if __name__ == "__main__":
    main()
