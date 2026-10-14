# -*- coding: utf-8 -*-
"""★ 可达性预筛（把「第 0 关」自动化）—— 判断一条候选**能不能被真正调到**。

## 为什么需要
`docs/206` 立的「第 0 关」：**在问"有没有校验"之前，先问"这个函数谁能调到"**。
- 反例（不算）：`samplenodeapp` 的节点参数 —— 是**用户在工作流里手填的**，不是 LLM 决定的（`docs/215` 实测）
- 正例（算）：`sampletoolkit` 的 `get_tools()` 白名单 / `sampleassistant_ai` 的 `@tool` / FastAPI 端点

但这一关**一直是人工做的**，而台账里"待处理"已积 330 条 ⇒ **人工一条条看不可行**。
这个工具先把明显调不到的筛掉，人工面才收得窄。

## 判据（全部静态，不调 LLM、不花钱）

**第 0 步 · 是不是产品代码**（先砍一批）
路径落在 `.github/` `tests/` `test/` `docs/` `examples/` `benchmarks/` 或文件名以 `mock_` 开头
⇒ `·不可达(非产品代码/示例)` —— 这些不是随产品发布、用户跑不到的代码。

**第 1 步 · 同文件精查**（AST 层，证据最硬）—— 沿候选所在函数的**外层链**逐层看：
| 看到什么 | 判 |
|---|---|
| 装饰器里有 `tool`（`@tool(...)`） | ★ **可达(LLM工具)** |
| 类里 `get_tools()` / `FunctionTool(self.xxx)` 引用了它 | ★ **可达(LLM工具)** |
| 装饰器形如 `@app.post(...)` / `@router.get(...)` / ★ **`@bp.route(...)`**（Flask 蓝图） | ★ **可达(HTTP端点)** |
| 装饰器里有 `register_microservice` | ★ **可达(服务端点)** |

**第 2 步 · 跨文件兜底**（★ 必需 —— 很多 Agent 项目把"工具壳"放在**另一个文件**里，
例：`sampletoolkit/interpreters/*.py` 的 `run()` 是被 `sampletoolkit/toolkits/*.py` 里的 `FunctionTool(...)` 暴露的）
⇒ 扫**整棵源码树**收集"暴露点附近文本"（`FunctionTool(` / `@*tool*` / `@*.route|get|post|...` / `register_microservice`
附近的 ±2 行），若候选函数名出现在其中 ⇒ **可达(跨文件)**。

**第 3 步 · 都没暴露**
| 条件 | 判 |
|---|---|
| 所在类有 `INPUT_TYPES`（SampleNodeApp 节点） | `·不可达(UI参数)` —— 参数由工作流填，不是 LLM 给 |
| 其他 | `?存疑(未看到暴露点)` —— **不等于不可达**，可能经更绕的路径被调到 |

★ **注意它只回答"调不调得到"，不回答"有没有洞"** —— 可达 ≠ 有洞（可达只说明值得继续看）。
★ 已知局限见文件末尾。

用法：
    python tools/reachability_triage.py                     # 筛台账里所有"待处理"
    python tools/reachability_triage.py --verdict vuln      # 只筛 LLM 判 vuln 的
    python tools/reachability_triage.py --limit 20          # 试跑
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import candidate_ledger as CL  # noqa: E402

OUT_JSON = ROOT / "data" / "target_pool" / "reachability_triage.json"
OUT_MD = ROOT / "data" / "target_pool" / "reachability_triage.md"

REACH_LLM = "★可达(LLM工具)"
REACH_HTTP = "★可达(HTTP端点)"
REACH_SVC = "★可达(服务端点)"
REACH_X = "★可达(跨文件)"
NO_UI = "·不可达(UI参数)"
NO_NONPROD = "·不可达(非产品代码)"
UNK = "?存疑(未看到暴露点)"
NO_FILE = "?存疑(文件缺失)"

ORDER = [REACH_LLM, REACH_HTTP, REACH_SVC, REACH_X, UNK, NO_UI, NO_NONPROD, NO_FILE]

# 明显不是产品代码的路径片段（被扫进库但用户跑不到的）
NONPROD = (".github/", "/tests/", "/test/", "/docs/", "/examples/", "/example/",
           "/benchmarks/", "/benchmark/", "/scripts/")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
             ".mypy_cache", ".pytest_cache"}
# ★ 跨文件索引要排掉的（它们不是"产品里的暴露点"）
SNIPPET_SKIP = ("/tests/", "/test/", "/docs/", "/examples/", "/example/",
                "/.github/", "/benchmarks/", "/benchmark/")


# --------------------------------------------------------------------------
def src_root_map() -> dict[str, Path]:
    """靶短名 → 源码根目录（读 targets*.yml）。"""
    import yaml
    m: dict[str, Path] = {}
    for y in sorted((ROOT / "core" / "config").glob("targets*.yml")):
        try:
            d = yaml.safe_load(y.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        for short, v in (d.get("targets") or {}).items():
            s = (v or {}).get("src")
            if s and short not in m:
                m[short] = (ROOT / s).resolve()
    return m


def build_exposure_snippets(root: Path) -> list[tuple[str, int, str]]:
    """★ 跨文件兜底：扫整棵树，收集"暴露点"附近的文本片段（文本级，便宜）。

    ★ 必须排掉测试/示例 —— 实测踩过：`sampletoolkit` 的 `test_commons.py` 里有 `FunctionTool(`，
      于是**泛名**（`run` / `query`）全被误判成"可达"。
    """
    out: list[tuple[str, int, str]] = []
    for p in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        posix = p.as_posix()
        if any(k in "/" + posix for k in SNIPPET_SKIP) or p.name.startswith("test_") \
           or p.name.endswith("_test.py"):
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            s = ln.strip()
            hit = ("FunctionTool(" in ln
                   or re.search(r"@\w*(tool|mcp)\b", s, re.I)
                   or (s.startswith("@") and re.search(r"\.(route|get|post|put|delete|patch)\s*\(", s))
                   or "register_microservice" in ln)
            if hit:
                lo, hi = max(0, i - 2), min(len(lines), i + 3)
                out.append((str(p), i + 1, "\n".join(lines[lo:hi])))
    return out


def _unparse(n: ast.AST) -> str:
    try:
        return ast.unparse(n)
    except Exception:
        return ""


def enclosing_chain(tree: ast.AST, line: int) -> list[ast.AST]:
    """包含该行的函数链：最内层 → 最外层。"""
    holders = [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.lineno <= line <= (getattr(n, "end_lineno", n.lineno) or n.lineno)]
    holders.sort(key=lambda n: getattr(n, "end_lineno", 0) - n.lineno)
    return holders


def parents_of(tree: ast.AST) -> dict[int, ast.AST]:
    m: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for ch in ast.iter_child_nodes(node):
            m[id(ch)] = node
    return m


def outer_class(node: ast.AST, parent: dict[int, ast.AST]) -> ast.AST | None:
    cur = node
    while id(cur) in parent:
        cur = parent[id(cur)]
        if isinstance(cur, ast.ClassDef):
            return cur
    return None


def exposed_in_file(fn: ast.AST, klass: ast.AST | None) -> tuple[str, str]:
    """同文件 AST 精查。返回 (种类, 证据)。"""
    decos = [_unparse(d) for d in getattr(fn, "decorator_list", [])]
    for d in decos:
        if re.search(r"\btool\b", d, re.I):
            return REACH_LLM, f"@{d.strip()[:60]}"
    for d in decos:
        if re.search(r"\b[\w.]*(app|router|bp|blueprint|api)[\w.]*\.(get|post|put|delete|patch|route)\s*\(", d):
            return REACH_HTTP, f"@{d.strip()[:60]}"
    for d in decos:
        if "register_microservice" in d:
            return REACH_SVC, f"@{d.strip()[:60]}"
    if klass is not None:
        # ① `FunctionTool(self.<name>)` —— 最明确的暴露写法
        calls = "\n".join(_unparse(c) for c in ast.walk(klass) if isinstance(c, ast.Call))
        if re.search(r"FunctionTool\(\s*self\.%s\b" % re.escape(fn.name), calls):
            return REACH_LLM, f"FunctionTool(self.{fn.name})"
        # ② 名字出现在**本类的 get_tools()** 里
        for sub in ast.walk(klass):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name == "get_tools":
                if re.search(r"(?<![\w.])%s(?![\w])" % re.escape(fn.name), _unparse(sub)):
                    return REACH_LLM, f"{klass.name}.get_tools() 里列了 {fn.name}"
    return "", ""


def triage_one(short: str, rel: str, line: int, roots: dict[str, Path],
               snips: list[tuple[str, int, str]] | None) -> dict:
    root = roots.get(short)
    if not root:
        return {"verdict": NO_FILE, "why": "目标表里没有这个靶的 src", "fn": "", "klass": ""}
    rel_posix = rel.replace("\\", "/")
    low = "/" + rel_posix.lstrip("/")
    if any(k in low for k in NONPROD) or rel_posix.split("/")[-1].startswith("mock_"):
        return {"verdict": NO_NONPROD, "why": f"路径不像产品代码：{rel_posix[:70]}",
                "fn": "", "klass": ""}

    p = root / rel
    if not p.exists():
        return {"verdict": NO_FILE, "why": f"文件不存在：{p}", "fn": "", "klass": ""}
    try:
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as e:
        return {"verdict": UNK, "why": f"解析失败：{e}", "fn": "", "klass": ""}
    except OSError as e:
        return {"verdict": NO_FILE, "why": str(e), "fn": "", "klass": ""}

    parent = parents_of(tree)
    chain = enclosing_chain(tree, line)
    if not chain:
        return {"verdict": UNK, "why": "行号落在函数外（模块级）", "fn": "", "klass": ""}

    chain_txt = " → ".join(x.name for x in chain)

    # ---- 第 1 步：同文件精查（沿外层链）----
    for fn in chain:
        k = outer_class(fn, parent)
        kind, ev = exposed_in_file(fn, k)
        if kind:
            return {"verdict": kind, "why": f"{fn.name}(): {ev}", "fn": chain[0].name,
                    "klass": (k.name if k else ""), "chain": chain_txt}

    # ---- 第 2 步：跨文件兜底 ----
    names = [x.name for x in chain]
    klass = outer_class(chain[0], parent)
    if klass is not None:
        names.append(klass.name)
    if snips:
        for nm in names:
            if len(nm) < 4:              # ★ 太短的名字（run/query/get）一律不靠文本匹配判可达
                continue
            # ★ 必须"绑引用"：self.<nm> / .<nm>( / <nm>(  —— 裸词会误判
            pat = re.compile(r"(?:self\.|\.|\b)%s\s*[(.=,)]" % re.escape(nm))
            for f, ln, sn in snips:
                if pat.search(sn):
                    hit_file = Path(f)
                    return {"verdict": REACH_X,
                            "why": f"暴露点({hit_file.name}:{ln})附近出现 `{nm}`",
                            "fn": chain[0].name,
                            "klass": (klass.name if klass else ""), "chain": chain_txt}

    # ---- 第 3 步：都没暴露 ----
    for fn in chain:
        k = outer_class(fn, parent)
        if k is not None and "INPUT_TYPES" in _unparse(k):
            return {"verdict": NO_UI,
                    "why": f"{k.name} 是 SampleNodeApp 节点（参数由工作流填，不是 LLM 给）",
                    "fn": chain[0].name, "klass": k.name, "chain": chain_txt}
    return {"verdict": UNK, "why": "没看到 @tool / get_tools / HTTP 装饰器 / 微服务注册",
            "fn": chain[0].name, "klass": (klass.name if klass else ""), "chain": chain_txt}


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="可达性预筛（第 0 关自动化）")
    ap.add_argument("--verdict", default="vuln,needs_human",
                    help="筛哪些 LLM 判定（逗号分隔；all=全部待处理）")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 条（试跑用）")
    a = ap.parse_args()

    wanted = ({"vuln", "needs_human"} if a.verdict == "all"
              else {x.strip() for x in a.verdict.split(",") if x.strip()})
    st = CL.derive(CL.read_events())
    rows = []
    for fp, d in sorted(st.items()):
        if d["status"] != "pending" or d["llm_verdict"] not in wanted:
            continue
        m = d["meta"] or {}
        rows.append({"fp": fp, "project": m.get("project") or "", "file": m.get("file") or "",
                     "line": m.get("line") or 0, "sink": m.get("sink") or "",
                     "llm": d["llm_verdict"]})
    if a.limit:
        rows = rows[:a.limit]

    roots = src_root_map()
    cache: dict[str, list] = {}
    for r in rows:
        root = roots.get(r["project"])
        key = r["project"]
        if root and key not in cache:
            n = sum(1 for _ in root.rglob("*.py")) if root.is_dir() else 0
            print(f"  [索引] {key}: 扫 {n} 个 .py 找暴露点 …", flush=True)
            cache[key] = build_exposure_snippets(root) if root.is_dir() else []
        r.update(triage_one(r["project"], r["file"], r["line"], roots, cache.get(key)))

    OUT_JSON.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    cnt = Counter(r["verdict"] for r in rows)

    print("\n★ 可达性预筛：%d 条候选（LLM 判定 %s）" % (len(rows), "、".join(sorted(wanted))))
    for k in ORDER:
        if cnt.get(k):
            print("   %-20s %3d" % (k, cnt[k]))
    reach = sum(cnt.get(k, 0) for k in (REACH_LLM, REACH_HTTP, REACH_SVC, REACH_X))
    print("   ── ★ 需要继续看的（可达）= %d 条" % reach)
    print("   ── 可以先不看的（不可达）= %d 条"
          % (cnt.get(NO_UI, 0) + cnt.get(NO_NONPROD, 0)))

    L = ["# 可达性预筛（第 0 关）—— 哪些候选真的能被调到", "",
         f"> 候选 **{len(rows)}** 条 ｜ 判据见 `tools/reachability_triage.py` 头部",
         "> ★ **可达 ≠ 有洞**，只说明值得继续看；**「存疑」不等于不可达**。", ""]
    L.append("| 判定 | 条数 |")
    L.append("|---|---|")
    for k in ORDER:
        if cnt.get(k):
            L.append(f"| {k} | {cnt[k]} |")
    L.append(f"| **★ 可达合计（要继续看）** | **{reach}** |")
    L.append("")
    for k in [REACH_LLM, REACH_HTTP, REACH_SVC, REACH_X, UNK]:
        sub = [r for r in rows if r["verdict"] == k]
        if not sub:
            continue
        L.append(f"## {k}（{len(sub)} 条）")
        L.append("")
        by: dict[str, list] = defaultdict(list)
        for r in sub:
            by[r["project"]].append(r)
        for proj in sorted(by):
            L.append(f"### {proj}（{len(by[proj])} 条）")
            L.append("")
            L.append("| 位置 | sink | LLM | 暴露点 / 理由 |")
            L.append("|---|---|---|---|")
            for r in sorted(by[proj], key=lambda x: (x["file"], x["line"])):
                L.append(f"| `{r['file']}:{r['line']}` | `{r['sink']}` | {r['llm']} | {r['why']} |")
            L.append("")
    for k in [NO_UI, NO_NONPROD, NO_FILE]:
        sub = [r for r in rows if r["verdict"] == k]
        if not sub:
            continue
        L.append(f"## {k}（{len(sub)} 条，可以先不看）")
        L.append("")
        L.append("| 靶 | 条数 |")
        L.append("|---|---|")
        for p, n in Counter(r["project"] for r in sub).most_common():
            L.append(f"| {p} | {n} |")
        L.append("")
    L.append("## ★ 已知局限（别当结论用）")
    L.append("")
    L.append("1. **跨文件兜底是文本匹配**（按函数名），**可能有同名误判** —— 判成「可达(跨文件)」的要瞄一眼证据行。")
    L.append("2. 「存疑」= **没看到暴露点**，**不等于不可达**（可能经更绕的调用被调到）。")
    L.append("3. 判据只看**静态注册/装饰器**；**运行时动态注册**（`getattr`/插件扫描）看不出来。")
    L.append("4. ★ **它不判断「有没有洞」** —— 可达只是「值得看」的必要条件。")
    OUT_MD.write_text("\n".join(L), encoding="utf-8")
    print(f"\n→ {OUT_MD}\n→ {OUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
