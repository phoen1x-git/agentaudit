"""② 新判据：**参数贯通性**（从"入口能到"到"参数真能带着 payload 到 sink"）。

★★ 为什么要加这一条（`docs/237` §四 与 2026-10-14 的两条实测）：

  `find_entries_for_suspects.py` 只回答「**sink 所在函数有没有挂暴露标记的调用方**」——
  也就是「**入口能到**」。但它**没回答后半句**：

  > ★ **入口能到 ≠ 参数能被外面控制、且能带着 payload 走到 sink。**

  2026-10-14 逐字复核两条候选，**两条都是误报、但根因不同**：

  | 靶 | sink | 误报根因 | 本工具应给什么判决 |
  |---|---|---|---|
  | sampletoolkit `open_api_toolkit.py` | `os.path.join` | `api_name` 是**从本地目录枚举出来的**（不是入参） | **本地生成** |
  | sampleassistant_ai `commodity_information.py` | `eval` | 参数**确实是工具入参**，但 `get_optional_fields()` 声明了 `Validator`，分发器 `execute_tool` 在 `execute()` **之前强制校验**（实测 payload 被降级成 `None`） | **有校验** |

  ⇒ ★ 本工具对每个候选给三档判决：
     `本地生成`（排除） / `有校验`（排除） / `直通`（**保留**，才值得送判定层）。

★ 成本：**0**（纯 AST，不调 LLM、不用网络）。

用法：
    python tools/param_taint_criteria.py --selftest          # 用上面那两条已知案例自测
    python tools/param_taint_criteria.py --all               # 全池跑一遍
    python tools/param_taint_criteria.py --project sampleassistant_ai
"""
from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import find_entries_for_suspects as E  # noqa: E402  复用 SRC_ROOTS / find_src_root / is_test_code

TRIAGE = os.path.join(ROOT, "data", "target_pool", "reachability_triage.json")
OUT_MD = os.path.join(ROOT, "data", "target_pool", "param_taint_probe.md")
OUT_JSON = os.path.join(ROOT, "data", "target_pool", "param_taint_probe.json")

# ── 校验/净化函数的命名特征（框架级 + 内联）──────────────────────────────
SANITIZER_NAME_PAT = re.compile(
    r"validat|sanitiz|sanitis|escape|whitelist|allowlist|allow_list|blocklist|"
    r"clean|normaliz|canonical|verify|ensure|assert|check|guard|filter_",
    re.I,
)
# 类型收窄：不改变值但把非目标类型排除
NARROW_ATTRS = {"isdigit", "isdecimal", "isnumeric", "isalpha", "isalnum", "isidentifier"}
RE_FUNCS = {"match", "fullmatch", "search", "findall", "sub"}

# ── 声明式 Validator：Agent 工具框架的典型形态 ──────────────────────────
FIELD_DECL_NAMES = {"get_optional_fields", "get_mandatory_fields", "get_fields",
                    "get_parameters", "get_input_schema", "parameters"}


# ══════════════════════════════════════════════════════════════════════════
# 基础工具
# ══════════════════════════════════════════════════════════════════════════
def _parse(path: str):
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
        return ast.parse(src), src
    except Exception:
        return None, ""


def _func_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _func_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _enclosing_func(tree, line: int):
    """返回**最内层**包住 line 的函数节点。"""
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(n, "end_lineno", n.lineno)
            if n.lineno <= line <= end:
                if best is None or n.lineno >= best.lineno:
                    best = n
    return best


def _enclosing_class(tree, func) -> ast.ClassDef | None:
    if func is None:
        return None
    for n in ast.walk(tree):
        if isinstance(n, ast.ClassDef):
            if func in getattr(n, "body", []):
                return n
    return None


def _names_in(node) -> set[str]:
    """取表达式里的**根基名**（含 f-string 里的插值变量）。"""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
    return out


def _sink_arg_names(func, line: int, sink: str) -> set[str]:
    """在 sink 那一行找到调用节点，抽出实参里的根基名。"""
    sink_tail = (sink or "").split(".")[-1]
    best = None
    for n in ast.walk(func):
        if isinstance(n, ast.Call) and n.lineno == line:
            nm = _func_name(n.func)
            if sink_tail and (sink_tail in nm or nm in sink_tail):
                best = n
                break
            if best is None:
                best = n
    if best is None:
        return set()
    acc: set[str] = set()
    for a in list(best.args) + [k.value for k in best.keywords]:
        acc |= _names_in(a)
    return acc


def _param_names(func) -> set[str]:
    a = func.args
    names = {p.arg for p in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)}
    # ★ self / cls 不是"外部可控的形参"，不能算
    names.discard("self")
    names.discard("cls")
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


# ── 追溯「这个名字从哪来」───────────────────────────────────────────────
def _bindings(func, line: int) -> dict[str, ast.AST]:
    """name → 绑定它的 AST 节点，★ 只取 **sink 之前最近一次** 绑定（否则会被后/前的无关循环带偏）。"""
    best: dict[str, tuple[int, ast.AST]] = {}

    def bind_target(t, src, ln):
        if isinstance(t, ast.Name):
            if ln < line and (t.id not in best or ln > best[t.id][0]):
                best[t.id] = (ln, src)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                bind_target(e, src, ln)

    for n in ast.walk(func):
        ln = getattr(n, "lineno", 0)
        if ln >= line:
            continue
        if isinstance(n, ast.Assign):
            for t in n.targets:
                bind_target(t, n.value, ln)
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            bind_target(n.target, n.value, ln)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            bind_target(n.target, n.iter, ln)
        elif isinstance(n, ast.With):
            for it in n.items:
                if it.optional_vars is not None:
                    bind_target(it.optional_vars, it.context_expr, ln)
    return {k: v[1] for k, v in best.items()}


def _classify_node(n, func, params: set[str], binds: dict, depth=0) -> tuple[str, str]:
    """把**一个表达式**归类：param / call / local / attr / unknown。"""
    if depth > 6:
        return "unknown", "追溯过深"
    if isinstance(n, ast.Name):
        return _classify_root(n.id, func, params, binds, depth)
    if isinstance(n, ast.Call):
        return "call", f"{_func_name(n.func)}() （调用产生）"
    if isinstance(n, ast.Constant):
        return "local", "常量"
    if isinstance(n, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return "local", "字面量容器"
    if isinstance(n, ast.JoinedStr):
        inner = _names_in(n)
        if not inner:
            return "local", "常量拼接"
        kinds = [_classify_root(x, func, params, binds, depth + 1) for x in inner]
        if any(k[0] == "param" for k in kinds):
            return "param", "由形参拼成"
        return "local", "由本地值拼成"
    if isinstance(n, ast.Attribute):
        if _func_name(n).startswith("self."):
            return "attr", f"{_func_name(n)}"
        return _classify_root(_func_name(n).split(".")[0], func, params, binds, depth + 1)
    if isinstance(n, (ast.Subscript,)):
        return _classify_node(n.value, func, params, binds, depth + 1)
    if isinstance(n, ast.BinOp):
        kinds = [_classify_node(s, func, params, binds, depth + 1)
                 for s in (n.left, n.right)]
        if any(k[0] == "param" for k in kinds):
            return "param", "由形参运算而成"
        return "local", "由本地值运算而成"
    return "unknown", f"表达式类型 {type(n).__name__}"


def _classify_root(root: str, func, params: set[str], binds: dict, depth=0) -> tuple[str, str]:
    """把一个名字归类：param / call / local / attr / unknown。返回 (kind, detail)。"""
    if depth > 6:
        return "unknown", "追溯过深"
    if root in params:
        return "param", f"形参 {root}"
    src = binds.get(root)
    if src is None:
        if root == "self":
            return "attr", "self"
        return "unknown", f"{root} 未在函数内找到绑定（可能是全局/闭包）"
    kind, detail = _classify_node(src, func, params, binds, depth + 1)
    return kind, (f"{root} = {detail}" if kind == "call" else detail)



# ── 守卫扫描：形参 → sink 之间有没有"约束"────────────────────────────────
def _guards_between(func, line: int, roots: set[str]) -> list[str]:
    hits: list[str] = []
    for n in ast.walk(func):
        ln = getattr(n, "lineno", 10 ** 9)
        if ln >= line:
            continue
        # ① 类型收窄 / 净化函数 / 正则
        if isinstance(n, ast.Call):
            nm = _func_name(n.func)
            tail = nm.split(".")[-1]
            if tail in NARROW_ATTRS or tail == "isinstance":
                if _names_in(n) & roots:
                    hits.append(f"{ln}: 类型/字符收窄 `{nm}()`")
            elif SANITIZER_NAME_PAT.search(tail):
                if _names_in(n) & roots:
                    hits.append(f"{ln}: 净化函数 `{nm}()`")
            elif tail in RE_FUNCS and nm.split(".")[0] == "re":
                if _names_in(n) & roots:
                    hits.append(f"{ln}: 正则约束 `{nm}()`")
        # ② 成员测试 x in [...] / x not in (...)
        if isinstance(n, ast.Compare) and _names_in(n) & roots:
            for op, cmp in zip(n.ops, n.comparators):
                if isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                        cmp, (ast.List, ast.Tuple, ast.Set)):
                    hits.append(f"{ln}: 白/黑名单成员测试 `in [...]`")
    return hits


# ── 声明式 Validator：类里声明了字段校验器 ───────────────────────────────
def _declared_validators(tree, klass, klass_src_lines: list[str]) -> dict[str, str]:
    """返回 {字段名: 证据}：类里 get_optional_fields/get_mandatory_fields 声明的字段。"""
    out: dict[str, str] = {}
    if klass is None:
        return out
    for fn in klass.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name not in FIELD_DECL_NAMES:
            continue
        seg = "\n".join(klass_src_lines[fn.lineno - 1: getattr(fn, "end_lineno", fn.lineno)])
        for key in re.findall(r"[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*:", seg):
            out.setdefault(key, f"{klass.name}.{fn.name} 声明了 `{key}`")
        # Validator( 出现的数量作为"该文件确实有校验框架"的旁证
        if "Validator(" in seg:
            out.setdefault("__has_validator__", f"{klass.name}.{fn.name} 用了 Validator(...)")
    return out


def _root_param(root: str, func, params: set[str], binds: dict, depth=0):
    """★ 把名字还原成它**最终源自哪个形参**（例如 `api_name` ← for 遍历 `apinames_filepaths`）。"""
    if depth > 6:
        return None
    if root in params:
        return root
    src = binds.get(root)
    if src is None:
        return None
    if isinstance(src, ast.Name):
        return _root_param(src.id, func, params, binds, depth + 1)
    if isinstance(src, ast.JoinedStr):
        for x in _names_in(src):
            r = _root_param(x, func, params, binds, depth + 1)
            if r:
                return r
    if isinstance(src, ast.BinOp):
        for s in (src.left, src.right):
            if isinstance(s, ast.Name):
                r = _root_param(s.id, func, params, binds, depth + 1)
                if r:
                    return r
    return None


def _param_index(func, name: str):
    a = func.args
    pos = list(a.posonlyargs) + list(a.args)
    # ★ 方法调用 `self.f(x)` 的实参**不含 self** ⇒ 下标要跳过 self/cls
    if pos and pos[0].arg in ("self", "cls"):
        pos = pos[1:]
    for i, p in enumerate(pos):
        if p.arg == name:
            return i
    for p in a.kwonlyargs:
        if p.arg == name:
            return -2
    return None


def _caller_pass_kind(tree, func, param: str) -> list[tuple[str, str]]:
    """★ 第二层：在本模块内找 `func` 的调用方，看它给 `param` 传的**实参**是什么。

    sampletoolkit 那条正是栽在这里：`api_name` **确实是形参**，但调用方传进来的是
    `self.generate_apinames_filepaths()`（**本地枚举 OpenAPIName 枚举值**）⇒ 外面控制不了。
    """
    idx = _param_index(func, param)
    hits = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        if _func_name(n.func).split(".")[-1] != func.name:
            continue
        argnode = None
        if idx is not None and idx >= 0 and idx < len(n.args):
            argnode = n.args[idx]
        for k in n.keywords:
            if k.arg == param:
                argnode = k.value
        if argnode is None:
            continue
        cf = _enclosing_func(tree, n.lineno)
        if cf is None or cf is func:
            continue
        cparams = _param_names(cf)
        cbinds = _bindings(cf, n.lineno)
        kind, detail = _classify_node(argnode, cf, cparams, cbinds)
        hits.append((kind, f"调用方 {cf.name}:{n.lineno} 传 {detail}"))
    return hits


def judge(project: str, rel: str, line: int, sink: str) -> dict:
    root = E.find_src_root(project)
    rec = {"project": project, "file": rel, "line": line, "sink": sink,
           "verdict": "不确定", "detail": "", "roots": [], "guards": [], "callers": [],
           "has_src": bool(root)}
    if not root:
        rec["detail"] = "找不到源码根"
        return rec
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        rec["detail"] = f"文件不存在: {rel}"
        return rec
    tree, src = _parse(path)
    if tree is None:
        rec["detail"] = "解析失败"
        return rec
    lines = src.splitlines()
    func = _enclosing_func(tree, line)
    if func is None:
        rec["detail"] = "找不到所在函数"
        return rec
    params = _param_names(func)
    binds = _bindings(func, line)
    names = _sink_arg_names(func, line, sink)
    if not names:
        rec["detail"] = "sink 那一行没抽到实参名"
        rec["verdict"] = "不确定"
        return rec

    kinds = {n: _classify_root(n, func, params, binds) for n in names}
    rec["roots"] = [f"{n}:{k[0]}({k[1]})" for n, k in kinds.items()]

    # ① 没有任何名字追到形参
    if not any(k[0] == "param" for k in kinds.values()):
        weak = {n: k for n, k in kinds.items() if k[0] in ("attr", "unknown")}
        if weak:
            # ★ self.xxx（实例属性）/ 追不到的全局 —— 未必"外面控制不了"，不能当排除
            rec["verdict"] = "不确定"
            rec["detail"] = ("sink 实参既追不到形参、也不全是本地值："
                             + "; ".join(f"{n}={k[1]}" for n, k in list(weak.items())[:3]))
            return rec
        loc = [n for n, k in kinds.items() if k[0] in ("local", "call")]
        rec["verdict"] = "本地生成"
        rec["detail"] = ("sink 实参 " + ", ".join(sorted(names))
                         + " 都是本地值/内部调用，追不到形参；其中 "
                         + ", ".join(f"{n}={kinds[n][0]}" for n in loc[:4])
                         + " ⇒ 外面控制不了")
        return rec

    # ② 追到形参 ⇒ 看有没有约束
    param_roots = {n for n, k in kinds.items() if k[0] == "param"}
    # ★ 还原成"最终源自哪个形参"（循环变量 → 源形参）
    sources = {s for s in (_root_param(n, func, params, binds) for n in param_roots) if s}
    rec["sources"] = sorted(sources)
    # ②a 内联守卫
    guards = _guards_between(func, line, param_roots)
    # ②b 声明式 Validator
    klass = _enclosing_class(tree, func)
    decl = _declared_validators(tree, klass, lines)
    decl_hit = [n for n in sources if n in decl]

    rec["guards"] = guards
    if decl_hit:
        rec["verdict"] = "有校验"
        rec["detail"] = f"参数 {', '.join(sorted(decl_hit))} 在 " + "; ".join(decl[n] for n in decl_hit[:2])
        return rec
    if guards:
        rec["verdict"] = "有校验"
        rec["detail"] = "形参到 sink 之间有约束：" + "; ".join(guards[:3])
        return rec

    # ③ 本函数里没看到约束 ⇒ ★ 再走一层：**调用方传进来的实参是什么**？
    caller_hits: list[tuple[str, str]] = []
    for pr in sorted(sources or param_roots):
        caller_hits.extend(_caller_pass_kind(tree, func, pr))
    rec["callers"] = [h[1] for h in caller_hits]

    if caller_hits and all(h[0] in ("local", "call") for h in caller_hits):
        rec["verdict"] = "本地生成"
        rec["detail"] = ("形参的实参在调用方那边是内部产生的值 ⇒ 外面控制不了；"
                         + "; ".join(h[1] for h in caller_hits[:2]))
        return rec
    if caller_hits and any(h[0] == "param" for h in caller_hits):
        rec["verdict"] = "直通"
        rec["detail"] = ("参数来自**上层形参**（还要再往上追）；"
                         + "; ".join(h[1] for h in caller_hits[:2]))
        return rec

    rec["verdict"] = "直通"
    rec["detail"] = (f"参数 {', '.join(sorted(param_roots))} 从形参直达 sink，"
                     + ("本模块内找不到调用方" if not caller_hits else "调用方传参不可判定")
                     + "，未见任何校验")
    return rec


# ══════════════════════════════════════════════════════════════════════════
def _selftest() -> int:
    cases = [
        # (project, file, line, sink, 期望判决)
        ("sampletoolkit", "sampletoolkit/toolkits/open_api_toolkit.py", 478, "os.path.join", "本地生成"),
        ("sampleassistant_ai", "skills/uexcorp/uexcorp/tool/commodity_information.py", 104, "eval", "有校验"),
    ]
    print("=" * 78)
    print("② 参数贯通性判据 · 自测（对着 2026-10-14 的两条已知案例）")
    print("=" * 78)
    ok = 0
    for proj, f, ln, sink, exp in cases:
        r = judge(proj, f, ln, sink)
        got = r["verdict"]
        mark = "✅" if got == exp else "❌"
        if got == exp:
            ok += 1
        print(f"\n{mark} 期望={exp}  实得={got}")
        print(f"   {proj} · {f}:{ln}  sink={sink}")
        print(f"   roots : {r['roots']}")
        print(f"   guards: {r['guards']}")
        print(f"   detail: {r['detail']}")
    print("\n" + "=" * 78)
    print(f"自测：{ok}/{len(cases)} 通过")
    print("=" * 78)
    return 0 if ok == len(cases) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--project", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--tier", default="all", choices=["all", "vuln", "needs_human"])
    a = ap.parse_args()

    if a.selftest:
        return _selftest()

    tri = json.load(open(TRIAGE, encoding="utf-8"))
    rows = tri
    if a.project and not a.all:
        rows = [r for r in rows if r["project"] == a.project]
    if a.tier != "all":
        rows = [r for r in rows if str(r.get("llm")) == a.tier]

    results = []
    for r in rows:
        rec = judge(r["project"], r.get("file") or "", int(r.get("line") or 0), r.get("sink") or "")
        rec["fp"] = r.get("fp")
        rec["tier"] = r.get("verdict")
        rec["llm"] = r.get("llm")
        results.append(rec)

    json.dump(results, open(OUT_JSON, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    cnt = collections.Counter(x["verdict"] for x in results)
    by_proj = collections.defaultdict(collections.Counter)
    for x in results:
        by_proj[x["project"]][x["verdict"]] += 1
    # ★ 直通里，"有调用方证据"的才更值得先看；"本模块内找不到调用方"的只是没被排除
    thru = [x for x in results if x["verdict"] == "直通"]
    thru_conf = [x for x in thru if x.get("callers")]

    L = ["# ② 参数贯通性判据 · 探测结果\n",
         "> ★ 零成本（纯 AST）。回答的问题是：**sink 的实参追不追得到形参，中间有没有校验**。",
         "> ★ 三档：`本地生成`（排除）/ `有校验`（排除）/ `直通`（**保留**）。",
         "> ⚠️ `直通` 只是**必要条件**（形参未被约束），**不等于「外面真能控制」** —— 还要经调用方确认。\n",
         f"- 看过：**{len(results)}** 条",
         f"- ★ **直通**（形参未被约束 ⇒ **未被排除**）：**{cnt.get('直通', 0)}**"
         f"，其中**有调用方证据**的 **{len(thru_conf)}** 条 ← 这些优先看",
         f"- 本地生成（外面控制不了 ⇒ 排除）：**{cnt.get('本地生成', 0)}**",
         f"- 有校验（被白名单/净化挡住 ⇒ 排除）：**{cnt.get('有校验', 0)}**",
         f"- 不确定（源码缺 / 解析失败 / 追溯复杂）：**{cnt.get('不确定', 0)}**",
         f"- ★★ **合计排除**（本地生成 + 有校验）：**{cnt.get('本地生成', 0) + cnt.get('有校验', 0)}**"
         f" 条 = {100 * (cnt.get('本地生成', 0) + cnt.get('有校验', 0)) / max(len(results), 1):.0f}% 的候选**在花钱之前就被排掉**\n",
         "## 分靶\n", "| 靶 | 直通 | 本地生成 | 有校验 | 不确定 | 合计 |", "|---|---|---|---|---|---|"]
    for p, c in sorted(by_proj.items(), key=lambda kv: -sum(kv[1].values())):
        tot = sum(c.values())
        L.append(f"| {p} | **{c.get('直通', 0)}** | {c.get('本地生成', 0)} | "
                 f"{c.get('有校验', 0)} | {c.get('不确定', 0)} | {tot} |")

    L.append("\n## ★ 直通 · 有调用方证据（优先看）· 前 30 条\n")
    for x in thru_conf[:30]:
        L.append(f"- `{x['project']}` **{x['file']}:{x['line']}**  sink=`{x['sink']}`  [{x['tier']}]")
        L.append(f"    - {x['detail']}")
    L.append("\n## 直通 · 本模块内找不到调用方（未确认）· 抽样 10 条\n")
    for x in [x for x in thru if not x.get("callers")][:10]:
        L.append(f"- `{x['project']}` {x['file']}:{x['line']} sink=`{x['sink']}` ⇒ {x['detail']}")
    L.append("\n## 有校验（排除）· 全部\n")
    for x in [x for x in results if x["verdict"] == "有校验"]:
        L.append(f"- `{x['project']}` {x['file']}:{x['line']} sink=`{x['sink']}` ⇒ {x['detail']}")
    L.append("\n## 本地生成（排除）· 抽样 20 条\n")
    for x in [x for x in results if x["verdict"] == "本地生成"][:20]:
        L.append(f"- `{x['project']}` {x['file']}:{x['line']} sink=`{x['sink']}` ⇒ {x['detail']}")

    md = "\n".join(L) + "\n"
    open(OUT_MD, "w", encoding="utf-8").write(md)
    print(md)
    print("写出:", OUT_MD)
    print("写出:", OUT_JSON)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
