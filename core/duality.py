# -*- coding: utf-8 -*-
"""内核 · 第 9 条规则（duality）：「同一函数里两种等价写法并存」

★ The standalone runner lives in `tools/duality_scan.py`.
  ` The strong/weak-form checks used to live outside the pipeline; this module brings them back in.

★ 它是**候选生成器**，不是判定器：
  「同一个函数里，强写法（参数化 / literal_eval / basename…）与弱写法
   （f-string 拼接 / eval / 直接 join…）同时出现」→ 弱的那处可疑。
  真正的判定仍归 LLM 判定层（四层规则）。

★★ 新增「常量 / 净化过滤」：
  measured on new targets, the 12 hits reported**全是误报**，原因**完全一致**：
  被内插的值要么是**常量**（`__init__` 里的表名字面量），要么**已被上游净化**
  （`re.sub("[^A-Za-z0-9_-]", "_", x)`）。it only looks at local inconsistency，
  不看那个值是什么 —— 这里补上：解析弱写法里的实参，能证成「常量/净化返回值」→ 丢掉。

★ 实现说明：判定**直接在 AST 上做**(not by regex on unparsed lines, as the older script did)——
  因为多行调用（`execute(\n "...",\n params)`）在源码里跨行，行正则匹配不到强写法。
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from core import finding as F

DESC = {
    "eval_safe": "literal_eval（安全）vs eval（可执行任意代码）",
    "exec_safe": "ast.parse（安全）vs exec",
    "sql": "参数化 execute(sql, params) vs execute(f-string) 拼接",
    "shell_on": "shell=False（安全）vs shell=True",
    "tls_verify_off": "证书校验开 vs 关（verify=False / CERT_NONE）",
    "path_join": "basename 清洗 vs 直接 join 用户输入",
    "pickle": "json.loads vs pickle.loads",
    "yaml": "yaml.safe_load vs yaml.load",
    "client_base_url": "SDK 客户端构造的 base_url 是**非常量**（可被指向任意主机 → SSRF/凭据转发）",
}
CAT_SINK = {
    "eval_safe": "eval", "exec_safe": "exec", "sql": "execute",
    "shell_on": "subprocess(shell=True)", "tls_verify_off": "requests(verify=False)",
    "path_join": "os.path.join", "pickle": "pickle.loads", "yaml": "yaml.load",
    "client_base_url": "client(base_url=…)",
}
TEST_PATH = re.compile(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                       r"benchmarks?|docs?)(/|$)", re.I)
TEST_NAME = re.compile(r"(^test_|_test\.py$|^conftest\.py$|^mock_|_mock\.py$)", re.I)
# ★ 夹带代码（第三方副本 / 构建产物）——必须丢，否则扫到 site-packages 里的
#   torch / transformers / setuptools，证据全都被污染（对照 core/surface.py 的 VENDOR_MARKS）。
_VENDOR = re.compile(r"(^|/)(\.git|\.venv|venv|node_modules|vendor|third[_-]?party|"
                     r"site-packages|dist|build|__pycache__|miniconda3?|anaconda3?|"
                     r"\.tox|eggs)(/|$)", re.I)
_SANITIZER = re.compile(
    r"(sub|subn|replace|quote|unquote|escape|sanit|_safe|basename|normalize|"
    r"validate|whitelist|allowlist|allow|clean|scrub|strip|sha\d*)$", re.I)
# ★ Python 常量命名约定：全大写（可带下划线前缀）→ 视为常量。
#   为什么需要：`from .x import Y as _Z` 这类**import 进来的常量**，本文件里没有赋值，
#   作用域表看不到（实测漏掉 memora 的 `_IMPORT_MARKER_KEY`）。
_UPPER = re.compile(r"^_?[A-Z][A-Z0-9_]*$")


# ─────────────────────────── AST 小工具 ───────────────────────────
def _attr_name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = _attr_name(node.value)
        return f"{b}.{node.attr}" if b else node.attr
    return None


def _kwarg(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _calls_in(fn):
    """收集 fn 内的 Call 节点（不下降进嵌套函数/lambda —— 否则作用域会串）。"""
    out = []

    def rec(n):
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(c, ast.Call):
                out.append(c)
            rec(c)
    rec(fn)
    return out


# ─────────────────────────── 检测 ───────────────────────────
def _detect(calls):
    """→ {cat: (weak_calls, strong_calls)}"""
    d: dict[str, tuple[list, list]] = {k: ([], []) for k in DESC}
    for c in calls:
        nm = _attr_name(c.func) or ""
        tail = nm.split(".")[-1]
        a0 = c.args[0] if c.args else None
        if tail == "eval" and not nm.endswith("literal_eval"):
            d["eval_safe"][0].append(c)
        if tail == "literal_eval":
            d["eval_safe"][1].append(c)
        if tail == "exec":
            d["exec_safe"][0].append(c)
        if nm.endswith("ast.parse"):
            d["exec_safe"][1].append(c)
        if tail in ("execute", "executemany", "executescript"):
            if isinstance(a0, ast.JoinedStr):
                d["sql"][0].append(c)
            elif len(c.args) >= 2 or (isinstance(a0, ast.Constant)
                                      and isinstance(a0.value, str) and "%s" in a0.value):
                d["sql"][1].append(c)
        v = _kwarg(c, "shell")
        if isinstance(v, ast.Constant) and isinstance(v.value, bool):
            d["shell_on"][0 if v.value else 1].append(c)
        v = _kwarg(c, "verify")
        if isinstance(v, ast.Constant) and isinstance(v.value, bool):
            d["tls_verify_off"][0 if v.value is False else 1].append(c)
        elif isinstance(v, ast.Attribute) and v.attr == "CERT_NONE":
            d["tls_verify_off"][0].append(c)
        elif isinstance(v, ast.Attribute) and v.attr == "CERT_REQUIRED":
            d["tls_verify_off"][1].append(c)
        if _kwarg(c, "ssl_context") is not None:
            d["tls_verify_off"][1].append(c)
        if nm.endswith("os.path.join") and any(
                isinstance(a, ast.Name) and re.search(r"user|input|name|file", a.id, re.I)
                for a in c.args[1:]):
            d["path_join"][0].append(c)
        if nm.endswith("basename"):
            d["path_join"][1].append(c)
        if tail in ("load", "loads") and "pickle" in nm:
            d["pickle"][0].append(c)
        if tail in ("load", "loads") and "json" in nm:
            d["pickle"][1].append(c)
        if tail == "safe_load" and "yaml" in nm:
            d["yaml"][1].append(c)
        elif tail == "load" and "yaml" in nm:
            d["yaml"][0].append(c)
    return d


def _suspects(cat, call):
    """弱写法里「被怀疑的值」表达式列表（用于常量/净化过滤）。"""
    a0 = call.args[0] if call.args else None
    if cat in ("eval_safe", "exec_safe", "pickle", "yaml"):
        return list(call.args[:1])
    if cat == "sql":
        if isinstance(a0, ast.JoinedStr):
            return [v.value for v in a0.values if isinstance(v, ast.FormattedValue)]
        return []
    if cat == "path_join":
        return list(call.args[1:])
    return []                                # shell_on / tls：逻辑值，无值可判


# ─────────────────────── 常量/净化过滤 ───────────────────────
def _classify(expr, scope, mod, seen) -> str:
    """'const' | 'sanitized' | 'other'"""
    if expr is None:
        return "other"
    if isinstance(expr, ast.Constant):
        return "const"
    if isinstance(expr, ast.Name):
        if expr.id in seen:
            return "other"
        rhs = scope.get(expr.id, mod.get(expr.id))
        if rhs is not None:
            return _classify(rhs, scope, mod, seen | {expr.id})
        if _UPPER.match(expr.id):        # 常量命名约定（含 import 进来的常量）
            return "const"
        return "other"
    if isinstance(expr, ast.Attribute):
        return "other"
    if isinstance(expr, ast.Call):
        nm = _attr_name(expr.func) or ""
        tail = nm.split(".")[-1]
        if _SANITIZER.search(tail):
            return "sanitized"
        # ★ `','.join('?' for _ in batch)`：接收者是字符串常量、元素也是常量
        #   → 整串仍是常量（实测漏掉 memora 的 `IN (?,?,…)` 占位符）。
        if tail == "join" and isinstance(expr.func, ast.Attribute) \
                and isinstance(expr.func.value, ast.Constant) and len(expr.args) == 1:
            it = expr.args[0]
            elt = it.elt if isinstance(it, (ast.GeneratorExp, ast.ListComp)) else None
            if elt is not None and _classify(elt, scope, mod, seen) == "const":
                return "const"
        res = [_classify(a, scope, mod, seen) for a in expr.args]
        return "const" if res and all(r == "const" for r in res) else "other"
    if isinstance(expr, ast.JoinedStr):
        vals = [v.value for v in expr.values if isinstance(v, ast.FormattedValue)]
        if not vals:
            return "const"
        res = [_classify(v, scope, mod, seen) for v in vals]
        return ("const" if all(r == "const" for r in res)
                else "sanitized" if all(r in ("const", "sanitized") for r in res)
                else "other")
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        res = [_classify(expr.left, scope, mod, seen),
               _classify(expr.right, scope, mod, seen)]
        return ("const" if all(r == "const" for r in res)
                else "sanitized" if all(r in ("const", "sanitized") for r in res)
                else "other")
    if isinstance(expr, (ast.List, ast.Tuple)):
        res = [_classify(e, scope, mod, seen) for e in expr.elts]
        return "const" if res and all(r == "const" for r in res) else "other"
    return "other"


def _scope(fn):
    m = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    m[t.id] = n.value
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            m[n.target.id] = n.value
    return m


def _module_scope(tree):
    m = {}
    for n in tree.body:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    m[t.id] = n.value
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            m[n.target.id] = n.value
    return m


def classify_suspects(suspects, fn, tree) -> str | None:
    if not suspects:
        return None
    scope = _scope(fn) if fn is not None else _module_scope(tree)
    mod = _module_scope(tree)
    kinds = [_classify(e, scope, mod, set()) for e in suspects]
    if all(k == "const" for k in kinds):
        return "被内插值是常量"
    if all(k in ("const", "sanitized") for k in kinds):
        return "被内插值已被上游净化"
    return None


# ★★ 「SDK 客户端构造参数」这一类 —— 补的是**已知真值自测暴露的缺口**：
#   SampleSDK 那条真漏洞是 `AsyncOpenAI(api_key=…, base_url=<请求头>)` —— SSRF **发生在客户端构造**
#   而不是 `requests.get(url)`，所以 sink 表（按调用名匹配）**天生认不出它**。
#   这里用 AST 判：**任何带 base_url / api_base 关键字实参、且该值不是常量**的调用 → 候选。
#   ★ 常量 base_url（写死的官方地址）会被 `_classify` 判成 const → 自动过滤，噪声可控。
_BASEURL_KWS = ("base_url", "api_base", "base_url_override")


def _client_base_hits(fn, tree, mod):
    """→ [(lineno, snippet, kwname)]：带非常量 base_url 的调用。"""
    scope = _scope(fn)
    out = []
    for c in _calls_in(fn):
        for k in c.keywords:
            if k.arg in _BASEURL_KWS and _classify(k.value, scope, mod, set()) == "other":
                out.append((c.lineno, k.arg))
    return out

def scan_file(_path: str, src: str) -> list[dict]:
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    lines = src.splitlines()
    mod = _module_scope(tree)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        det = _detect(_calls_in(fn))
        seen_ln = set()
        for cat, (weak, strong) in det.items():
            if not weak or not strong:
                continue
            for c in weak:
                if c.lineno in seen_ln:
                    continue
                seen_ln.add(c.lineno)
                line = lines[c.lineno - 1].strip()[:160] if 0 < c.lineno <= len(lines) else ""
                susp = _suspects(cat, c)
                out.append({
                    "cat": cat, "desc": DESC[cat], "func": fn.name,
                    "start": fn.lineno, "end": getattr(fn, "end_lineno", fn.lineno) or fn.lineno,
                    "weak_at": [c.lineno], "strong_at": [s.lineno for s in strong[:4]],
                    "weak_code": [line],
                    "strong_code": [lines[s.lineno - 1].strip()[:160]
                                    for s in strong[:3] if 0 < s.lineno <= len(lines)],
                    "_filter": classify_suspects(susp, fn, tree),
                })
        # ★ 第二类：SDK 客户端构造里的非常量 base_url（补自测暴露的缺口）
        #   ★★ 默认**关**（`AF_DUALITY_SDK=1` 才开）：实测全语料会加 **297 条** ——
        #     因为"自定义 base_url"在 LLM 框架里极其常见（本地模型/代理），绝大多数是正常配置。
        #     它只在"base_url 来自不可信来源（请求头/LLM 产出）"时才是洞 —— 那要交给
        #     实参来源（dataflow）+ 判定层，不能靠"非常量"一刀切。见 。
        if os.environ.get("AF_DUALITY_SDK", "0") == "1":
            for ln, kwn in _client_base_hits(fn, tree, mod):
                if ln in seen_ln:
                    continue
                seen_ln.add(ln)
                line = lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else ""
                out.append({
                    "cat": "client_base_url",
                    "desc": DESC["client_base_url"],
                    "func": fn.name, "start": fn.lineno,
                    "end": getattr(fn, "end_lineno", fn.lineno) or fn.lineno,
                    "weak_at": [ln], "strong_at": [],
                    "weak_code": [line], "strong_code": [],
                    "_filter": None,
                })
    return out


def scan_dir(src_root, project: str, on_log=None) -> list[F.Finding]:
    root = Path(src_root)
    if not root.exists():
        if on_log:
            on_log(f"[duality] {project}: 源码目录不存在 {root}")
        return []
    kept, filtered, n_files, n_raw = [], 0, 0, 0
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root).as_posix()
        if TEST_PATH.search(rel) or TEST_NAME.search(p.name) or _VENDOR.search(rel):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        n_files += 1
        for h in scan_file(str(p), src):
            n_raw += 1
            if h.get("_filter"):
                filtered += 1
                continue
            sink = CAT_SINK.get(h["cat"], h["cat"])
            snippet = h["weak_code"][0] if h["weak_code"] else ""
            chain = (f"{h['func']}@{p.name}:{h['start']}-{h['end']} "
                     f"弱[{h['cat']}] {h['weak_at']} vs 强 {h['strong_at']}")
            kept.append(F.Finding(
                project=project,
                fingerprint=F.make_fingerprint(project, rel, sink, snippet),
                rule="duality", sink_func=sink, sink_uri=rel,
                sink_line=h["weak_at"][0], entry=h["func"], depth=0,
                snippet=snippet, chain=chain, src_root=str(root),
            ))
    if on_log:
        on_log(f"[duality] {project}: {n_files} 文件 → 原始 {n_raw} 处，"
               f"保留 {len(kept)} 条，按「常量/已净化」滤掉 {filtered} 条")
    return kept


if __name__ == "__main__":
    import sys
    for x in scan_dir(sys.argv[1], "demo", on_log=print):
        print(f"  {x.sink_uri}:{x.sink_line}  {x.sink_func}  {x.snippet[:100]}")
