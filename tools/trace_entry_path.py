# -*- coding: utf-8 -*-
"""从 sink 往上追，追到「入口函数」，然后回答一句：**这个参数是外面给的吗？**

    python tools/trace_entry_path.py --root <靶源码根> --file mcp/work.py --line 143
    python tools/trace_entry_path.py --root ... --file ... --line ... --json out/x.json

★ 为什么要这个工具（一个老缺口，今天第四次撞到）
  判定层对「实参是 param」的候选只能说 `needs_human`：参数是传进来的，可**谁传的、传的是什么**，
  写在给定代码之外。它不是在推卸，是真的看不到。这个工具把那一段补上：
  **把「参数 ← 调用方 ← 调用方」这条路走一遍，走到带装饰器的入口就停**。

★ 与 `tools/resolve_needs_human_callers.py` 的区别（别把两个混成一个）
  那个：把调用方源码拼进 prompt **重判**（花钱），对象是 `entry`（调用链起点）。
  这个：**不调模型**，纯静态，对象是「sink 那个函数自己的参数」，并且回答一个二值问题 ——
  这些参数最终是不是从入口函数（`@mcp.tool` / 路由 / `@click.command`）的参数流下来的。

★ 三层判据，一层都不许跳（跳了就会把"内部工具函数"当成"外部可控"）：
  ① 名字要能回溯到参数（`folder = Path(directory)` 这种派生也算，见 `_tainted`）；
  ② 调用点要把实参喂给那个参数（位置或关键字对得上，见 `_arg_map`）；
  ③ 调用方本身得是入口（装饰器），不是的话继续往上一层 —— 层数有上限，用完就说"用完了"。

★ 结果只有五种，**不许有第六种含糊说法**：
  external     某条路径到达了入口，参数确实是从入口参数流下来的
  constant     往上追到了，但传的是字面量/常量（枪里没子弹）
  internal     追到了，调用方都不是入口，爬到顶也不是
  exhausted    层数用完还没到入口（**不等于不可达**，只等于没追完）
  no_caller    仓库里找不到任何调用点（死代码 / 动态派发 / 公开 API，三选一，这里分不出）
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path

# 入口装饰器：认得出这几类就够，认不出的一律当普通函数（宁可少说，不许多说）
ENTRY_DECOS = (
    ("mcp", (r"\.tool$", r"\.function$", r"^tool$")),
    ("http", (r"\.(get|post|put|delete|patch|route|websocket)$",)),
    ("cli", (r"^(command|group)$", r"\.command$", r"\.group$")),
)
SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv", "build", "dist"}


# ---------------------------------------------------------------- 基础

def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _py_files(root: Path, limit: int = 4000) -> list[Path]:
    out = []
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            if n.endswith((".py", ".pyw")):
                out.append(Path(dirpath) / n)
                if len(out) >= limit:
                    return out
    return out


def _params(fn) -> list[str]:
    a = fn.args
    return [x.arg for x in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)]


def _deco_kind(fn) -> tuple[str, str]:
    """→ (kind, 装饰器原文)。认不出给 ('', '')。

    ★ 装饰器**基本都带参数**（`@mcp.tool(annotations=...)`、`@app.post("/x")`），
      `ast.unparse` 出来尾巴上挂着一对括号。第一版正则写成 `\\.tool$`，
      于是带参数的装饰器一个都认不出 —— 而"不带参数的 tool 装饰器"几乎不存在。
      先切掉尾部调用再匹配。
    """
    import re
    for d in fn.decorator_list:
        try:
            text = ast.unparse(d)
        except Exception:                       # noqa: BLE001
            continue
        head = re.sub(r"\(.*\)\s*$", "", text, flags=re.S)
        for kind, pats in ENTRY_DECOS:
            for p in pats:
                if re.search(p, head):
                    return kind, text
    return "", ""


def _functions(tree) -> list:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _func_at(tree, line: int):
    """包含这一行的**最内层**函数。嵌套函数要取最里那个，否则参数会多出一堆用不上的。"""
    best = None
    for fn in _functions(tree):
        if fn.lineno <= line <= (getattr(fn, "end_lineno", None) or 0):
            if best is None or fn.lineno >= best.lineno:
                best = fn
    return best


def _names_on_line(tree, line: int) -> list[str]:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and getattr(n, "lineno", 0) == line:
            out.append(n.id)
    return sorted(set(out))


# ---------------------------------------------------------------- 第①层：名字能不能回溯到参数

def _tainted(fn, start_names: list[str], max_steps: int = 40) -> set[str]:
    """从 sink 行上的名字往上回溯，看哪些**函数参数**会影响它。

    `folder = Path(directory)` 这种派生要算进去 —— 否则 `open(folder / "x")` 永远追不到 `directory`。
    """
    params = set(_params(fn)) - {"self", "cls"}
    seen: set[str] = set()
    stack = list(start_names)
    steps = 0
    while stack and steps < max_steps:
        steps += 1
        nm = stack.pop()
        if nm in seen:
            continue
        seen.add(nm)
        if nm in params:
            continue
        for node in ast.walk(fn):
            value = None
            targets = []
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, (ast.AugAssign,)):
                targets, value = [node.target], node.value
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                # ★ 循环变量也是"数据从哪来"的一环：
                #   `for path in self._kept: shutil.rmtree(path)` —— 只认 `=` 赋值的话，
                #   `path` 会被当成"回溯不到任何东西"，进而被误读成常量。
                targets, value = [node.target], node.iter
            elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
                targets, value = [node.optional_vars], node.context_expr
            if value is None:
                continue
            if not any(isinstance(t, ast.Name) and t.id == nm for t in targets):
                continue
            stack.extend(x.id for x in ast.walk(value) if isinstance(x, ast.Name))
    return seen & params


# ---------------------------------------------------------------- 第②层：调用点与实参映射

class Index:
    """一次扫全仓库，建「函数名 -> 定义」「函数名 -> 调用点」两张表。"""

    def __init__(self, root: Path):
        self.root = root
        self.defs: dict[str, list[tuple[str, object]]] = {}
        self.calls: dict[str, list[tuple[str, int, object, object]]] = {}
        for p in _py_files(root):
            rel = str(p.relative_to(root)).replace("\\", "/")
            try:
                tree = ast.parse(_read(p))
            except SyntaxError:
                continue                      # 语法坏的文件跳过，别让整轮挂掉
            for fn in _functions(tree):
                self.defs.setdefault(fn.name, []).append((rel, fn))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _call_name(node)
                if not name:
                    continue
                self.calls.setdefault(name, []).append((rel, node.lineno, node, tree))

    def sig(self, name: str, prefer_file: str = "") -> list[str]:
        cands = self.defs.get(name) or []
        if not cands:
            return []
        if prefer_file:
            for rel, fn in cands:
                if rel == prefer_file:
                    return _params(fn)
        return _params(cands[0][1])


def _call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _arg_map(call: ast.Call, params: list[str]) -> dict[str, str]:
    """→ {被调函数参数名: 调用处实参的源码文本}。对不上位置的记 `?posN`。

    ★★ 方法调用时 `self` / `cls` **不占实参位**（实测踩到）：
      `self._refuse_a_held_profile(role, settings.get("profile_dir"))`
      签名是 `(self, role, directory)`、实参只有两个，按位置硬对会整体错一位 ——
      `role` 对到 `self`、`settings...` 对到 `role`，而 `directory` **根本不出现在映射里**。
      结果就是整条链在这里断掉，看着像"追不到参数"，实际是映射错位。
      `obj.method(...)` 是 `ast.Attribute`，据此判断绑定调用，去掉第一个参数再对位。
    """
    ps = list(params)
    if ps and ps[0] in ("self", "cls") and isinstance(call.func, ast.Attribute):
        ps = ps[1:]
    out: dict[str, str] = {}
    for i, a in enumerate(call.args):
        if isinstance(a, ast.Starred):
            out["*args"] = ast.unparse(a)[:80]
            continue
        key = ps[i] if i < len(ps) else "?pos%d" % i
        out[key] = ast.unparse(a)[:80]
    for kw in call.keywords:
        if kw.arg:
            out[kw.arg] = ast.unparse(kw.value)[:80]
        else:
            out["**kwargs"] = ast.unparse(kw.value)[:80]
    return out


def _expr_names(expr: str) -> list[str]:
    """把实参的源码文本拆回名字。`settings.get("profile_dir")` -> ['settings']。

    ★ 这一步不能省：`next_params` 要的是**名字**（跟 `ast.Name.id` 对得上），
      而 `_arg_map` 存的是源码文本。第一版直接拿文本去回溯，
      `settings.get('profile_dir')` 这个字符串不是任何 Name，于是永远回溯不到参数。
    """
    try:
        return [n.id for n in ast.walk(ast.parse(expr, mode="eval")) if isinstance(n, ast.Name)]
    except SyntaxError:
        return []


def _is_literal(expr: str) -> bool:
    e = expr.strip()
    if e in ("None", "True", "False", "()", "[]", "{}"):
        return True
    if len(e) >= 2 and e[0] == e[-1] and e[0] in "\"'":
        return True
    try:
        float(e)
        return True
    except ValueError:
        return False


def _arg_nature(expr: str, caller_params: set[str]) -> str:
    """一句话说清这个实参是什么。这是判定层真正需要的那一行。

    ★ 只说三档，不说第四档：**字面量 / 调用方的参数 / 未定**。
      第一版把最后一种写成"局部表达式/常量"，于是 `settings.get("profile_dir")`
      被读成常量 —— 它明明是个表达式，可能由 `profile` 参数派生。
      **把"看不懂"写成"常量"，正是这个项目一直在防的那个错。**
    """
    e = expr.strip()
    if _is_literal(e):
        return "字面量常量"
    if e in caller_params:
        return "调用方的参数"
    if e.startswith(("os.environ", "os.getenv")):
        return "环境变量"
    if e.startswith(("request.", "self.request")):
        return "HTTP 请求"
    return "未定（表达式，需要再追一层）"


# ---------------------------------------------------------------- 第③层：往上走

def _is_test(rel: str) -> bool:
    """测试文件不算调用方。

    ★ 必须排除，而且必须**数出来**（`skipped_tests`）：测试里 `profile_holder(str(tmp_path))`
      这种调用会让整件事看起来"追到常量了、枪里没子弹"，而真正的生产调用路径还挂在后面没走。
      第一版就是这么误判的 —— 4 条测试调用把 verdict 压成了 `constant`。
    """
    p = rel.lower()
    name = p.rsplit("/", 1)[-1]
    return ("/tests/" in p or p.startswith("tests/") or "/test/" in p
            or name.startswith("test_") or name.endswith("_test.py")
            or "/conftest.py" in p)


def _call_form(call: ast.Call) -> str:
    """`self.open(...)` 是 attr，`open(...)` 是 name。

    ★★ 这一维不加就会**跨文件撞名**（实测）：
      `Work.open()` 是个方法，而 `profile_holder` 里有一句内置的 `open(...)`。
      只按末段名匹配的话，这两件事被当成同一个 —— 链条从第 3 层绕回自己，
      还顺带把 `build_wiki.py` 里的 `open()` 拉了进来。
      方法只认 `obj.method(...)`，普通函数只认 `name(...)`，这一刀就够了。
    """
    return "attr" if isinstance(call.func, ast.Attribute) else "name"


# attr 形式下，这些接收者一定不是"本仓库里的那个类"。
# `os.open(...)` / `shutil.rmtree(...)` 会被末段名匹配成同名方法，纯噪声。
STD_RECEIVERS = {
    "os", "sys", "shutil", "io", "subprocess", "pathlib", "json", "tempfile", "re",
    "time", "logging", "codecs", "gzip", "zipfile", "tarfile", "socket", "urllib",
    "requests", "httpx", "aiofiles", "asyncio", "typing", "collections", "builtins",
}


def _receiver(call: ast.Call) -> str:
    """取方法调用的接收者根名：`self.a.b.open()` -> `self`。"""
    if not isinstance(call.func, ast.Attribute):
        return ""
    v = call.func.value
    while isinstance(v, ast.Attribute):
        v = v.value
    return v.id if isinstance(v, ast.Name) else ""


def _is_std_call(call: ast.Call) -> bool:
    return _receiver(call) in STD_RECEIVERS


def _known_names(tree, fn) -> set[str]:
    """已知是常量来源的名字：内置名 / import 进来的模块 / 字面量赋值的变量。"""
    import builtins
    ok = set(dir(builtins)) | {"True", "False", "None", "self", "cls"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                ok.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                ok.add(a.asname or a.name)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            try:
                if _is_literal(ast.unparse(node.value)):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            ok.add(t.id)
            except Exception:                    # noqa: BLE001
                pass
    return ok


def _constant_only(tree, fn, names: list[str]) -> bool:
    """这些名字能不能**确认**全是常量来源（import 进来的模块 / 字面量赋值 / 内置名）。

    ★ 不能确认时必须返回 False。第一版没有这一步，`tainted` 一空就下 `constant` 的结论 ——
      于是 `for path in self._kept: shutil.rmtree(path)` 被判成"枪里没子弹"，
      而 `path` 明明是个循环变量，来自实例状态，只是不在这个函数里产生。
      **"追不到"不等于"常量"，这两个必须分开。**
    """
    ok = _known_names(tree, fn)
    return not [n for n in names if n not in ok]


# 内部工厂：这些调用产出的值不可能来自外部。判成"内部生成"，跟"不知道"分开。
FACTORY_CALL = (
    "tempfile.", "uuid.", "datetime.", "time.time", "time.monotonic", "random.",
    "os.getcwd", "os.path.abspath", "os.path.realpath", "pathlib.Path", "Path(",
    "hashlib.", "secrets.token", "itertools.",
)


def _generated_only(tree, fn, names: list[str]) -> bool:
    """这些名字是不是**由内部工厂调用**赋值的（tempfile.mkdtemp() 之类）。

    ★ 与 `constant` 分开：常量是"写死的"，内部生成是"运行时造的但外面给不了"。
      两者都意味着"枪里没子弹"，但理由不同 —— 判定层读理由，不是读标签。
    """
    hits = set()
    for node in ast.walk(fn):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            # `for i in range(n)` / `enumerate(...)` 的循环变量也是内部产生的
            try:
                it = ast.unparse(node.iter)
            except Exception:                    # noqa: BLE001
                it = ""
            if it.startswith(("range(", "enumerate(", "zip(", "sorted(", "list(")):
                for t in ast.walk(node.target):
                    if isinstance(t, ast.Name):
                        hits.add(t.id)
            continue
        if not isinstance(node, ast.Assign):
            continue
        try:
            expr = ast.unparse(node.value)
        except Exception:                        # noqa: BLE001
            continue
        if not any(expr.startswith(f) or ("." + f) in expr for f in FACTORY_CALL):
            continue
        for t in node.targets:
            if isinstance(t, ast.Name):
                hits.add(t.id)
    # 只看"还没被确认为常量"的那些名字（`shutil` 这种 import 名不该拉低判断）
    rest = [n for n in names if n not in _known_names(tree, fn)]
    return bool(rest) and all(n in hits for n in rest)


def trace(root: str | Path, rel_file: str, line: int, max_depth: int = 3) -> dict:
    root = Path(root)
    p = root / rel_file
    if not p.is_file():
        return {"verdict": "no_caller", "why": "文件不存在：%s" % rel_file, "paths": []}
    try:
        tree = ast.parse(_read(p))
    except SyntaxError as exc:
        return {"verdict": "exhausted", "why": "解析失败：%s" % exc, "paths": []}

    fn0 = _func_at(tree, line)
    if fn0 is None:
        return {"verdict": "no_caller", "why": "这一行不在任何函数里（模块级）", "paths": []}

    names = _names_on_line(tree, line)
    tainted = sorted(_tainted(fn0, names))
    base = {
        "sink": {"file": rel_file, "line": line, "names_on_line": names},
        "function": {"name": fn0.name, "params": _params(fn0),
                     "decorators": [ast.unparse(d) for d in fn0.decorator_list]},
        "tainted_params": tainted,
        "paths": [],
    }
    if not tainted:
        if _constant_only(tree, fn0, names):
            base["verdict"] = "constant"
            base["why"] = ("sink 那一行用到的名字（%s）全是常量/模块名 —— 枪里没子弹"
                           % (", ".join(names) or "（空）"))
        elif _generated_only(tree, fn0, [n for n in names if n not in set(dir(__import__("builtins")))]):
            base["verdict"] = "internal_generated"
            base["why"] = ("sink 那一行用到的名字由内部工厂产生（tempfile / Path / uuid 之类）—— "
                           "运行时才有的值，外面给不了")
        else:
            base["verdict"] = "unknown"
            base["why"] = ("sink 那一行用到的名字（%s）既不是参数、也确认不了是常量 —— "
                           "来源未定（可能是实例状态或别处赋的值）"
                           % (", ".join(names) or "（空）"))
        return base

    idx = Index(root)
    paths: list[dict] = []
    verdicts: set[str] = set()
    frontier = [(rel_file, fn0, tainted, 0)]
    visited: set[tuple[str, int]] = set()

    while frontier:
        cur_file, cur_fn, cur_params, depth = frontier.pop(0)
        if depth >= max_depth:
            verdicts.add("exhausted")
            paths.append({"depth": depth, "at": "%s:%s" % (cur_file, cur_fn.lineno),
                          "status": "exhausted",
                          "note": "层数用完还没到入口（%s）" % cur_fn.name})
            continue
        callers = idx.calls.get(cur_fn.name) or []
        # 方法与普通函数分开认：`self.open(...)` 不等于内置 `open(...)`
        want = "attr" if (_params(cur_fn) or [""])[0] in ("self", "cls") else "name"
        callers = [c for c in callers if _call_form(c[2]) == want]
        std = [c for c in callers if _is_std_call(c[2])]
        if std:
            base["skipped_std_calls"] = base.get("skipped_std_calls", 0) + len(std)
        callers = [c for c in callers if not _is_std_call(c[2])]
        skipped_tests = [c for c in callers if _is_test(c[0])]
        if skipped_tests:
            base.setdefault("skipped_test_calls", 0)
            base["skipped_test_calls"] += len(skipped_tests)
        mine = [c for c in callers if not _is_test(c[0])]
        mine = [c for c in mine if c[0] == cur_file] + [c for c in mine if c[0] != cur_file]
        if not mine:
            verdicts.add("no_caller")
            paths.append({"depth": depth, "at": "%s:%s" % (cur_file, cur_fn.lineno),
                          "status": "no_caller", "note": "仓库里找不到调用 %s 的地方" % cur_fn.name})
            continue

        for cfile, cline, call, tree_c in mine:
            if (cfile, cline) in visited:
                continue
            visited.add((cfile, cline))
            caller_fn = _func_at(tree_c, cline)
            if caller_fn is None:
                continue
            sig = _params(caller_fn)
            amap = _arg_map(call, _params(cur_fn))
            # 只看"喂给了被污染参数"的那些实参
            fed = {k: v for k, v in amap.items() if k in set(cur_params)}
            if not fed:
                continue
            kind, deco = _deco_kind(caller_fn)
            step = {
                "depth": depth + 1,
                "caller": {"file": cfile, "line": cline, "function": caller_fn.name,
                           "decorators": [ast.unparse(d) for d in caller_fn.decorator_list]},
                "fed": fed,
                "arg_nature": {k: _arg_nature(v, set(sig)) for k, v in fed.items()},
            }
            if kind:
                step["status"] = "entry"
                step["entry_kind"] = kind
                step["entry_decorator"] = deco
                # 实参是不是调用方自己的参数？是才算外部可控。
                own = [k for k, v in fed.items() if v.strip() in set(sig)]
                step["from_entry_param"] = own
                verdicts.add("external" if own else "constant")
                paths.append(step)
                continue

            # 调用方不是入口：看实参能不能继续回溯到它自己的参数。
            # ★ 要先从源码文本里把名字拆出来，整串表达式回溯不到任何东西。
            next_params = _tainted(caller_fn, [n for v in fed.values() for n in _expr_names(v)])
            if not next_params:
                all_literal = all(_is_literal(v) for v in fed.values())
                step["status"] = "constant" if all_literal else "opaque"
                step["note"] = ("实参全是字面量" if all_literal
                                else "实参既不是字面量，也回溯不到调用方的参数 —— 未定")
                verdicts.add("constant" if all_literal else "unknown")
                paths.append(step)
                continue
            step["status"] = "continue"
            paths.append(step)
            frontier.append((cfile, caller_fn, sorted(next_params), depth + 1))

    base["paths"] = paths
    base["layers"] = max((p.get("depth", 0) for p in paths), default=0)
    # ★ 优先级不是随便排的：**只要还有一条路没走完，就不许下 constant 的结论**。
    #   第一版把 constant 排在 exhausted 前面，于是"4 条测试调用传了 tmp_path"把
    #   一条真正的生产路径（当年在 frontier 里还没走）压成了"枪里没子弹"。
    #   有 external 就是 external；否则有没走完的就是 exhausted；再否则才是 constant。
    for v in ("external", "exhausted", "unknown", "internal_generated",
              "constant", "no_caller", "internal"):
        if v in verdicts:
            base["verdict"] = v
            break
    else:
        base["verdict"] = "internal"
    base["why"] = {
        "external": "追到入口了，且实参就是入口函数的参数 —— 外部可控",
        "constant": "追上去了，传的全是字面量 —— 枪里没子弹",
        "internal_generated": "追上去了，值由内部工厂产生（tempfile / Path 之类）—— 外面给不了",
        "unknown": "追上去了，但实参是表达式，既不是字面量也回溯不到参数 —— **未定，不是常量**",
        "no_caller": "仓库里找不到调用点 —— 死代码 / 公开 API / 动态派发，这里分不出是哪个",
        "exhausted": "层数用完还没到入口 —— **不等于不可达**，只等于没追完",
        "internal": "追到了顶，调用方都不是入口",
    }[base["verdict"]]
    return base


# ---------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description="从 sink 往上追到入口，判断参数是不是外面给的")
    ap.add_argument("--root", required=True)
    ap.add_argument("--file", required=True,
                    help="path relative to the source root")
    ap.add_argument("--line", type=int, required=True)
    ap.add_argument("--max-depth", type=int, default=3,
                    help="往上追几层（默认 3；1 = 只看直接调用方）")
    ap.add_argument("--json", help="write the result as JSON")
    a = ap.parse_args()

    r = trace(a.root, a.file, a.line, a.max_depth)
    print("sink   %s:%s" % (r["sink"]["file"], r["sink"]["line"]))
    if r.get("function"):
        print("function %s(%s)%s" % (r["function"]["name"], ", ".join(r["function"]["params"]),
                                 ("  装饰器 " + str(r["function"]["decorators"]))
                                 if r["function"]["decorators"] else ""))
    print("tainted  %s" % (", ".join(r.get("tainted_params") or []) or "(none)"))
    print()
    for p in r.get("paths") or []:
        if p.get("status") == "entry":
            print("  [%d] -> entry %s  %s:%s  %s" % (
                p["depth"], p["entry_kind"], p["caller"]["file"], p["caller"]["line"],
                p["caller"]["function"]))
        elif p.get("caller"):
            print("  [%d] -> %s:%s  %s   （%s）" % (
                p["depth"], p["caller"]["file"], p["caller"]["line"],
                p["caller"]["function"], p["status"]))
        else:
            print("  [%d]   %s" % (p.get("depth", 0), p.get("note") or p.get("status")))
        for k, v in (p.get("fed") or {}).items():
            print("         %-12s = %-40s %s" % (k, v, (p.get("arg_nature") or {}).get(k, "")))
    print()
    print("verdict  %s - %s" % (r["verdict"].upper(), r["why"]))
    print("depth    %d / limit %d" % (r.get("layers") or 0, a.max_depth))
    if a.json:
        Path(a.json).write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n",
                                encoding="utf-8")
        print("detail   %s" % a.json)
    return 0 if r["verdict"] == "external" else 2


if __name__ == "__main__":
    sys.exit(main())
