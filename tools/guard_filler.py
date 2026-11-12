# -*- coding: utf-8 -*-
"""自动填 `guards_relevant` —— 把「这条为什么是假阳」从散文变成机器可读的一栏。

    python tools/guard_filler.py --root <src> --file <rel> --line <sink 行> [--value 变量名]

背景（这一步为什么要做）：`案卷/_试填15条_结果.md` 里 v2 的 `guards_relevant` 在 15 条上
7 条全落在假阳、`kind` 全是 `transform`，区分度看着完美 —— 但那 7 个字段是**人看着同一批数据填的**，
等于训练集考满分，不算验证。这一步把那一栏变成工具产出，才能拿新数据检验它。

★★ 三条纪律（比算法重要）：
1. **判不了就写 `unknown`，不许猜。** `verdict` 的每一种取值都要能指到一条规则；
   规则表里没有的形状一律 `unknown`，`why` 里写清"为什么判不了"。
2. **筛选靠别名族，不靠行号远近。** 一个函数里几百行，随机挑几个 if 全是噪声；
   只有操作过「危险值本身或它的上游别名」的语句才算候选。
3. **`verdict: real` 不等于「漏洞不成立」。** `float()` 让非数字抛异常是真净化，
   但抛异常本身可能是 DoS；`why` 必须把这点写出来，不许让下游读成"这条没事"。

用法上的两个坑（实测）：
  · `--value` 不给时，从 sink 调用的**所有实参名**出发（多值时逐条判，宁多不漏）；
  · 赋值链只在本函数内追 —— 跨函数的来源是 `trace_note` 的 `callers` 那一层负责的，
    这里越界去追会把「调用方传进来的」错算成「本函数转换过」。
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 规则表：判定只认这里写下的形状。表里没有的一律 unknown。
# ---------------------------------------------------------------------------

# 真净化：值被强制成受限形态，越界通常抛异常或截断。
# ★ 每条都带一句 why，因为「real」这个词很容易被下游读成「安全」。
REAL_TRANSFORMS = {
    "float": "强制成浮点，非数字直接抛 ValueError（★ 抛异常路径本身可能是 DoS，不等于无风险）",
    "int": "强制成整数，非数字直接抛 ValueError（★ 同上，且 `int(True)`/超长数字有边界）",
    "Decimal": "强制成十进制数，非法输入抛 InvalidOperation",
    "shlex.quote": "按 shell 规则转义，元字符变成字面量",
    "html.escape": "HTML 实体转义，尖括号与引号被替换",
    "quote": "URL 转义（urllib.parse.quote），分隔符被编码",
    "escape": "转义函数，需确认是 html/url 哪一类 —— 这里按 HTML 转义判",
    "dumps": "序列化成 JSON 文本，输出必然是字符串字面量",
    "json.dumps": "序列化成 JSON 文本，输出必然是字符串字面量",
    "basename": "取路径末段，`..` 与目录分隔被丢掉",
}

# 假净化：看着像在处理，其实值能原样穿过去。
BOGUS_TRANSFORMS = {
    "str": "★ `str()` 对字符串是恒等 —— 模型给的任意字符串原样进入下一环，"
           "这不是净化。只有上游本身是数字/容器时它才改变形态",
    "list": "只改容器，元素没动",
    "tuple": "只改容器，元素没动",
    "set": "只改容器（还会去重），元素没动",
    "sorted": "只改顺序，元素没动",
    "strip": "只去首尾空白，中间的元字符全在",
    "lstrip": "只去左侧空白",
    "rstrip": "只去右侧空白",
    "lower": "只改大小写，字符集没变",
    "upper": "只改大小写，字符集没变",
    "replace": "逐字符替换，是否安全取决于被替换的字符集 —— 一般不足以净化",
    "format": "格式化只拼字符串，不改变其中已有的内容",
    "join": "拼接只合并字符串，不转义任何部分",
    "abspath": "★ 只做绝对化，`..` 依然被解析穿过",
    "normpath": "★ 只做规范化，`..` 照样能穿出目标目录",
    "realpath": "★ 只解符号链接，不限制最终落在哪",
    "copy": "复制对象，值原样保留",
    "deepcopy": "复制对象，值原样保留",
}

# 只判存在性/可访问性的条件函数：看着像检查，其实一个字符都不管。
# ★ CASE-0001 里 `if os.path.isfile(file_path)` 就是这一类 —— 它只问"这个路径存在吗"，
#   `../../etc/passwd` 存在，所以它返回真、照样读出去。这正是那条假守卫的判据。
BOGUS_IF_CALLS = {
    "isfile": "只判是否为已存在的文件，不管路径落在哪 —— 穿越出来的路径只要存在就通过",
    "isdir": "只判是否为目录，同样不管落在哪",
    "exists": "只判存在性，不限制位置",
    "islink": "只判是否为符号链接，不限制指向",
    "lexists": "只判存在性（含失效链接），不限制位置",
    "access": "只判权限位，不限制路径位置",
    "startswith_ok": "",                       # 占位，见 WHITELIST_CALLS
}

# 只判存在性/真假的条件：不约束值的内容。
BOGUS_IFS = (
    "只判存在性或真值，不约束内容",
)

# 类型约束类条件：能真挡住一部分输入。
REAL_IF_KINDS = ("isinstance", "type")

# 白名单纯函数。
WHITELIST_CALLS = ("fullmatch", "match", "startswith", "endswith", "isdigit", "isalnum")

MAX_ROWS = 6
MAX_PATH_DEPTH = 8


def _call_name(node: ast.AST) -> str:
    """取调用的可读名字：`os.path.join` → `join`，`Foo.bar()` → `bar`。"""
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _full_name(node: ast.AST) -> str:
    """取完整点号名，用于在 why 里引用原文。"""
    if isinstance(node, ast.Attribute):
        base = _full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _full_name(node.func) + "()"
    return ast.unparse(node) if hasattr(ast, "unparse") else ""


def _names_in(node: ast.AST) -> set[str]:
    """一个表达式中出现的所有 Name（含属性链的根名字）。"""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
    return out


def _enclosing_func(tree: ast.AST, line: int) -> ast.AST | None:
    """最内层包含该行的函数。"""
    best, best_span = None, None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo = node.lineno
            hi = getattr(node, "end_lineno", lo) or lo
            if lo <= line <= hi:
                span = hi - lo
                if best_span is None or span < best_span:
                    best, best_span = node, span
    return best


def _sink_call(func: ast.AST, line: int) -> ast.Call | None:
    """定位 sink 行上的那个调用表达式（同行可能有多个，取**最内层**的那个）。

    ★★ 不能按行跨度取最小来选。`open(p).read()` 的两个调用都在同一行、跨度都是 0，
      而 `ast.walk` 是 BFS，会**先**给出外层的 `read()` —— 它没有实参，
      于是 seeds 空、整条候选被判成「实参里没有可追踪的变量名」。
      实测就是这么错的：`exist_only` 那条一个守卫都报不出来。
      正确判据是「不包含任何其它候选」= 最内层。
    """
    cands: list[ast.Call] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        lo = node.lineno
        hi = getattr(node, "end_lineno", lo) or lo
        if lo <= line <= hi:
            cands.append(node)
    if not cands:
        return None
    inner = [c for c in cands
             if not any(c is not o and any(sub is o for sub in ast.walk(c)) for o in cands)]
    if not inner:
        return cands[-1]
    # 仍可能并列（同一行两棵不相交的子树），取实参多的那个
    inner.sort(key=lambda c: -len(_arg_exprs(c)))
    return inner[0]


def _arg_exprs(call: ast.Call) -> list[tuple[int, ast.AST]]:
    """sink 调用的实参，带位置下标（关键字参数给 -1..-n 之后的值没用，用名字代替）。"""
    out: list[tuple[int, ast.AST]] = []
    for i, a in enumerate(call.args):
        out.append((i, a))
    for kw in call.keywords:
        if kw.arg:
            out.append((-1, kw.value))
    return out


def _alias_family(func: ast.AST, seeds: set[str]) -> dict[str, int]:
    """从种子变量往上做传递闭包：`x = y` 让 y 也进族。

    返回 {变量名: 最早出现的行}，用于后面筛「哪些语句碰过这族值」。
    ★ 只做**同向**传播（`x = <表达式含 y>`），不做反向 —— 反向会把
      「结果是 y 算出来的」错当成「y 来自 x」。
    """
    family = {s: 10 ** 9 for s in seeds}
    changed = True
    rounds = 0
    while changed and rounds < MAX_PATH_DEPTH:
        changed, rounds = False, rounds + 1
        for node in ast.walk(func):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            targets = []
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = ([node.target] if node.target else []), node.value
            else:
                targets, value = [node.target], node.value
            if value is None:
                continue
            rhs_names = _names_in(value)
            lhs_names = set()
            for t in targets:
                lhs_names |= _names_in(t)
            if rhs_names & set(family):
                for name in lhs_names:
                    if name not in family:
                        family[name] = node.lineno
                        changed = True
    return family


def _transform_verdict(call: ast.Call) -> tuple[str, str]:
    """转换语句的 verdict。"""
    name = _call_name(call)
    full = _full_name(call.func)
    # 绝对名优先（json.dumps vs dumps）
    if full in REAL_TRANSFORMS:
        return "real", REAL_TRANSFORMS[full]
    if name in REAL_TRANSFORMS:
        return "real", REAL_TRANSFORMS[name]
    if name in BOGUS_TRANSFORMS:
        return "bogus", BOGUS_TRANSFORMS[name]
    return "unknown", (
        f"`{name or '?'}()` 不在净化函数规则表里，无法判断它是否让值受约束"
        f"（要么补进 tools/guard_filler.py 的规则表并写明依据，要么维持 unknown）")


def _binop_verdict(node: ast.BinOp) -> tuple[str, str] | None:
    """拼接/算术。固定前缀拼接是真净化，纯算术对字符串没意义、对数字不改变可控性。"""
    if isinstance(node.op, ast.Add):
        left_is_const = isinstance(node.left, ast.Constant)
        right_is_const = isinstance(node.right, ast.Constant)
        if left_is_const or right_is_const:
            return ("real",
                    "与字面量拼接：结果必然是「固定前缀/后缀 + 原值」的形状，"
                    "原值不可能单独成为一个完整表达式（★ 但值本身没被转义，仍可能注入到拼接目标里）")
        return "unknown", "两段都不是字面量的拼接，看不出哪一段可控"
    if isinstance(node.op, (ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)):
        return "unknown", "算术运算：对数字会改变值域但不限制来源，对字符串多为非法或重复"
    return None


def _if_verdict(test: ast.AST) -> tuple[str, str]:
    """条件语句的 verdict。只认几种能说清的形状，其余 unknown。"""
    # `if not <条件>:` —— 反向写法。★ 不能一律当"只判真假"：
    # `if not isinstance(x, str): return` 是**类型约束**（提前返回的写法），
    # 判成 bogus 会把真守卫说成假守卫。所以要递归进去看那个条件本身。
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        v, why = _if_verdict(test.operand)
        return v, (why + "（以 `not ...` 反向写出，提前返回；判据同正向）" if v != "bogus"
                   else why)
    inner = test
    if isinstance(inner, ast.Name):
        return "bogus", BOGUS_IFS[0]
    # 比较：x is None / x in WHITELIST / x < 100
    if isinstance(inner, ast.Compare):
        for op in inner.ops:
            if isinstance(op, (ast.In, ast.NotIn)):
                right = inner.comparators[0] if inner.comparators else None
                if isinstance(right, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                    return ("real", "成员测试对字面量白名单：不在集合里的值被拒")
                if isinstance(right, ast.Name):
                    return ("unknown",
                            f"成员测试对变量 `{right.id}`：是不是白名单取决于那个变量在哪定义，这里看不到")
                return "unknown", "成员测试的被测对象形状不认识"
            if isinstance(op, (ast.Is, ast.IsNot)):
                return "bogus", "只判是否为 None/同一对象，不约束内容"
            if isinstance(op, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
                return "unknown", "大小比较：可能挡住一部分值，但看不出是否覆盖危险区间"
        if len(inner.ops) == 1 and isinstance(inner.ops[0], ast.Eq):
            return ("bogus",
                    "等值比较只挡一个特定值/一种形状，不构成净化 —— 换一个值就穿过去")
    # 调用类：isinstance / re.match / str.isdigit / os.path.isfile ...
    if isinstance(inner, ast.Call):
        name = _call_name(inner)
        if name in REAL_IF_KINDS:
            return ("real",
                    "类型判断：挡掉非目标类型的值（★ `isinstance(True, int)` 为真，布尔要单独看）")
        if name in BOGUS_IF_CALLS and BOGUS_IF_CALLS[name]:
            return "bogus", BOGUS_IF_CALLS[name]
        if name in WHITELIST_CALLS:
            return ("unknown",
                    f"`{name}()` 是否构成白名单，取决于传给它的模式/前缀 —— 而模式多半是变量，这里看不到")
    return "unknown", "条件形状不在规则表里，判不出是否约束了值的内容"


def _iter_guards(func: ast.AST, family: set[str], sink_line: int, sink_node=None):
    """遍历函数内所有碰过这族值的语句，产出 (行号, kind, 节点, 变量名, 方向)。

    ★★ 两个方向都要收，这是踩过才知道的：
      - `upstream`：sink **之前**，值被净化了吗；
      - `downstream`：sink **之后**，这个危险动作的结果被校验/限制了吗。

      为什么必须有 downstream：CASE-0001 里 CodeQL 报的 sink 是 `os.path.join`（`:1609`，
      它是"入口"不是"终点"），真正的危险在 `:1611` 的 `FileResponse`，
      而唯一的校验是 `:1610` 的 `if os.path.isfile(...)` —— **在 sink 之后**。
      第一版只做上游，于是这条案卷一个守卫都找不到、还显得"没有防护记录"，
      而它其实有一个（假）守卫，正好是判假阳的依据。

    ★ 仍然跳过 `lineno == sink_line` 且节点包含 sink 调用的那种（sink 行自身不是自己的守卫）。
    """
    def _is_sink_self(node) -> bool:
        if sink_node is None or node.lineno != sink_line:
            return False
        for sub in ast.walk(node):
            if sub is sink_node:
                return True
        return False

    for node in ast.walk(func):
        if isinstance(node, (ast.If, ast.While)):
            if _is_sink_self(node):
                continue
            hit = _names_in(node.test) & family
            if hit:
                yield (node.lineno, "if", node.test, sorted(hit)[0],
                       "upstream" if node.lineno < sink_line else "downstream")
        elif isinstance(node, ast.Assert):
            if _is_sink_self(node):
                continue
            hit = _names_in(node.test) & family
            if hit:
                yield (node.lineno, "if", node.test, sorted(hit)[0],
                       "upstream" if node.lineno < sink_line else "downstream")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if _is_sink_self(node):
                continue
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            lhs = set()
            for t in targets:
                lhs |= _names_in(t)
            if not (lhs & family):
                continue
            if isinstance(value, ast.Call):
                yield (node.lineno, "transform", value, sorted(lhs & family)[0],
                       "upstream" if node.lineno < sink_line else "downstream")
            elif isinstance(value, ast.BinOp):
                yield (node.lineno, "transform", value, sorted(lhs & family)[0],
                       "upstream" if node.lineno < sink_line else "downstream")
            elif isinstance(value, (ast.List, ast.Tuple)):
                yield (node.lineno, "transform", value, sorted(lhs & family)[0],
                       "upstream" if node.lineno < sink_line else "downstream")


def _why_expr(node: ast.AST) -> str:
    try:
        text = ast.unparse(node)
    except Exception:                                    # noqa: BLE001
        text = type(node).__name__
    return " ".join(text.split())[:110]


def fill(root, rel: str, line: int, values=None) -> dict:
    """填一条候选的 guards_relevant。返回 dict，可直接进案卷。"""
    result = {
        "guards_total": 0,
        "guards_relevant": [],
        "unresolved": [],
        "skill": "static",
        "why_empty": "",
    }
    path = Path(root) / rel
    if not path.is_file():
        result["error"] = f"源文件不存在：{path}"
        return result
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except SyntaxError as exc:
        result["error"] = f"解析失败（{exc.msg}，第 {exc.lineno} 行）"
        return result

    # ★ 先把 import 进来的名字收出来：`os.path.join(...)` 里的 `os` 会被 `_names_in` 当成变量，
    #   于是 seeds = {'os'}、family = {'os'}，一个守卫都追不到（trulens 那条实测）。
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for al in node.names:
                imported.add((al.asname or al.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                imported.add(al.asname or al.name)

    func = _enclosing_func(tree, line)
    if func is None:
        # 模块级代码：把整个文件当作用域，但明确标注
        func = tree
        result["scope"] = "module"
    else:
        result["scope"] = getattr(func, "name", "?")

    call = _sink_call(func, line) if isinstance(func, ast.AST) else None
    seeds: set[str] = set()
    attr_seeds: set[str] = set()
    if values:
        seeds |= set(values)
    if call is not None:
        for _, expr in _arg_exprs(call):
            # ★ 不能只看 `ast.Name`：实参常常是 f-string / 拼接 / 属性链。
            #   trulens `beir_loader.py:280` 的实参是
            #   `f"rm -rf {os.path.join(self.data_folder, self.dataset_name)}"`，
            #   第一版只认 Name，于是 seeds 空、整条报"没有可追踪的变量名"。
            if isinstance(expr, ast.Name):
                if expr.id not in imported:
                    seeds.add(expr.id)
            elif isinstance(expr, (ast.Attribute, ast.Subscript, ast.JoinedStr, ast.BinOp)):
                seeds |= {n for n in _names_in(expr) if n not in ("self", "cls") and n not in imported}
                # `self.data_folder` 里的 `data_folder` 不是 Name 节点，单独收出来
                for sub in ast.walk(expr):
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                            and sub.value.id in ("self", "cls"):
                        attr_seeds.add(sub.attr)
    if attr_seeds:
        # ★ 实例属性在本函数内**看不到赋值**（来源在 `__init__` 或更外层）。
        #   这里如实记成 unresolved，不假装追到了 —— 这正是第四步暴露的能力边界。
        result["unresolved"].append(
            "实参里有实例属性（%s）：它们的赋值在本函数之外（通常是 `__init__`），"
            "本工具只看当前函数，看不到来源。要追得用 `tools/trace_note.py` 的 callers。"
            % "、".join("`self.%s`" % a for a in sorted(attr_seeds)))
    if not seeds and not attr_seeds:
        result["why_empty"] = "sink 调用的实参里没有可追踪的变量名（全是字面量或复杂表达式）"
        return result
    if not seeds:
        # 只有实例属性、没有局部变量时，别急着返回：属性名仍可当"这族值"的线索去匹配
        seeds = set(attr_seeds)

    family = _alias_family(func, seeds)
    # guards_total：函数内所有条件 + 所有赋值转换，作为「工具报了多少」的基数
    total = 0
    for node in ast.walk(func):
        if isinstance(node, (ast.If, ast.While, ast.Assert)):
            total += 1
    result["guards_total"] = total

    rows, seen = [], set()
    for lineno, kind, node, var, direction in _iter_guards(func, set(family), line, call):
        key = (lineno, kind)
        if key in seen:
            continue
        seen.add(key)
        if kind == "if":
            verdict, why = _if_verdict(node)
        elif isinstance(node, ast.Call):
            verdict, why = _transform_verdict(node)
        elif isinstance(node, ast.BinOp):
            got = _binop_verdict(node)
            if got is None:
                continue
            verdict, why = got
        elif isinstance(node, (ast.List, ast.Tuple)):
            verdict, why = ("real",
                            "被装进列表/元组字面量：输出必然是 `[...]` 形状，"
                            "原值不可能单独成为一个完整表达式")
        else:
            continue
        # ★ schema v2 的 guards_relevant.items 是 additionalProperties:false，没有 direction 这一栏。
        #   所以方向只能并进 why 的开头（`[上游]` / `[下游]`）——**这是塞不进去的一处，不是设计得对**。
        #   要正式区分就得升 v3，这一条已记入 `案卷/_guard_filler_实测.md`。
        tag = "[上游] " if direction == "upstream" else "[下游] "
        rows.append({
            "location": f"{rel}:{lineno}",
            "kind": kind,
            "constrains_value": var,
            "verdict": verdict,
            "why": tag + why,
            "expression": _why_expr(node),
            "direction": direction,          # ← 工具内部字段，写进案卷前会被剔掉（schema 不认）
        })

    # 排序：real 优先（下游最该先看），再上游优先（管的是输入），最后按行号倒序（离 sink 近）
    order = {"real": 0, "bogus": 1, "unknown": 2}
    rows.sort(key=lambda r: (order.get(r["verdict"], 3),
                             0 if r["direction"] == "upstream" else 1,
                             -int(r["location"].rsplit(":", 1)[1])))
    if len(rows) > MAX_ROWS:
        result["unresolved"].append(
            f"相关语句共 {len(rows)} 条，只列前 {MAX_ROWS} 条（按 real 优先 + 距 sink 由近到远）")
        rows = rows[:MAX_ROWS]
    result["guards_relevant"] = rows
    result["unresolved"].append(
        "同一行内的嵌套转换（如 `exec(str(x))` 里的 `str`）未纳入 —— "
        "同行可能有多个调用，猜哪个是 sink 的输入容易错，所以整行跳过")
    if not rows:
        result["why_empty"] = (
            "在这条路径上没有找到操作过该值的条件或转换语句 —— "
            "★ 这**不等于**没有守卫，可能是值在本函数里没被再赋值（来源在调用方）")
    result["seeds"] = sorted(seeds)
    return result


def to_case_shape(filled: dict) -> dict:
    """转成 `_schema_v2.json` 认得的形状（`guards_relevant.items` 是 additionalProperties:false）。

    ★ 会剔掉 `direction` 和 `expression` 两个工具内部字段 —— 它们有用，但 v2 装不下。
      这不是"顺手加个可选字段"能解决的：`additionalProperties:false` 就是不许加。
      要么升 v3，要么把方向并进 `why`（本工具采用后者，`[上游]`/`[下游]` 前缀）。
    """
    keep = ("location", "kind", "constrains_value", "verdict", "why")
    return {
        "guards_total": filled.get("guards_total", 0),
        "guards_relevant": [
            {k: r[k] for k in keep if k in r} for r in filled.get("guards_relevant", [])
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="自动填 guards_relevant（静态，只看源码窗口）")
    ap.add_argument("--root", required=True, help="source root")
    ap.add_argument("--file", required=True,
                    help="file the candidate is in, relative to root")
    ap.add_argument("--line", type=int, required=True, help="line number of the sink")
    ap.add_argument("--value", action="append", default=None,
                    help="危险实参的变量名，可给多次；不给则从 sink 调用实参自动取")
    ap.add_argument("--for-case", action="store_true",
                    help="只输出 schema v2 认得的字段（去掉 direction/expression），可直接填进案卷")
    ap.add_argument("--out", help="write the result as JSON")
    a = ap.parse_args()

    out = fill(a.root, a.file, a.line, a.value)
    if a.for_case:
        out = to_case_shape(out)
    text = json.dumps(out, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {a.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
