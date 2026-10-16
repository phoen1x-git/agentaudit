#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
轻量污点追踪：判断一个变量「值从哪来」
========================================

要解决什么
----------
判「外部输入直落危险点」时，光看变量名不够。实测踩过两次：

| 场景 | 变量名 | 真实来源 | 结论 |
|---|---|---|---|
| one SDK 真漏洞 | `runtime_params["base_url"]` | `request.headers.get("base_url")` | ★ 是外部输入 |
| one SDK 误报 | `base_url`（函数形参） | 服务端自己的配置 | ★ 不是 |
| reagent 误报 | `api_key`（函数形参） | 环境变量/配置 | ★ 不是 |

**名字长得一样，来源完全不同。**

★ 这已经是同一个病的第 N 次发作（pexpect 漏词/ samplesdk 漏词 /
  auth_header 漏词 / 形参名误伤 / 中转变量误伤）——
**根因都是「靠名字判断，而不是靠数据流」**。

所以这里做真正的追踪：**在函数体内回溯这个变量的赋值链**，
看它最终是不是来自 `request.*` / `request.headers` / `ctx.*` 之类。

★ 为什么不做完整的跨函数污点分析：
   代价大、容易出false positive，而且本项目的目标是**筛出值得人工看的点**，
   不是精确判定。只要在本函数内追一层就能分开上面那两类，
   剩下的交人工 —— 这与「探针给的是线索不是结论」一致。

边界（必须写清楚）
----------------
  - 只在**单个函数内**追踪，不跨函数
  - 追不到时返回「不确定」，由调用方按可疑处理（宁可多报）
  - 追到 `request.*` 才算「确认外部输入」
"""

import ast
import re

# Web 框架的请求对象（确认外部输入的源头）
REQUEST_ROOTS = re.compile(
    r"^(req|request|http_request|httprequest|flask_request|ctx|context|"
    r"aiohttp_request|starlette_request|websocket|self\.request)$", re.I)

# 请求对象上取数据的属性（几乎全是外部输入）
REQUEST_ATTRS = re.compile(
    r"^(args|query_params|form|json|body|data|headers|cookies|values|"
    r"get_post|get_json|path_params|path|query_string|raw_body|user)$", re.I)

# 配置类来源（这些是服务端自己配的，**不算**外部输入）
CONFIG_ATTRS = re.compile(
    r"^(getenv|environ|env|config|settings|opts|options|kwargs|"
    r"default|defaults|DEFAULT|_default)$", re.I)

# 本模块的判定结果（三档，不许只有两档）
CONFIRMED = "confirmed"       # 追到 request.* 了
NOT_INPUT = "not_input"       # 明确来自配置/常量
UNKNOWN = "unknown"           # 追不到 —— 不可当成「不是外部输入」


class _FuncScope(object):
    """一个函数（或模块顶层）的赋值表：变量名 -> 赋值来源表达式"""

    def __init__(self, node):
        self.node = node
        self.assigns = {}     # 变量名 -> [来源表达式, ...]
        # ★ 带类型注解的参数名 —— 只有这些才是「框架的请求对象」
        #   实测踩过：只看名字会把 urllib 构造出来的待发送 Request 也算进来
        self.annotated_names = set()
        self.collect()
        self._collect_annotations()

    def _collect_annotations(self):
        for n in ast.walk(self.node):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = n.args
                pairs = list(zip(a.posonlyargs, a.args)) + \
                    list(zip(a.args, a.args)) + \
                    list(zip(a.kwonlyargs, [None] * len(a.kwonlyargs)))
                for arg, _ in pairs:
                    if arg is None:
                        continue
                    if arg.annotation is not None:
                        try:
                            ann = ast.unparse(arg.annotation)
                        except Exception:
                            ann = ""
                        # 只认框架的请求类型
                        if re.search(r"\b(Request|WebSocket|Starlette|"
                                     r"FastAPI|HTTPConnection)\b", ann):
                            self.annotated_names.add(arg.arg)

    def collect(self):
        for n in ast.walk(self.node):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.assigns.setdefault(t.id, []).append(n.value)
                    elif isinstance(t, ast.Subscript):
                        # d["k"] = v  →  记到 d 上
                        base = self._base_name(t.value)
                        if base:
                            self.assigns.setdefault(base + "[]", []).append(n.value)
            elif isinstance(n, ast.AnnAssign):
                if isinstance(n.target, ast.Name) and n.value is not None:
                    self.assigns.setdefault(n.target.id, []).append(n.value)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 参数视为「来源未知」（不是 request）
                a = n.args
                for arg in list(a.args) + list(a.kwonlyargs) + list(a.posonlyargs):
                    self.assigns.setdefault(arg.arg, []).append(None)

    @staticmethod
    def _base_name(node):
        try:
            n = ast.unparse(node)
            return n.split("[")[0].split(".")[-1]
        except Exception:
            return None


def _expr_is_request(node):
    """这个表达式本身是不是直接来自 request对象？"""
    if node is None:
        return False
    if isinstance(node, ast.Attribute):
        v = node
        root = None
        while isinstance(v, ast.Attribute):
            v = v.value
        if isinstance(v, ast.Name):
            root = v.id
        if root and REQUEST_ROOTS.match(root):
            # request.headers / request.query_params / request.json …
            return True
        # a.b.request.c 这类
        try:
            u = ast.unparse(node)
        except Exception:
            u = ""
        return bool(re.search(r"\b(request|req|ctx)\.", u, re.I))
    if isinstance(node, ast.Call):
        # ★★ 先排除「请求对象的构造器」——
        #   实测踩过：`urllib.request.Request(url)` 名字里含 request，
        #   但它是自己构造一个**待发送**对象，不是外部输入。
        #   这跟「框架的 request 对象」名字相同、性质相反。
        try:
            fname = ast.unparse(node.func)
        except Exception:
            fname = ""
        # 形如 X.request.Request(...) / urllib.request.Request(...)
        if BUILT_REQUEST_CTORS.search(fname.split("(")[0].split(".")[-1] or "") \
                or fname.rstrip(".").endswith("request.Request") \
                or fname.endswith(".Request"):
            return False
        # request.headers.get(...) / request.query_params.get(...)
        if re.search(r"\b(request|req|ctx)\b", fname, re.I):
            return True
        if re.search(r"\.(get|post|json|form|body)$", fname):
            return False
    if isinstance(node, ast.Subscript):
        return _expr_is_request(node.value)
    if isinstance(node, ast.BinOp):
        return _expr_is_request(node.left) or _expr_is_request(node.right)
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_expr_is_request(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_expr_is_request(k) for k in node.keys if k is not None) or \
            any(_expr_is_request(v) for v in node.values)
    return False


def _expr_is_config(node):
    """这个表达式来自配置/环境变量？

    ★★ 这里连栽了两次，两次都是同一个病：**用正则去匹配表达式文本**。
       - `os.getenv("B")` 明明是配置，正则却没匹配上
       - `settings.BASE_URL` 是模块级配置，也匹配不上
       - 更早一次：`json.loads(...)` 因为含 `env` 子串被误判成配置
       → 病根：靠名字/字面判断数据来源。
       → 改成**按 AST 节点类型判定**，这是结构信息，不靠猜。

    ★★ 另一个坑：形参（None 默认值）原本被判成「不是外部输入」，
       但 one SDK 的 `runtime_params` 恰恰是形参，
       真实来源在**另一个函数**里（那里确实来自 request.headers）。
       → 单函数内追不到，正确结论是 unknown（不确定），不是 not_input（安全）。
       → ★ 与「没检出 ≠ 没有」同源：
         **追不到来源 ≠ 来源安全。** 把 unknown 混进 not_input
         会把真漏洞静默判成安全 —— 那是最坏的失败方式。
    """
    if node is None:
        return False        # ★ 形参 ≠ 配置
    # 1) 调用型：os.getenv / os.environ.get / settings.get / config.get
    if isinstance(node, ast.Call):
        try:
            u = ast.unparse(node.func)
        except Exception:
            return False
        # 去掉末尾的 .get，匹配基名
        base = u.split(".")[0].lower()
        leaf = u.split(".")[-1].lower()
        if leaf in ("getenv", "getenviron"):
            return True
        if base in ("os",) and leaf in ("environ", "getenv"):
            return True
        if base in ("settings", "config", "conf", "cfg", "options", "opts",
                    "app_config", "appconfig", "environment", "env"):
            return True
        return False
    # 2) 属性型：settings.X / config.X / self.settings.X / self.config.X
    if isinstance(node, ast.Attribute):
        try:
            u = ast.unparse(node)
        except Exception:
            return False
        # 取根名与中间段
        parts = re.split(r"[.\[\]]+", u)
        for p in parts:
            if p.lower() in ("settings", "config", "conf", "cfg", "options",
                             "opts", "app_config", "appconfig",
                             "environment", "environ", "env"):
                return True
        return False
    # 3) 常量（含空）→ 不是外部输入
    if isinstance(node, ast.Constant):
        return True
    return False


# ★ 「待发送的请求对象」与「外部 HTTP 请求」同名但不同物
#
#   实测踩过（同一类误报的第4 次变种）：某项目 8 处
#       with urllib.request.urlopen(request, timeout=120)
#   被判成「外部输入直落客户端」。读代码才发现 `request` 是
#   **内部构造出来的待发送请求对象**（urllib 的 Request），不是外部 HTTP 请求。
#
#   病根：`request` 这个名字被用于两种完全不同的东西
#   - FastAPI/Starlette 的 `request: Request` ← **外部输入**
#   - urllib 的 `request = Request(url, headers=...)` ← **自己构造的**
#
#   → 按 AST 结构区分：有类型注解 `request: Request` 才是框架请求对象；
#     无注解的 `request` 只当普通名字。
REQUEST_ANNOTATED = re.compile(r"^(request|req|ctx|websocket)$", re.I)
# urllib / requests 构造出来的请求对象
BUILT_REQUEST_CTORS = re.compile(
    r"(^|\.)(Request|PreparedRequest|RequestObject)$", re.I)


def is_framework_request_arg(node):
    """这个实参是不是「框架的请求对象」（外部输入）？

    ★ 必须看**有没有类型注解** —— 只看名字会把 urllib 的待发送对象也算进来。
    """
    if not isinstance(node, ast.Name):
        return False
    if not REQUEST_ANNOTATED.match(node.id):
        return False
    # 在函数签名里找它有没有 : Request 这样的注解
    fn = getattr(node, "_owner_fn", None)
    scope = getattr(node, "_scope", None)
    if scope is None:
        return False
    anns = getattr(scope, "annotated_names", None)
    if anns is None:
        return False
    return node.id in anns


def trace(node, name, scope=None, depth=0, seen=None):
    """追踪变量 `name` 的来源。返回 (CONFIRMED / NOT_INPUT / UNKNOWN, 证据串)"""
    if depth > 6:
        return UNKNOWN, "递归过深"
    if seen is None:
        seen = set()
    if name in seen:
        return UNKNOWN, "成环"
    seen = seen | {name}

    if scope is None:
        scope = _FuncScope(node)

    # 1) 只有「带类型注解的 request」才算框架请求对象。
    #    ★ 原来这里是「变量名匹配 REQUEST_ROOTS就算」——
    #      实测踩过：urllib 构造的 `request = urllib.request.Request(url)`
    #      变量也叫 request，但它是自己构造的待发送对象，不是外部输入。
    if name in getattr(scope, "annotated_names", set()):
        return CONFIRMED, "框架请求对象（带类型注解）"

    # 2) 查赋值表
    srcs = scope.assigns.get(name)
    if srcs is None:
        return UNKNOWN, "本函数内没有对它的赋值（可能是形参或来自别处）"

    ev = []
    for s in srcs:
        if _expr_is_request(s):
            ev.append("← request 数据")
            return CONFIRMED, "; ".join(ev)
        if _expr_is_config(s):
            # ★ 配置是「确知不是外部输入」→ 直接定案。
            #   （实测这里原来返回 unknown，导致 os.getenv("BASE_URL")
            #     这种明确的配置来源判不出来。配置与「追不到」是两件事。）
            ev.append("← 配置/环境变量")
            return NOT_INPUT, "; ".join(ev)
        # 是不是另一个变量的转发（如 runtime_params = xxx）
        inner = _forwarded_name(s)
        if inner:
            r, e2 = trace(node, inner, scope, depth + 1, seen)
            ev.append("← %s %s" % (inner, e2))
            if r == CONFIRMED:
                return CONFIRMED, "; ".join(ev)
            if r == NOT_INPUT:
                continue
        else:
            ev.append("← %s" % (ast.unparse(s)[:40] if s is not None else "参数默认值"))
    if ev and all("配置" in e for e in ev):
        return NOT_INPUT, "; ".join(ev)
    if ev:
        return UNKNOWN, "; ".join(ev)
    return UNKNOWN, "无信息"


def _forwarded_name(node):
    """若表达式是「另一个变量」或「d['k']」，返回那个名字"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Subscript):
        try:
            u = ast.unparse(node.value)
            return u.split(".")[-1]
        except Exception:
            return None
    if isinstance(node, ast.Attribute):
        try:
            return ast.unparse(node).split(".")[0]
        except Exception:
            return None
    return None


def resolve_arg(node, arg, scope=None):
    """判断一个实参是不是外部输入。"""
    if scope is None:
        scope = _FuncScope(node)
    if arg is None:
        return NOT_INPUT, "无"
    # ★★ 先看是不是「框架请求对象」（有类型注解的 request/req）
    #   实测踩过：urllib 的 `urlopen(request)` 里 request 是自己构造的
    #   待发送对象，没有注解 —— 按名字判会误报。
    if isinstance(arg, ast.Name) and arg.id in getattr(
            scope, "annotated_names", set()):
        return CONFIRMED, "框架请求对象(%s: 有类型注解)" % arg.id
    if _expr_is_request(arg):
        return CONFIRMED, "直接来自 request"
    if _expr_is_config(arg):
        return NOT_INPUT, "配置"

    name = None
    if isinstance(arg, ast.Name):
        name = arg.id
    elif isinstance(arg, ast.Subscript):
        try:
            # d["k"] →先看 d 是不是外部来的
            base = ast.unparse(arg.value).split(".")[-1]
            key = arg.slice.value if isinstance(arg.slice, ast.Constant) else None
            r, e = trace(node, base, scope)
            if r == CONFIRMED:
                return CONFIRMED, "%s 是外部来源（%s）" % (base, e)
            # 键名本身就说明内容性质
            if key and re.match(
                    r"^(api_key|base_url|url|endpoint|token|secret|password|"
                    r"command|cmd|query|sql|path|file|model|host|uri)", str(key), re.I):
                # 键名可疑但父对象来源不明 → 不确定
                return UNKNOWN, "%s[%s] 的父对象来源不明" % (base, key)
            return r, e
        except Exception as ex:
            return UNKNOWN, "解析失败:%s" % ex
    elif isinstance(arg, ast.Attribute):
        try:
            u = ast.unparse(arg)
        except Exception:
            return UNKNOWN, "?"
        if re.search(r"\b(request|req|ctx)\b", u, re.I):
            return CONFIRMED, "来自 request"
        root = u.split(".")[0]
        r, e = trace(node, root, scope)
        return r, e

    if name:
        r, e = trace(node, name, scope)
        return r, e
    return UNKNOWN, "无法静态判定"