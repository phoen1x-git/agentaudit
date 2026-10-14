#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AST 级漏洞判据（跨 token 关联版）
==================================

为什么要重写
------------
`run_criteria.py` 的注入面判据是正则版，为了补两处漏报
（`cursor.execute("..."+uid)`、`open(os.path.join(base, filename))`）
连改三轮，每轮修好上轮、弄坏下轮 —— 这是"该停手换路子"的信号。

★ 病根：**正则做不了跨 token 的关联。**
  这两处都要求"先知道这个变量是什么、那个变量从哪来"，
  而正则只能看一行文本。硬堆规则只会无限返工。

→ 改用 Python 自己的 ast：参数表达式能原样拿到，
  BinOp / 嵌套 Call / 变量名全都是结构化的，不用猜。

★ 顺带解决假阳性：正则分不清
    logger.error(f"...{exc}")        ← 拼进日志，无害
    cursor.execute(f"...{req.id}")    ← 拼进 SQL，要看
  AST 版能判断这个 f-string 的**去向**是不是危险调用。

判据口径
--------
  code_exec_sink        代码执行点（eval/exec/subprocess/pexpect…）
  injection_surface     注入面：外部输入直落执行点 / SQL / 路径
  auth_surface          认证鉴权痕迹
  agent_tool_surface    工具注册与可调用能力面
  dangerous_cooccurrence ★★ 同一个表达式里「外部输入」与「危险操作」同时出现
                        （= 最值得人工看的点）

★ 只读代码，不执行被测项目。解析失败就跳过并计数，不假装成功。
"""

import ast
import re

# ★ 污点追踪：判断变量值从哪来（避免「看名字猜来源」）
from taint_flow import (trace as _trace, _FuncScope,
                        CONFIRMED, NOT_INPUT, UNKNOWN)

# ---------------------------------------------------------------- 词表

EXEC_FUNCS = {
    "eval", "exec", "compile", "os.system", "os.popen", "os.execv",
    "os.execvp", "os.spawnl", "os.spawnv", "subprocess.run",
    "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "subprocess.getoutput",
    "pexpect.spawn", "pexpect.run", "pexpect.execute",
    "pty.spawn", "pty.call",
    "pickle.loads", "pickle.load", "dill.loads", "marshal.loads",
    # ★★★ 10-08 补：语义等价的反序列化库，★ 之前一个都没进清单。
    #   cloudpickle/dill/marshal 的 `loads` 行为一致 —— 都执行 __reduce__。
    #   ★ 为什么漏：找SampleOrch 漏洞时，`load_obj` 里的 `cloudpickle.loads`
    #   正好在 `open(path)` 之后，★ 视觉上被「读文件」盖住了；
    #   而清单里只有 `pickle.loads`，★ 于是所有判据都漏了它。
    #   ★ 实测本批漏了 5 处（SampleAgentX / SampleOrch）。
    #   ★★ 教训：**清单要按「语义组」维护，不是逐个词打补丁**。
    "cloudpickle.loads", "cloudpickle.load",
    "jsonpickle.decode", "jsonpickle.unpickler.decode",
    "shelve.open", "shelve.DbfilenameShelf",
    "yaml.unsafe_load", "yaml.load",
    "run_cell", "run_line_magic", "run_cell_magic", "exec_command",
    "exec_cell", "IPython",
}

# ★★★ 不是执行点的调用（按**能力**归类，不是逐个打补丁）
#
#   ★ 这张表本身也是踩出来的：
#     第一版只列了 re.compile / re.match → dynamiq 里
#     `filename = re.sub(r"[/\\]", "_", filename)` 被报成「输入直落执行点」。
#     补了 re.sub 之后才想到：**整个 `re.*` 家族 + 各类数据转换函数
#     都不执行外部内容**。
#     → 教训与 samplecli 的 pexpect、SampleDelegate 的 samplesdk 完全一致：
#       **按能力归类，别按名字逐个列。列不全的表现是静默误报。**
#
# 分类：
#   文本处理  re.*  str.*  （拼字符串不会执行代码）
#   数据转换  json.loads / yaml.safe_load / ast.parse / base64.b64decode
#   正则/模板  re.compile / Template(...).substitute

SAFE_PREFIXES = (
    "re.", "regex.", "str.", "json.loads", "json.load", "json.dumps",
    "yaml.safe_load", "yaml.safe_dump", "ast.parse", "ast.literal_eval",
    "base64.b64encode", "base64.b64decode", "base64.urlsafe_b64encode",
    "urllib.parse.quote", "urllib.parse.unquote", "urllib.parse.urlparse",
    "os.path.join", "os.path.basename", "os.path.dirname", "os.path.exists",
    "os.path.abspath", "os.path.splitext", "os.makedirs", "pathlib.Path",
    "logging.getLogger", "dataclasses.", "typing.", "collections.",
    "itertools.", "functools.", "datetime.", "time.time", "uuid.",
    "hashlib.", "secrets.", "copy.", "pprint.", "textwrap.",
)

# ★ 精确名单（不在前缀家族里的）
SAFE_EXACT = {
    "compile_rule", "Template", "Template.substitute", "escape", "quote",
    "make_secure", "urlencode", "urlparse", "parse_qs", "parse_qsl",
}

SQL_FUNCS = {"execute", "executemany", "executescript", "raw", "cursor.execute"}
SQL_KEYWORDS = ("select", "insert", "update", "delete", "drop", "union",
                "alter", "create table", "where")

PATH_FUNCS = {"open", "read_text", "write_text", "unlink", "rmtree",
              "remove", "listdir", "makedirs", "send_file", "send_from_directory"}

AUTH_WORDS = {"login_required", "require_auth", "verify_token",
              "check_permission", "authenticate", "authorize",
              "current_user", "get_current_user", "is_admin",
              "check_access", "permission_required",
              # ★★ 补词（SampleSDK 逼出来的）：这一组在实际项目里很常见，
              #   漏了它们会让「认证鉴权痕迹」判据输出 0，
              #   而0 在报告里长得和「确实没有鉴权」一模一样 —— 假阴性。
              #   与 samplecli 的 pexpect.spawn、SampleDelegate 的 samplesdk 装饰器同类。
              "auth_header", "authorization", "api_key", "apikey",
              "credentials", "credentials_payload", "authenticate_user",
              "get_api_key", "load_credentials", "token", "access_token",
              "refresh_token", "bearer", "jwt", "session_key"}

TOOL_WORDS = {"tool", "agent_tool", "register_tool", "mcp_tool", "tool_registry",
              "add_tool", "FastMCP", "MCPServer", "register_tool_impl"}

# ★★★ 「对外发起请求的客户端」—— 危险点，但性质与 exec 不同
#
#   实测踩过：六项目高覆盖对比时「输入×危险共现」0/5 全部未检出，
#   查下去发现 SampleSDK 真实的洞就在这里——
#       AsyncOpenAI(api_key=runtime_params["api_key"],
#                   base_url=runtime_params["base_url"])
#   之前只把 exec/subprocess 当危险点，**漏了整个「LLM SDK 客户端」这一类**。
#
#   为什么它算危险点：base_url / api_endpoint / api_key 都由调用方决定
#   → 服务端被支使着向任意地址发请求（SSRF），
#     或把请求发到攻击者的服务器（凭据外泄）。
#   这在 Agent 项目里极其常见—— 每个项目都在调 LLM SDK。
#
#   ★ 与 exec 类的区别：exec 直接在本机执行代码；
#     SDK 客户端是**把请求发出去**，危害是 SSRF / 凭据泄露。
#     所以单列一档，不混进 EXEC_FUNCS。
CLIENT_FUNCS = {
    "AsyncOpenAI", "OpenAI", "AsyncAzureOpenAI", "AzureOpenAI",
    "AsyncAnthropic", "Anthropic", "AsyncBedrock", "Bedrock",
    "ChatOpenAI", "AzureChatOpenAI", "ChatAnthropic",
    "acompletion", "completion",
    "CohereClient", "AsyncGroq", "Groq", "ReplicateClient",
    "httpx.AsyncClient", "httpx.Client", "aiohttp.ClientSession",
    "requests.get", "requests.post", "requests.request",
    "urlopen", "urllib.request.urlopen", "httpx.get", "httpx.post",
    "aiohttp.request",
}

# 危险点总集：执行类 + 客户端类
DANGEROUS_ALL = EXEC_FUNCS | CLIENT_FUNCS

# ★★★ 「外部输入」的判定：必须区分**谁的数据**
#
#   实测踩过两次：
#   (1) 某项目的子进程工具库写法很规范（Sequence[str]、无 shell=True、有超时/
#       输出上限/进程组终止），却因形参名叫 `args` 被判成「输入直落」3 处。
#       →病根：把「变量名长得像用户输入」当成「它就是用户输入」。
#   (2) ★★ 六项目高覆盖对比时，「输入×危险共现」0/5 全部未检出，
#       看起来像「这类漏洞真的不存在」。用已知答案一验才发现是**判据太钝**：
#       SampleSDK 真实代码里是
#           client = AsyncOpenAI(api_key=runtime_params["api_key"],
#                                 base_url=runtime_params["base_url"])
#       而 `runtime_params` 不在词表里 → 不算外部输入 → 漏报。
#       →病根：外部数据常**经过中间变量中转**才到危险点，
#         而我的词表只看「直接来自请求的名字」。
#         ★ 这与「按名字匹配会瞎」是同一个病的第N 次发作，
#           但这次更隐蔽：它伪装成「负结果」。
#
#   → 所以加一档：**中转变量**（把外部数据装进去的容器/字典）。
#     宁可多报（靠人工核实），不可因词表漏词而漏掉真洞。

# 强：Web 框架请求/上下文对象（这类对象本身就是「外部」）
STRONG_INPUT_TOKENS = re.compile(
    r"^(req|request|http_request|httprequest|flask_request|ctx|context|"
    r"aiohttp_request|starlette_request|websocket)$", re.I)

# ★ 中转变量：外部数据常先被装进这些名字，再到危险点
#   （SampleSDK 的 runtime_params 就是这种）
#   ★★★ 但**仅凭名字会大量误报**，实测：
#     SampleSDK 里`OpenAI(api_key=api_key, base_url=base_url)` 被判成外部输入，
#     可那 两个值是**服务端自己的配置**（函数形参），不是请求数据。
#     → 病根与之前几次相同：**靠名字判断数据来源**。
#   → 所以 CARRIER 只作为「需要追来源」的提示，
#     **真正判定靠 taint_flow.py 的赋值追踪**。
#     这里保留它是为了让追来源有个入口。
CARRIER_INPUT_TOKENS = re.compile(
    r"^(runtime_params|runtime_params_|_params|params_dict|runtime|"
    r"credentials|credential|creds|auth|auth_params|connection_params|"
    r"client_params|llm_params|model_params|provider_params)$", re.I)

# 弱：名字像用户数据，但要靠「是否在请求上下文里」才算
WEAK_INPUT_TOKENS = re.compile(
    r"^(params|param|payload|body|data|json|form|query|args|argv|"
    r"user_input|userinput|input_text|user_message|message|content|prompt|"
    r"filename|filepath|file_path|path|upload|uploaded_file|model_name|"
    r"api_key|token|headers|cookies)$", re.I)

# 带这些前缀/后缀的形参，即便名字是弱词也仍算外部输入
REQUEST_HINT = re.compile(
    r"(request|req|user|client|caller|external|http|web|api|body|payload|"
    r"param|query|header|cookie|upload|form|input|message|content)",
    re.I)

# ★ 明确排除：常见的「不是外部输入」的形参名
NOT_INPUT_NAMES = re.compile(
    r"^(cmd|command|argv0|exe|executable|bin|python|python_exe|node|"
    r"env|envs|env_vars|environ|options|opts|flags|config|conf|settings|"
    r"cwd|workdir|work_dir|root|base|prefix|suffix|sep|delimiter|"
    r"func|fn|callback|cb|handler|funcs|"
    r"seq|sequence|items|item|values|value_list|elements|lines|"
    r"raw|raw_cmd|shell_cmd)$", re.I)

# 无害的动态导入（加载内建库，不是执行外部内容）
HARMLESS_IMPORT = re.compile(
    r"^(numpy|pandas|matplotlib|sklearn|scipy|torch|IPython|json|re|os|sys|"
    r"ast|typing|importlib|logging|datetime|collections|abc|enum)$")


# ★★ 这些对象的 .exec()/.execute() 是 **ORM /数据库查询**，不是执行代码
#   实测踩过：SQLAlchemy 的 `session.exec(stmt)` / `db.exec(stmt)`，
#   因为判据「只取名字最后一段」拿到 `exec` → 被当成 Python 的 exec() 报成执行点。
#   而真正的 exec() 是**裸调用**（没有对象前缀）。
#   → 必须区分「谁的 exec」。ORM 会话/连接的 exec 不算执行点。
ORM_OBJECTS = {
    "session", "db", "conn", "connection", "cursor", "cur", "tx",
    "transaction", "sql_session", "async_session", "sess", "engine",
    "scoped_session", "dbapi", "mongo", "collection", "bucket", "table",
    "orm", "dao", "repo", "repository", "store", "database", "pool",
    "redis", "client",
}
ORM_METHODS = {"exec", "execute", "executemany", "executescript",
               "raw", "execute_sql", "exec_driver_sql"}


# ★ 这些函数名只有**裸调用**（无对象前缀）才是内建函数；
#   带对象前缀的基本都是框架 API，不是执行点。
#   实测：`graph_builder.compile(x)`（LangGraph 构图）被当成
#   Python 的 compile() 代码执行 —— 而 compile() 本身也不执行代码，
#   只是编译，真正执行的是 exec。
BUILTIN_ONLY = {"compile", "eval", "exec", "print"}


def _is_framework_method(nm):
    """这个「危险名字」是不是其实是框架对象的方法？

    ★ `compile` / `eval` / `exec` 这几个名字很特殊：
      - 裸调用 `compile(src, "f", "exec")` → 真的是 Python 内建 → 要报
      - 带前缀 `graph_builder.compile(x)`      → LangGraph 构图 → 不报
      - `re.compile(p)`                      → 正则编译 → 不报（已在 SAFE_PREFIXES）
    → 所以判据是「**带对象前缀**就不算内建」。
    ★ 我第一次把这里写反了（裸调用反而被排除），
      靠双向验证抓出来：真 exec/eval/compile 从 4 处掉到 2 处。
    """
    leaf = nm.split(".")[-1]
    if leaf not in BUILTIN_ONLY:
        return False
    return "." in nm        # ★ 有对象前缀 = 框架方法，不算内建


def _is_orm_call(nm):
    """这个调用是ORM/数据库查询吗？（`session.exec(...)` 而不是 `exec(...)`）"""
    if "." not in nm:
        return False            # 裸 exec() 才是真的
    obj, _, meth = nm.rpartition(".")
    leaf = obj.split(".")[-1].lower()
    return (leaf in ORM_OBJECTS and meth in ORM_METHODS) or \
        (meth in ORM_METHODS and obj.split(".")[-1].lower() in ORM_OBJECTS)


def _is_safe_call(nm):
    """★ 这个调用会不会执行外部给的内容？按能力判断，不按名字逐个列。"""
    if nm in SAFE_EXACT:
        return True
    return any(nm.startswith(p) for p in SAFE_PREFIXES)


def _name(node):
    """取调用的全名：os.system / cursor.execute / f(...)"""
    f = node.func if isinstance(node, ast.Call) else None
    if f is None:
        return ""
    try:
        return ast.unparse(f)
    except Exception:
        if isinstance(f, ast.Attribute):
            return f.attr
        if isinstance(f, ast.Name):
            return f.id
    return ""


def arg_node_of(args):
    """挑出「最可疑」的那个实参（用于报告里显示）

    ★ 实测踩过：f-string（JoinedStr）也是常见形态，
      漏掉它会让报告里「来源不明←」后面空着，看不出是哪���参数。
    """
    for want in (ast.Call, ast.Subscript, ast.Attribute, ast.JoinedStr):
        for a in args:
            if isinstance(a, want):
                return a
    return args[0] if args else None


def _resolve_any(args, scope):
    """对一个调用的所有实参做来源判定，取最强结论。

    ★ 强度顺序：CONFIRMED > UNKNOWN > NOT_INPUT
       —— ★★ 关键：**UNKNOWN 不能当 NOT_INPUT**。
          把「追不到来源」当成「来源安全」，会把真漏洞静默判成安全，
          那是最坏的失败方式（同「没检出 ≠ 没有」）。
    """
    from taint_flow import resolve_arg
    best = NOT_INPUT
    for a in args:
        try:
            r, _e = resolve_arg(None, a, scope)
        except Exception:
            r = UNKNOWN
        if r == CONFIRMED:
            return CONFIRMED
        if r == UNKNOWN:
            best = UNKNOWN
    return best


def _is_input_expr(node, depth=0):
    """★ 判断表达式里是否含「外部输入」。

    这是 AST 版的核心优势：能顺着 Attribute/Call 一层层看下去，
    而正则只能盯着同一行。

    ★ 分两档（见词表处的说明）：
      强输入（request/req 这类 Web 对象）→ 算
      弱输入（args/data/path 这类名字）→ **不算**，
      除非它明确挂在请求上下文上，或名字里带 request/user 等提示
    """
    if node is None or depth > 6:
        return False
    if isinstance(node, ast.Attribute):
        # req.query / request.body / user_input.text
        base = _name_of_root(node)
        if base:
            if STRONG_INPUT_TOKENS.match(base):
                return True
            if REQUEST_HINT.search(base):
                return True
        return _is_input_expr(node.value, depth + 1)
    if isinstance(node, ast.Name):
        n = node.id
        # ★ 先排掉「明确不是外部输入」的通用形参名
        if NOT_INPUT_NAMES.match(n):
            return False
        if STRONG_INPUT_TOKENS.match(n):
            return True
        # ★ 中转变量：外部数据常先装进这里再到危险点（SampleSDK 的 runtime_params）
        if CARRIER_INPUT_TOKENS.match(n):
            return True
        if WEAK_INPUT_TOKENS.match(n):
            # 名字带请求/用户提示才算
            return bool(REQUEST_HINT.search(n))
        return False
    if isinstance(node, ast.Subscript):
        # ★ d["api_key"] / runtime_params["base_url"] —— 下标里的键名能说明内容性质
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            k = node.slice.value
            if re.match(
                    r"^(api_key|base_url|url|endpoint|token|key|secret|password|"
                    r"credential|command|cmd|query|sql|path|file|model|host)", k, re.I):
                return True
        return _is_input_expr(node.value, depth + 1)
    if isinstance(node, ast.Call):
        # os.path.join(base, request.name) —— 看参数
        return any(_is_input_expr(a, depth + 1) for a in node.args) or \
            any(_is_input_expr(k.value, depth + 1) for k in node.keywords)
    if isinstance(node, (ast.BinOp,)):
        return _is_input_expr(node.left, depth + 1) or \
            _is_input_expr(node.right, depth + 1)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_is_input_expr(e, depth + 1) for e in node.elts)
    return False


def _name_of_root(node):
    """取 a.b.c 最外层的名字（req / request / self.request …）"""
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    return None


def _has_dynamic_expr(arg):
    """参数里有没有插值/拼接（f-string / BinOp / % / .format / join）"""
    for n in ast.walk(arg):
        if isinstance(n, ast.JoinedStr):
            return True
        if isinstance(n, ast.BinOp):
            return True
        if isinstance(n, ast.FormattedValue):
            return True
        if isinstance(n, ast.Call):
            nm = _name(n)
            if nm.endswith((".format", ".join")):
                return True
    # f-string 的隐式拼接在py3.12+ 是 JoinedStr，已覆盖
    return False


def _sqlish(arg):
    """参数里像 SQL 吗（关键字 + 动态部分）"""
    try:
        s = ast.unparse(arg)
    except Exception:
        return False
    low = s.lower()
    return any(k in low for k in SQL_KEYWORDS)


def _src(node, full_text):
    """取节点的源码片段。**full_text = 整个文件的原文**（已 join 好的字符串）。

    ★★★★★★ 性能（10-07 修）：原来签名是 `(node, code_lines)`，
      内部每次都 `"\n".join(code_lines)`。
      实测 dataelement/Clawith 的 `agent_tools.py`：
      **108 万字符 / 28028 行 / 133754 个 AST 节点**
      → 每个节点 join 一次 28 万行，拼接总量 ~1.6e11 字符，
        **单文件 analyze 跑 90 秒还没完**。

      现在把「join 全文」这件事**提到调用方做一次**，
      `_src` 只做一次 `get_source_segment`（它本身是O(节点长度)）。

    ★ 为什么不用 cache 记住上次 join 的结果：
      缓存要处理「同一个 lines 列表被反复传入」的判定，
      比直接传字符串更容易写错。传全文更直白。
    """
    try:
        return ast.get_source_segment(full_text, node) or ""
    except Exception:
        return ""


# ★★★★★ 第 3 种鉴权写法的词根表（2026-10-05 06:58 修正）
#   形如 require_admin_header(x, y) / verify_token(token) / check_permission(...)
#
#   ★★ 把 `ensure` 从表里去掉了：实测 trinity 里
#   `asyncio.ensure_future(...)` 命中它 → 端点被误判成"有鉴权"，
#   而它成了「同文件内 1/N」的引爆点，一次带出 4 处假阳性。
#   `ensure_*` 是 asyncio/断言的常用前缀，而没有任何项目拿它命名鉴权函数。
_AUTH_WORDROOT = re.compile(
    r"\b(verify|require|check|validate|auth)\w*\s*\(")

# ★ 同前缀但**不是鉴权**的调用（asyncio / 断言 / 容器）。
#   逐个匹配排除，不能整体排除 —— 见_has_auth_wordroot_call 的说明。
_NOT_AUTH_PREFIX = re.compile(
    r"^_?(ensure_future|ensure_asyncio|check_output|check_returncode|"
    r"check_callable|check_instance|is_checkable|validator\.validate_dict|"
    r"pydantic|BaseModel\.validate|schema\.validate)")


def _has_auth_wordroot_call(body_src):
    """★ 函数体里有没有「像鉴权的调用」。

    与朴素写法的区别（这是 06:58 那次修复的核心）：
        ✗ if re.search(AUTH_WORDROOT, body) and not NOT_AUTH.search(body)
            → 端点里"既有真鉴权、又有 ensure_future"会被**误杀** → 假阴性
        ✓ 逐个匹配，把排除项剔掉，**还剩至少一个**才算
    """
    if not body_src:
        return False
    for m in _AUTH_WORDROOT.finditer(body_src):
        #取到完整的调用名（含点号链，如 asyncio.ensure_future）
        seg = body_src[max(0, m.start() - 40):m.end()]
        mm = re.search(r"([\w\.]*%s)\s*\(" % re.escape(m.group(0)[:-1]), seg)
        name = mm.group(1).split(".")[-1] if mm else ""
        if name and _NOT_AUTH_PREFIX.match(name):
            continue          # ★ 排除这一项，继续看别的命中
        return True
    return False


# ---------------------------------------------------------------- 主扫描

# ★★★★★ 第 7 种鉴权写法要用：全项目源码拼成的文本。
#   由 analyze_files() 在第 1 趟填好。
#   ★ 单文件 analyze() 调用时它是空字符串 → 第 7 种写法自动失效（退化成旧行为），
#     这是**有意的**：单文件模式本来就无法解析跨文件别名。
_ALL_MODULE_SRC = ""

# ★★★★★★ 第 7 种写法的别名**缓存**（10-07 修，性能）。
#
#   ★ 这不是微优化，是**能不能跑完的问题**：
#   `_ALL_MODULE_SRC` 是全项目源码拼起来的大字符串。
#   实测 dataelement/Clawith（597 个 py）：**865 万字符**。
#   `_collect_auth_aliases` 对它跑一次 = 0.16 秒。
#   而 `_find_unauth_endpoints` 是**按文件**调的
#   → 595 个业务文件里每个重算一次 ≈ **92 秒**，
#     且该项目一个别名都没有（收到 0 个），**纯白花**。
#
#   → 缓存成"一个元素 list"：一次算完，之后 O(1) 取。
#     用 list 而不是裸 set/None 是为了**能被赋值**（模块级 rebind）。
_AUTH_ALIASES_CACHE = [None]


def _auth_aliases():
    """取鉴权别名集合，**带自愈**。

    ★★★★★★ 为什么不能直接读 `_AUTH_ALIASES_CACHE[0]`（10-07踩了）：
      自测（`selftest_auth.py` 第 14 档）只设 `A._ALL_MODULE_SRC = ...`，
      不走 `analyze_files()`，于是缓存还是 None → 别名认不出来 →
      **期望 1 实得 0，测试直接把这个 bug 抓出来了。**
      这是自测的价值：性能优化改坏了机制，被自动发现。

    ★ 判据不能靠「调用方记得填两个变量」——
      那样每加一个调用点就是一个漏。
      改成「缓存空就现算」，漏填也能得到正确结果，
      只是慢一点（回到修改前的行为，不会错）。

    ★★ 缓存按 `_ALL_MODULE_SRC` 的**长度 + 身份**做键，
      不是无脑「算一次就永久用」。
      理由：自测会在同一进程里换 `_ALL_MODULE_SRC` 再跑，
      无脑缓存会让第二次拿到第一次的别名集 → 又是个假阴性。
    """
    src = _ALL_MODULE_SRC
    if not src:
        _AUTH_ALIASES_CACHE[0] = (None, set())
        return set()
    key = (id(src), len(src))
    cached = _AUTH_ALIASES_CACHE[0]
    if cached is not None and cached[0] == key:
        return cached[1]
    names = _collect_auth_aliases(src)
    _AUTH_ALIASES_CACHE[0] = (key, names)
    return names


def _collect_auth_aliases(all_src):
    """★★ 收集「鉴权依赖的类型别名」（第 7 种写法）。

    真实形态（abilityai/trinity  实测）：
        # src/backend/dependencies.py
        OwnedAgentByName = Annotated[str, Depends(get_owned_agent_by_name)]
        CurrentUser       = Annotated[User, Depends(get_current_user)]

        # src/backend/client_portal/router.py —— 签名里一个 Depends 字都没有
        @router.get("/agents/{agent_name}/clients")
        def list_agent_clients(agent_name: OwnedAgentByName, current_user: CurrentUser):

    ★ 为什么必须跨文件：别名定义在 dependencies.py，路由文件只 import 它。
      单文件扫**必然漏**（我第一版就是这么写的，等于没修）。

    识别两种形态：
        1) X = Annotated[...Depends(...)...]
        2) X = Depends(...)                （FastAPI 官方推荐写法）

    ★★★★★ 3) `type X = ...`（PEP 695，Python 3.12 起的官方类型别名语法）
       # ascending-llc/jarvis-registry 实测（10-05 08:0x）：
       #   registry/src/registry/auth/dependencies.py:40
       #   type CurrentUser = Annotated[UserContextDict, Depends(get_current_user)]
       #   → 原正则一个别名都收不到（名字前面多了个 `type `）
       #   → 9 个用它的端点全被判成「无鉴权」，
       #     其中 registry/src/registry/api/proxy_routes.py:527 被列进
       #     inconsistent_auth —— ★★ 而它其实有鉴权，是纯假阳性。

    ★ 只收"名字像类型别名"的（大写开头或含 _ ），避免把普通变量当别名。
      这是"宁可少认也不误认"：多认一个别名 → 真阳性被吃掉（假阴性）。
    """
    if not all_src:
        return set()
    names = set()
    # ★★ `(?:\s*type\s+)?` —— 必须放在捕获组**外面**，
    #   否则 group(1) 会变成 "type CurrentUser"（带前缀），
    #   后面 `re.search(r"\b%s\b" % alias, sig)` 永远匹不中。
    for m in re.finditer(
            r"^[ \t]*(?:type\s+)?([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
            # ★★ `[^\]]` 换成 `[^]]`：允许跨行 ——ruff 格式化会把长别名拆成
            #   type X = Annotated[\n      User,\n      Depends(get_current_user),\n  ]
            #   原来的 `[^\]]` 遇到第一个 `]` 就断了（真实数据里 0 例，
            #   但代价是零、收益是多覆盖一种排版，不值得留这个洞）。
            r"(?:Annotated\s*\[[^]]{0,300}?Depends\s*\(|\s*Depends\s*\()",
            all_src, re.M):
        names.add(m.group(1))
    return names


def analyze(text, path="<file>"):
    """★ 对一段源码跑全部 AST 判据。返回 {判据: {...}}。"""
    empty = lambda label: {"label": label, "hits": [], "n_hits": 0,
                           "hit_files": []}
    out = {
        "code_exec_sink": empty("代码执行点"),
        "injection_surface": empty("注入面（输入直落危险点）"),
        "auth_surface": empty("认证/鉴权痕迹"),
        "agent_tool_surface": empty("工具注册/可调用能力面"),
        "dangerous_cooccurrence": empty("★★输入与危险操作同表达式"),
        "unauth_endpoint": empty("★★对外端点无鉴权"),
        "input_source_unknown": empty("★来源不明（需人工确认）"),
        "inconsistent_auth": empty("★★同文件内端点鉴权不一致"),
    }
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        # ★ 解析失败就说失败，不假装扫过（教训：判据坏了，数字全是废的）
        return out, "parse_error:%s" % (e.msg,)
    lines = text.splitlines()

    for node in ast.walk(tree):
        ln = getattr(node, "lineno", 0)
        src_line = lines[ln - 1].strip()[:140] if 0 < ln <= len(lines) else ""
        # ★★ 原来这里还有一行 `seg = _src(node, lines)...`，
        #   **但 `seg` 是死变量** —— 全函数只在 add() 里用 src_line，
        #   `seg` 算出来一次都没被读。
        #   ★ 而这一行是**性能杀手**：_src 内部 `"\n".join(code_lines)`
        #     对**每个** AST 节点重拼一次全文。
        #     实测 Clawith 的 agent_tools.py（108 万字符/ 133754 节点）
        #     → 拼接总量 ~1.6e11 字符，单文件 analyze 90 秒没跑完。
        #   → 直接删掉。删之前先确认过 `seg` 真的没被用到
        #     （grep `\bseg\b` 只在下面另一个函数的局部作用域出现过）。

        def add(key, kind):
            out[key]["hits"].append({"file": path, "line": ln,
                                     "kind": kind, "text": src_line})
            out[key]["n_hits"] += 1
            if path not in out[key]["hit_files"]:
                out[key]["hit_files"].append(path)

        # ---------- 装饰器
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            for d in node.decorator_list:
                dn = ""
                try:
                    dn = ast.unparse(d)
                except Exception:
                    pass
                base = dn.split("(")[0].strip()
                if base in TOOL_WORDS or base.endswith(".tool"):
                    add("agent_tool_surface", "工具装饰器@%s" % base)
                if base in AUTH_WORDS:
                    add("auth_surface", "鉴权装饰器@%s" % base)

        # ---------- 名字里的工具注册表
        if isinstance(node, ast.Assign):
            try:
                tgt = ast.unparse(node.targets[0])
            except Exception:
                tgt = ""
            if tgt in ("TOOLS", "tools", "TOOL_REGISTRY", "tool_registry"):
                add("agent_tool_surface", "工具注册表变量 %s" % tgt)
            if tgt in AUTH_WORDS:
                add("auth_surface", "鉴权符号 %s" % tgt)

        if not isinstance(node, ast.Call):
            continue
        nm = _name(node)
        base_nm = nm.split(".")[-1]

        # ---------- 工具注册（调用形式）
        if nm in TOOL_WORDS or base_nm in ("register_tool", "add_tool"):
            add("agent_tool_surface", "工具注册 %s" % nm)
        if nm in ("FastMCP", "MCPServer", "McpServer", "CMSServer"):
            add("agent_tool_surface", "MCP 服务器 %s" % nm)

        # ---------- 鉴权（调用形式）
        if base_nm in AUTH_WORDS or nm in AUTH_WORDS:
            add("auth_surface", "鉴权调用 %s" % nm)

        # ---------- 无害的动态导入，不算执行点
        if nm.endswith("import_module") or nm == "__import__":
            arg0 = node.args[0] if node.args else None
            try:
                s = ast.unparse(arg0) if arg0 is not None else ""
            except Exception:
                s = ""
            m = re.search(r"['\"]([^'\"]+)['\"]", s)
            if m and HARMLESS_IMPORT.match(m.group(1).split(".")[0]):
                continue

        # ---------- 代码执行点
        # ★ 排除 ORM 查询（session.exec / db.execute），它们不是执行代码
        if (not _is_safe_call(nm) and not _is_orm_call(nm)) and \
                (nm in EXEC_FUNCS or base_nm in EXEC_FUNCS) and \
                not _is_framework_method(nm):
            add("code_exec_sink", "执行点 %s" % nm)

        args = list(node.args) + [k.value for k in node.keywords]

        # ---------- 注入面
        # a) 外部输入直落执行点（★ 用同一套「安全调用」判定，
        #    否则 re.sub(filename) 之类会被报成执行点）
        if (not _is_safe_call(nm) and not _is_orm_call(nm)) and \
                (nm in EXEC_FUNCS or base_nm in EXEC_FUNCS) and \
                not _is_framework_method(nm) and \
                any(_is_input_expr(a) for a in args):
            add("injection_surface", "输入直落执行点 %s" % nm)
            add("dangerous_cooccurrence", "输入直落 %s" % nm)

        # a2) ★★ 外部输入直落「对外请求客户端」→ SSRF / 凭据外泄
        #     这一档是六项目对比里 0/5 全未检出后才发现的：
        #     SampleSDK 的真实洞是
        #         AsyncOpenAI(api_key=runtime_params["api_key"],
        #                     base_url=runtime_params["base_url"])
        #     而 `AsyncOpenAI` 原本不在任何危险点词表里 → 整条判据失灵。
        #     ★ Agent 项目每个都在调 LLM SDK，**漏这一类等于漏掉整个生态**。
        if not _is_safe_call(nm) and \
                (nm in CLIENT_FUNCS or base_nm in CLIENT_FUNCS):
            # ★★ 用污点追踪而不是「看名字」：
            #   实测踩过 —— SampleSDK 的 `OpenAI(api_key=api_key, base_url=base_url)`
            #   里两个值都是**服务端自己的配置**，但因为名字像用户输入，
            #   被判成外部输入 → 满屏误报。
            #   而 `runtime_params["base_url"]` 才是真外部输入。
            scope = _FuncScope(node)
            r_in = _resolve_any(args, scope)
            hit_in = r_in == CONFIRMED
            if r_in == UNKNOWN:
                add("input_source_unknown",
                    "来源不明 %s ← %s" % (nm, _name(arg_node_of(args))))
            if hit_in:
                add("injection_surface", "输入直落客户端 %s" % nm)
                add("dangerous_cooccurrence", "输入直落客户端 %s" % nm)
                # ★ 特别标记 SSRF 面：base_url/api_endpoint 由外部输入决定
                for a in args:
                    if isinstance(a, ast.keyword) and a.arg in (
                            "base_url", "api_base", "endpoint", "url",
                            "api_endpoint", "host"):
                        add("dangerous_cooccurrence", "SSRF面 %s=%s"
                            % (nm, ast.unparse(a.value)[:40]))
                    elif isinstance(a, ast.Call):
                        pass
                for k in node.keywords:
                    if k.arg in ("base_url", "api_base", "endpoint",
                                 "url", "api_endpoint", "host") and \
                            _is_input_expr(k.value):
                        add("dangerous_cooccurrence",
                            "SSRF面 %s(%s=外部输入)" % (nm, k.arg))

        # b) SQL 拼接
        if base_nm in ("execute", "executemany", "executescript", "raw"):
            for a in args:
                if _sqlish(a) and _has_dynamic_expr(a):
                    add("injection_surface", "SQL拼接 %s" % nm)
                    if _is_input_expr(a):
                        add("dangerous_cooccurrence", "SQL注入 %s" % nm)
                    break

        # c) 路径拼接（穿越面）
        if base_nm in PATH_FUNCS or nm in PATH_FUNCS:
            for a in args:
                if _has_dynamic_expr(a) and _is_input_expr(a):
                    add("injection_surface", "路径拼接 %s" % nm)
                    add("dangerous_cooccurrence", "路径穿越 %s" % nm)
                    break
        if nm == "os.path.join" and any(_is_input_expr(a) for a in node.args):
            add("injection_surface", "path.join 外部输入")

    # ---------- 危险操作 + shell=True（沙箱逃逸面）
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        nm = _name(node)
        if nm.startswith("subprocess.") or nm in ("os.system", "os.popen"):
            for k in node.keywords:
                if k.arg == "shell" and isinstance(k.value, ast.Constant) \
                        and k.value.value is True:
                    ln = getattr(node, "lineno", 0)
                    sl = lines[ln - 1].strip()[:140] if 0 < ln <= len(lines) else ""
                    out["injection_surface"]["hits"].append(
                        {"file": path, "line": ln, "kind": "shell=True", "text": sl})
                    out["injection_surface"]["n_hits"] += 1
                    if path not in out["injection_surface"]["hit_files"]:
                        out["injection_surface"]["hit_files"].append(path)

    for k in out:
        out[k]["hit_files"] = sorted(set(out[k]["hit_files"]))
    _find_unauth_endpoints(tree, lines, path, out)
    _find_inconsistent_auth(tree, lines, path, out)
    return out, None


# ★★ 对外端点鉴权检查
#
# ★ 这条判据是被SampleSDK 逼出来的：
#   实测它的 server/app.py 有 124 个调用，其中 app.post×6 / app.get×3
#   —— **全是对外 HTTP 端点，而全文件找不到任何鉴权痕迹**。
#   我原有的 4 条判据此时全部输出「0 处」，看起来像"这项目没问题"，
#   实际上它是最值得看的一个。
#   → 教训：**判据集没覆盖到的维度，不会报错，只会安静地返回 0**。
#     0 处有两种含义（「查过确实没有」/「压根没查这条」），
#     报告里必须能区分，否则就成了假阴性。
#
# 判定逻辑（保守，宁可多报）：
#   对每个 @app.get/post/put/delete/patch 路由：
#     看它自己的参数里有没有 Depends(...) / 鉴权装饰器
#     看它调用的下游函数链里有没有鉴权
#   都没有→ 报「未鉴权端点」（这只是**线索**，不是漏洞结论）

ROUTE_RE = re.compile(
    r"^(@?[\w\.]*)\.(get|post|put|delete|patch|route|websocket)\s*\(")
ROUTE_DECO = re.compile(r"^@(app|router|api|blueprint|bp|application|server)\."
                        r"(get|post|put|delete|patch|route|websocket)\b")

# ★★★ 鉴权的**三种写法**（第三种最容易漏，报了 6 处假阳性才补上）
#
#   1) 依赖注入：  async def f(u: User = Depends(get_current_user))
#   2) 装饰器：    @require_auth  /  @login_required
#   3) ★★ 函数体内直接调：  def f(token: str):
#                              require_admin_header(token, session)   ← 就是这种
#
#   实测踩过：某项目 admin 端点全是第3 种写法
#   （`require_admin_header(x_astra_admin_token, x_astra_session)`），
#   我的判据只认Depends → 报了 6 处「未鉴权」，实际全都有鉴权。
#   → 这是「按名字/按模式判断」的又一次失手：**鉴权可以是任意函数调用**。
AUTH_HINT = re.compile(
    r"(Depends\s*\(|require_auth|login_required|verify_token|"
    r"current_user|get_current_user|check_permission|authenticate|"
    r"oauth|jwt|bearer|api_key|apikey|permission|authorize|verify_)", re.I)

# ★★★ 第 4 种鉴权写法：中间件注入型（判据此前一个都认不出来）
#   身份不在签名里、也不调鉴权函数，而是从 request.state 读 + 抛 401/403：
#       user_id = getattr(request.state, "user_id", None)
#       if not user_id: raise HTTPException(401, "未登录")
#   ★ 踩过的坑：`ast.unparse` 输出的是 **字符串字面量**形式
#     `getattr(request.state, 'user_id', None)` —— 属性名带引号，
#     所以 `request\.state\.\w+` 匹配不到。必须写成「点号 + 可选引号」。
#     而 `scope['user']` 这种字典取法也要覆盖。
#   两个条件必须同时成立才算有鉴权：只出现 request.state 可能是在读
#   session 之类无关数据；只抛 401 也可能是参数校验。
AUTH_MIDDLEWARE = re.compile(
    r"request\.state[\.\"']|scope\[\s*[\"']user|"
    r"getattr\s*\(\s*request\.state", re.I)
AUTH_DENY = re.compile(r"HTTPException\s*\(\s*(401|403)", re.I)


# ★★ 只认「真正的路由载体」：app / router / api / blueprint / bp
#   （实测踩过：dynamiq 里 response_json.get("exports", ...) 和
#     error_message = search_result.get("request_info", ...)
#     都被报成「未鉴权端点」—— 原因是这一版只要看到 `.get(` 就去匹配路由。
#     → 教训：判据必须在**结构位置**上成立，不能靠字面相似。
ROUTE_BASES = {"app", "router", "api", "blueprint", "bp", "application",
               "server", "application_router", "api_router", "web", "api_v1",
               "router_v1", "route", "urls"}

ROUTE_VERBS = ("get", "post", "put", "delete", "patch", "route", "websocket",
               "head", "options")

# ★★ 本来就不该有鉴权的端点 —— 判据报出来是**噪音**，不是发现
#   实测：某项目 `/register`、`/login`、`/health` 全被报成「未鉴权端点」，
#   读代码才确认它们的鉴权是**完整的**（业务端点都挂了
#   `Depends(get_current_user)`），而注册/登录/健康检查本来就不需要 token。
#   → 端点名（不是函数名）落在这些词上就跳过。
#★★ 豁免只在「整段路径」或「末尾」成立 —— 不能子串匹配！
#
#   实测踩过：`/api/info/user/{uid}` 被当成「info 页」豁免了，
#   而它其实是「按 user_id 查他人数据」的端点 —— 恰恰是要报的。
#   原因：老正则里 `info` 前后是 `|` 分隔的裸词，`/info/` 直接命中。
#   → 分两类：
#     强豁免（任何位置都算）：register/login/health/... 本身就是公开端点
#     弱豁免（**只在末尾**才算）：info/version/status/ready/...
NO_AUTH_STRONG = re.compile(
    r"(^|/)(register|signup|sign-up|signin|sign-in|login|logout|logon|"
    r"auth|oauth|authorize|token|refresh|health|healthz|ping|metrics|"
    r"favicon|static|robots\.txt|sitemap\.xml|openapi\.json|docs|redoc|"
    r"graphql|websocket|ws)(/|$)", re.I)

# ★ 弱豁免：只在**路径最后一段**成立
NO_AUTH_WEAK = re.compile(
    r"^[^/]*(?:/[^/]+)*/(info|version|status|ready|readiness|liveness|"
    r"health|ping|index|home|schema|spec)$", re.I)

#★★★★★ 协议性公开（第 8 类豁免，10-05 08:1x 补，实测依据见 docs/47）
#
#  为什么必须和「业务上公开」分开：
#    业务公开（register/login/health）是**项目自己的选择** ——
#    它不挂鉴权可能只是疏忽，扫出来值得看一眼；
#    协议性公开是**标准强制要求** —— 客户端就是靠它发现 token_endpoint，
#    加了鉴权所有标准客户端都连不上。报出来是**纯噪声**。
#
#  实测形态（ascending-llc/jarvis-registry auth-server）：
#    @router.get("/.well-known/openid-configuration")  RFC 8414 OIDC Discovery
#    @router.get("/.well-known/jwks.json")             RFC 7517 JWKS
#  它的 docstring 自己写清楚了：
#    "to obtain the public key and verify tokens **without sharing a secret**"
#  —— 也就是说**不公开才是设计错误**。
#
#  ★ 只收 .well-known 前缀，不收裸的 /jwks 或 /keys：
#    后者常是业务自定义端点，未必是协议要求。
WELL_KNOWN = re.compile(r"(^|/)\.well-known(/|$)", re.I)


def _is_exempt_path(path):
    """这个路径本来就不该有鉴权吗？"""
    if not path:
        return False
    p = path.split("?")[0].rstrip("/")
    # ★ 协议性公开优先（.well-known 前缀）—— 标准强制要求公开
    if WELL_KNOWN.search(p):
        return True
    if NO_AUTH_STRONG.search(p):
        return True
    # ★ 弱豁免要求「末尾就是」，且中间不能带参数段
    if NO_AUTH_WEAK.search(p) and "{" not in p.rsplit("/", 1)[-1]:
        return True
    return False


# ★ 有显式豁免标记的端点也算「不该报」
AUTH_EXEMPT_HINT = re.compile(
    r"(public|no_auth|anonymous|open_endpoint|skip_auth|"
    r"PUBLIC_ENDPOINTS|EXEMPT)", re.I)


def _route_from_decorator(d):
    """★ 从装饰器 AST 节点取出（方法名, 路径）。

    ★★ 为什么不用正则：`ast.unparse(d)` 输出的是 `self.app.get('/x')`，
       **没有 `@` 符号** —— 而按 `^@` 写的正则一律匹配不上（实测踩过）。
       而 `unauth_endpoint` 判据是从源码行文本取 `@`，所以它能匹配。
       → 同一种装饰器，两个判据解析方式不同 = 必然有一个错。
       → 统一改成按 AST 结构取。
    """
    if not isinstance(d, ast.Call):
        return None, None
    f = d.func
    if not isinstance(f, ast.Attribute):
        return None, None
    meth = f.attr
    if meth not in ("get", "post", "put", "delete", "patch",
                    "websocket", "route", "head", "options"):
        return None, None
    # 路径必须是第一个位置参数的字符串常量
    if not d.args:
        return meth, ""
    a = d.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return meth, a.value
    # f-string / 拼接：取片段拼出来（够用了）
    try:
        return meth, ast.unparse(a)
    except Exception:
        return meth, ""


# ★★ 第 6 种鉴权写法要用的正则：端点体里出现了「把 request 传给某个函数」的调用
#   uid = _uid(request) / who = _whoami(request) / ctx = _ctx_user(request)
#   为什么要单独识别：见_find_inconsistent_auth 里第 6 种写法的说明。
#
# ★★★ 10-05 修的真实缺陷：request 不一定是**第一个**实参，也不一定叫 `request`。
#   实测 academic-commercialization-agent 第 1131 行：
#       _authorize_run_mutation(run_id, http_request)   ← 第 2 个实参，且叫 http_request
#   老正则 `\b(\w+)\s*\(\s*request\s*[,)]` 要求 request 紧跟左括号 →
#   完全匹配不到 → **一个真做了鉴权的端点被报成「无鉴权」**（假阴性）。
#   → 修法：位置放宽到「本调用的实参列表里出现任意含 request 的标识符」。
#     仍然保守：只在同一个括号对内匹配，不会跨调用串味。
_WRAPPER_CALL = re.compile(r"\b(\w+)\s*\(([^()]{0,200}?)\)")
#★★★★★ 参数名白名单：这里必须用**精确匹配**，不能用 `\w*request\w*` 通配。
#   起因（10-05 07:2x）：`\w*request\w*` 意思是「前后随便接字符」，于是
#   以下全部被当成「HTTP 请求对象」—— 而它们跟鉴权毫无关系：
#       requested_path            路径参数（FastAPI 最常见）
#       request_id/agent_request_id   业务ID
#       request_timeout_seconds   超时
#       request_may_have_spent     **计费额度**（商业化项目）
#       credits_per_request        计费
#       requests                   ★ **HTTP 客户端库名**（出站调用）
#       chat_request/update_request   Pydantic 模型
#   实测规模：trinity 正确识别 412 次、误匹配 48 次；academic-commercialization
#   正确 201+12 次、误匹配 33 次 —— **量级相当，不能靠"占比小"忽略**。
#
#   ★ 命名规律：带修饰语的（requested_ / request_id / request_timeout）
#     几乎都不是请求对象；**恰好叫 request、或带 http_/req_ 前缀的**才是。
#   ★ 这跟「词根表撞 asyncio」是同一类错：用**一个宽松的匹配**去近似
#     **一个语义判断**。正则写得出来，但"你不知道它还匹配了什么"。
_REQ_PARAM = re.compile(
    r"^(?:request|http_request|http_req|req|request_obj|request_object|"
    r"req_obj|raw_request|scoped_request|"
    r"starlette_request|fastapi_request)$", re.I)


def _collect_router_guards(tree):
    """★★★★★ 第 9 种鉴权写法：**router 级dependencies**（10-05 08:3x 补）。

    真实形态（rhesis-ai/rhesis 实测）：
        # apps/backend/src/rhesis/backend/app/routers/services.py:63
        router = RhesisRouter(
            prefix="/services",
            dependencies=[Depends(require_current_user_or_token)],   ★★ 这里
        )

        @router.get("/github/contents")
        def get_github_contents(repo_url: str):       ← 端点自己一个字都没挂

    ★★ 为什么这个盲区比前 8 种都危险：
      判据认的是「**端点自己**有没有鉴权痕迹」，
      而 router 级dependencies 是**整个文件的所有端点共享**的。
      → 判据会把**这个文件里每一个端点**都判成"无鉴权"。
      → 而这些端点全都有鉴权。**100% 假阳性。**

    实测规模：
      | 项目 | 带 deps 的 router | 其下端点 | ★ 自身无痕迹（误判） |
      |---|---|---|---|
      | rhesis-ai/rhesis | 24（23 文件） | 164 | 2 |
      | abilityai/trinity | 2（2 文件） | 14 | **11** |

      trinity 那 11 处包括 `/execute-task` `/agent-files/share`
      `/playbooks` `/chat` —— **全是高价值端点**。

    ★ 为什么漏了这么久：第 8 种写法（类型别名）的注释里我写了
      "签名里一个 Depends 字都没有" → 我以为已经覆盖了"Depends 不在签名里"，
      **没想到 Depends 还能挂在 router 上、连签名都不参与。**

    返回：{router 变量名: 依赖列表的unparse 文本}
    """
    out = {}
    for n in ast.walk(tree):
        if not isinstance(n, (ast.Assign, ast.AnnAssign)):
            continue
        if not isinstance(n.value, ast.Call):
            continue
        fn = n.value.func
        # ★ 兼容 `RhesisRouter(...)` / `APIRouter(...)` / `router = APIRouter()`
        #   —— 判断依据是类名里含 "Router"，不挑具体基类（子类是常见写法）
        cname = getattr(fn, "id", None)
        if cname is None:
            cname = getattr(fn, "attr", None)
        if not isinstance(cname, str) or "Router" not in cname:
            continue
        targets = ([n.target] if isinstance(n, ast.AnnAssign)
                   else n.targets)
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not names:
            continue
        for kw in n.value.keywords:
            if kw.arg != "dependencies":
                continue
            try:
                src = ast.unparse(kw.value)
            except Exception:
                src = "<unparse-failed>"
            # ★★ `dependencies=[]` 是**显式声明「不挂」**，不是鉴权
            if src.strip() in ("[]", ""):
                continue
            for nm in names:
                out[nm] = src
    return out


def _router_var_of_deco(d):
    """★ 从路由装饰器 AST 里取出 router 的变量名（`router.get` -> "router"）。

    为什么要这个：`_collect_router_guards` 给的是变量名 → 依赖的映射，
    而端点这一侧要反查「我挂在哪个 router 上」。
    ★ 不能用 `self.app.get` 这种 —— 变量名取的是最后一段。
    """
    f = getattr(d, "func", None) or getattr(d, "value", None)
    if f is None:
        return None
    # Call.func是 Attribute(value=Name('router'), attr='get')
    v = getattr(f, "value", None)
    if isinstance(v, ast.Name):
        return v.id
    if isinstance(v, ast.Attribute):
        return v.attr
    return None


def _has_req_param(arglist):
    """★ 实参列表里有没有「请求对象」。

    ★★★ 关键：**逐个标识符判断**，不能拿白名单去 search 整段文本。
      `search(r"^(?:request|...)$", "run_id, http_request")` 永远不匹配
      —— 而 `_authorize_run_mutation(run_id, http_request)` 正是真实形态。

      我第一版把通配改成白名单时就是这么错的：
      **语义上"收紧"了，机械上"全都不认了"** → 端点被认成"无鉴权"
      → **假阴性**（真洞被藏起来），而且看起来一切正常。

      → 正确做法：先把实参列表按非标识符字符切成 token，逐个送白名单。
    ★ 这跟「`A and not B` 会误杀 A 和 B 都有」是同一类：
      **收紧匹配时，要确认收紧后「该认的」还认得出来。**
    """
    if not arglist:
        return False
    for tok in re.split(r"[^A-Za-z0-9_]+", arglist):
        if tok and _REQ_PARAM.match(tok):
            return True
    return False


def _wrapper_names(body_src, self_name=None):
    """★ 抽出端点体里「把请求对象传给了某个自定义函数」的调用名。

    返回函数名集合。判定口径：
      1. 抓出所有 `名字(实参列表)` 形态的调用（不跨嵌套括号）
      2. 实参列表里出现「请求对象」（request / http_request / req / request_obj…）
      3. 排除明显不是包装函数的

    ★ 为什么要按「实参」而不是按「函数名」筛：
      端点里会有 `runs.get_state(run_id)` 这种调用，如果只按名字猜，
      就得靠一张猜出来的名字白名单 —— 下一个项目叫什么都可能漏。

    ★★★★★ 10-05 08:4x 修：必须排除**函数定义那一行**。
      真实形态（rhesis travel_agent/app.py:248）：
          @app.post("/chat")
          async def chat(request: ChatRequest):        ← 这行被当成调用了
              ...
              raise HTTPException(500, "Error processing request")   ← detail 里有 "request"
      两个缺陷叠在一起：
        A) `ast.unparse(n)` 输出**包含 def 行**，正则把 `chat(request: ChatRequest)`
           当成一次调用 → `chat` 进了 names
        B) `HTTPException(status_code=500, detail='...request')` 的 detail
           里含 "request" 一词 → 也过了 _has_req_param
      结果：**端点自己被当成"调用的包装函数"**，
      而它函数体里有 `if "API_KEY" in str(exc): raise HTTPException(503, ...)`
      → READ_ID 命中 API_KEY + DENY 命中 raise HTTPException
      → ★★ **这个完全没鉴权的端点被判成"有鉴权"**，
         成了「同文件内 1/6 有鉴权」那个 **1** —— 1 引爆 5处假阳性。
    """
    names = set()
    if not body_src:
        return names
    for m in _WRAPPER_CALL.finditer(body_src):
        fn, arglist = m.group(1), m.group(2)
        #★★★★★ 排除①：函数定义自身。`def chat(request: X)` 不是调用。
        if self_name and fn == self_name:
            continue
        # ★★ 排除②：**异常/响应类的构造**不是"把请求传给鉴权函数"。
        #   `HTTPException(status_code=500, detail='Error processing request')`
        #   的 detail 里含 "request" 一词就会混进来（实测踩过）。
        if fn.rsplit(".", 1)[-1] in _NOT_AUTH_CTORS:
            continue
        if not _has_req_param(arglist):
            continue
        names.add(fn)
    names -= {"print", "json", "str", "int", "len", "dict", "set", "list",
              "isinstance", "hasattr", "getattr", "setattr", "type", "bool",
              "min", "max", "sum", "sorted", "tuple", "float", "repr", "any",
              "all", "round", "bytes", "format", "vars", "id", "open"}
    return names


# ★ 异常/响应类的构造名 —— 它们**不是**「把请求传给某个鉴权函数」。
#   判据第 6 种写法要追进被调函数看它做什么，而 HTTPException 被 raise 时
#   恰恰说明**这个端点自己在做错误处理**，不是在鉴权。
#   ★ 为什么要单列而不是塞进上面那个"排除内建"集合：
#     那个集合是「内建函数」，这个是「框架类」，语义不同；
#     而且 `Response` / `JSONResponse` 这类不是内建的，塞进去会混淆语义。
_NOT_AUTH_CTORS = frozenset([
    "HTTPException", "HTTPException401", "JSONResponse", "Response",
    "StreamingResponse", "FileResponse", "RedirectResponse", "PlainTextResponse",
    "UJSONResponse", "ORJSONResponse", "Exception", "ValueError", "TypeError",
    "KeyError", "RuntimeError", "OSError", "HTTPError",
])



# ★★★★★★ 10-07 新增：凭据以**字符串参数**传递时的调用名（守卫名形态）
#
#   与 `_wrapper_names` 的区别 —— 那条路要求「实参里有请求对象」，
#   这条路认的是「**函数名本身像守卫** + 实参里有凭据」。
#
#   ★ 为什么要单独一条而不是放宽 `_wrapper_names` 的实参要求：
#     放宽之后 `f(x)` 里的任何 x 都会被当成候选，
#     而端点体里全是 `f(payload)` / `f(row)` / `f(data)` 这类调用
#     → 候选爆炸 → 追定义的代价也跟着爆炸。
#     **收紧入口 + 靠定义验证兜底**，比放宽入口安全。
_GUARD_NAME = re.compile(
    r"^(?:_?)"
    r"(?:(?:require|ensure|check|verify|validate|assert)_"          # 动词_xxx
    r"|(?:current|get|load|fetch|resolve|read)_"                # 取身份_xxx
    r"|(?:is|has|can)_)"
    r"(?:admin|superadmin|superuser|super|root|owner|author|permission|perm|"
    r"role|token|auth|identity|user|session|principal|access|"
    r"subject|credential|gate)"
    r"(?:_[\w]+)?$"
    # ★ 动词本身就是守卫词的情况：require_auth / verify_token
    r"|^(?:_?)(?:require|verify|validate|ensure|check)_?"
    r"(?:admin|superadmin|superuser|root|owner|auth|authorization|token|"
    r"identity|user|session|principal|access|permission|perm|role|"
    r"credential|gate|trusted|local)(?:_[\w]+)?$",
    re.I)
# ★ 实参里必须有「凭据」形态的东西，否则 `_uid(payload)` 之类会被误当候选。
_CRED_ARG = re.compile(
    r"\b\w*(?:token|secret|apikey|api_key|auth|authorization|session|"
    r"credential|password|ticket|signature|principal|user_id|uid|"
    r"admin|role|perm|permission|subject|claims|jwt|bearer)\w*\b",
    re.I)


def _guard_called_names(body_src, self_name=None):
    """抽出「看起来像守卫、且实参带凭据」的调用名。

    ★★★ 这条路径**必须**配 `_wrapper_is_auth` 里的 READ_ID + DENY 双条件，
      否则就是「看名字猜鉴权」—— 实测里`local_only`（响应体里的一个
      reason 字符串）这类噪声会被直接认成鉴权，**假阴性方向**。

    ★ 排除项与 `_wrapper_names` 对齐（自身 def 行、内建、框架类构造）。
    """
    names = set()
    if not body_src:
        return names
    for m in _WRAPPER_CALL.finditer(body_src):
        fn, arglist = m.group(1), m.group(2)
        if self_name and fn == self_name:
            continue
        if fn.rsplit(".", 1)[-1] in _NOT_AUTH_CTORS:
            continue
        if fn in names:
            continue
        # ★ 双条件：名字像守卫 **且** 实参里真有凭据形态的东西
        if not _GUARD_NAME.match(fn):
            continue
        if not _CRED_ARG.search(arglist or ""):
            continue
        names.add(fn)
    return names


# ★★★★★★ 10-07 补：**跨文件定义查找的结果缓存**。
#
#   起因：`_def_body_in` 在 973 万字符的 `_ALL_MODULE_SRC` 上
#   **每次调用都重新扫一遍**。实测 SampleOrch：
#       调 269 次 × 0.081 秒 = **21.8 秒**（占整个 analyze 29 秒的 75%）。
#   同一次 analyze 里问的名字大量重复 → 缓存收益极大。
#
#   ★ 缓存键用 `(id(src), name)`：
#     按内容建键要复制 973 万字符（比扫一遍还贵）；
#     id() 会在 src 被回收后复用，所以**连id 一起存**做双重保险。
_DEF_BODY_CACHE = {}     # {(id(src), name): body or None}


def _def_body_in(src, name):
    """从整份源码文本里切出某个顶层函数的函数体。

    ★ 为什么要它：守卫函数的定义常常和路由函数**不在同一个文件**
      （astra 的 `require_admin_header` 在 app.py，而调用它的端点在
      auth.py / dashboard.py / exchanges.py）。
      只搜本文件必然扑空 → 48 处假阳性。

    ★ 用正则切而不是 ast：这里只需要「函数名 → 函数体文本」，
      而函数定义可能嵌套在类里，ast 走一遍反而更啰嗦。
      切不干净就返回 None（宁可少报）。
    ★★ 同名函数有多个时返回**第一个** —— 保守取向：
      认不准就不算鉴权，不能因为猜对了一个就放过其他实现。
    """
    if not src:
        return None
    key = (id(src), name)
    if key in _DEF_BODY_CACHE:
        return _DEF_BODY_CACHE[key]
    m = re.search(
        r"^[ \t]*(?:async\s+)?def\s+%s\s*\([^)]*\)[^:]*:"
        r"(.*?)(?=^[ \t]*(?:async\s+)?def\s+\w+\s*\(|"
        r"^[ \t]*@|^class\s|\Z)"
        % re.escape(name), src, re.M | re.S)
    body = m.group(1) if m else None
    _DEF_BODY_CACHE[key] = body
    return body


def _wrapper_is_auth(module_src, body_src, _cache=None, self_name=None):
    """★ 判断「端点里调用的那个自定义包装函数」到底是不是鉴权。

    ★★ 这个函数是 10-05 上午为了修 hunter-community 的 69 处假阳性写的。
    起因：那项目把鉴权封成 `_uid(request)`，端点里只写一行`uid = _uid(request)`。
    而判据前5 种写法全都识别不出来 —— 因为 **`_uid` 这个名字里
    没有 verify / require / check / ensure / validate / auth 任何一个词根**。

    ★★ 修法为什么不是「把 _uid 加进词根表」：
      那是**猜名字**。下一个项目叫 _me() / _whoami() / _principal() 就又漏了，
      而且把 _uid 加进「有鉴权」词根表还会造成反向错误 ——
      任何一个恰好叫 _uid 的**非鉴权**函数都会被当成有鉴权（真阳性被吃掉）。
      词根表越大，假阴性越多，**这比假阳性危险得多**（真洞被漏掉）。

    ★ 正确做法：追进那个函数的定义，看它**实际做了什么**：
      - 读了身份（request.state / token / credentials）→ 有「取身份」语义
      - 且在拿不到时会**拒绝**（401/403 / raise / abort / 抛异常）→ 有「鉴权」语义
      两个同时成立才算鉴权。这与判据 3/4 的判定口径保持一致。

    返回 True/False。判定不出来时返回 False —— 与判据整体「宁可少报」的口径一致。

    ★★★★★ 10-05 08:4x 修：调用方**必须传 self_name**。
      起因是 `_wrapper_names` 把端点自己的 `def` 行当成了调用
      （详见 _wrapper_names 注释里的完整案例）——
      一个**完全没鉴权**的 `/chat` 端点被判成"有鉴权"，
      成了「同文件内 1/6」那个 **1**，1 引爆 5 处假阳性。
    """
    names = _wrapper_names(body_src, self_name=self_name)
    # ★★★★★★ 10-07 补第2 条入口：**凭据以字符串参数传递**。
    #
    #   实测代价：astra-quant-agent **72 处**假阳性（116 处的 62%），
    #   占全表 433 处判定的 17%。
    #
    #   为什么 `_wrapper_names` 认不出来：它要求实参里有**请求对象**
    #   （request / websocket / principal…），而这批项目的写法是：
    #
    #       @app.get("/api/v1/admin/memory")
    #       def get_admin_memory(x_astra_admin_token: str = Header(default=None), ...):
    #           require_admin_header(x_astra_admin_token, x_astra_session)   ← 全是 str
    #
    #   实参是**凭据字符串**（Header 注入的 token），不是 Request 对象。
    #   ★ 顺带纠正我第一版的误诊：最初以为问题在「转发层」
    #     （`require_admin_header` 只是 `return current_admin(...)`）。
    #     自测档 5.1「端点直接调鉴权函数、无转发」**也失败** →
    #     说明根因在**入口的实参要求**上，跟转发层无关。
    #
    #   ★ 为什么这条路径必须**同样追进定义验证**，不能只看名字：
    #     `require_thing(token)` 这种名字带 require 但实际只
    #     `return len(token or "")` 的假鉴权很常见。
    #     下面的 READ_ID/DENY 双条件就是为拦住它设计的。
    # ★★★ 10-07 再修：**两个入口都要走，不是二选一。**
    #
    #   原来写的是 `if not names:` —— 意思是「老入口没认出东西时才试新的」。
    #   ★ 实测这个写法导致 astra 55 处一处没减：
    #     `admin_get_llm_models` 的函数体里**同时**有
    #       require_admin_header(x_astra_session=...)← 新入口能认
    #       payload = load_llm_config(mask_keys=True)     ← 老入口也能匹到什么
    #     老入口返回了非空 → 新入口**根本没被调用**。
    #
    #   → 正确的结构是「**并集**」：老入口认的 + 新入口认的，一起验。
    #     每个候选最终都要过 READ_ID + DENY 双条件，所以多认几个候选
    #     **不会**引入假阳性（那些只有名字像、实际不拒绝的会被双条件挡掉）。
# ★★★ 10-07 再修：**两个入口都走，取并集**（不是二选一）。
    #
    #   ★ 我第一版写成了 `if not names:`（老入口没认出东西时才试新的）——
    #     实测这导致 astra 55 处**一处没减**：
    #     `admin_get_llm_models` 的函数体里**同时**有
    #       require_admin_header(x_astra_session=...)   ← 新入口能认
    #       payload = load_llm_config(mask_keys=True)  ← 老入口也能匹到什么
    #     老入口返回了非空 → 新入口**根本没被调用**。
    #
    #   → 取并集是安全的：每个候选最终都要过 READ_ID + DENY 双条件，
    #     那些「名字像但实际不拒绝」的会被双条件挡掉。
    names = set(names) | _guard_called_names(body_src, self_name=self_name)

    # 取出所有 def 的源码片段，按函数名索引
    # ★ 用正则切而不是 ast：这里只需要「函数名 → 函数体文本」，
    #   而函数定义可能嵌套在类里，ast 走一遍反而更啰嗦。
    #   切不干净就当识别不到，返回 False（宁可少报）。
    defs = {}
    for m in re.finditer(
            r"^[ \t]*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)[^:]*:"
            r"(.*?)(?=^[ \t]*(?:async\s+)?def\s+\w+\s*\(|"
            r"^[ \t]*@|^class\s|\Z)",
            module_src, re.M | re.S):
        defs[m.group(1)] = m.group(2)

    READ_ID = re.compile(
        r"request\.state|credentials|\btoken\b|\bapi_key\b|"
        r"\bauth\b|\buser_id\b|\bcurrent_user\b|\bsession\b|\bprincipal\b",
        re.I)
    # ★★★★★★ 10-07 再修：READ_ID **词边界太紧**，把真实鉴权挡掉了。
    #
    #   实测代价：astra-quant-agent **48 处假阳性**（55 处的 87%）。
    #
    #   真实形态（`astra_backend/app.py:124`）：
    #       def require_superadmin(x_astra_session: Any = None):
    #           session_tok = x_astra_session if isinstance(...) else REQUEST_SESSION.get()
    #           user = admin_auth.validate_session(session_tok)
    #           if not user:
    #               raise HTTPException(status_code=401, detail="管理员会话已失效")
    #
    #   这段**明确在读身份 + 会拒绝**（DENY=True），
    #   但 `READ_ID` 是 False —— 因为它用的是
    #       `x_astra_session` / `validate_session` / `user`
    #   而词表写的是 `\bsession\b` / `\bcurrent_user\b`，
    #   **带前缀的 `x_astra_session` 匹配不上 `\bsession\b`**。
    #
    #   ★★ 同一个坑我在 `_REQ_PARAM` 上已经栽过一次
    #     （`\w*request\w*` 通配把 requested_path / request_id 全匹上了，
    #      当时为了收紧改回精确匹配）。
    #     ★ 但这次方向相反：要修的是**太紧**，不是太松。
    #       而"太紧"的修法不能是"放开成 `\w*session\w*`"
    #       —— 那会把 `session_start_time`（计费会话开始时间）也匹上。
    #
    #   → 折中：**只在有 DENY 的前提下**要求身份证据，
    #     身份侧放宽成「含 session/user/auth/token/principal/credential
    #     等**身份类词根**，允许前后缀」。
    #     因为 DENY 已经限定了「这是个会拒绝的函数」，
    #     在这个前提下放宽 READ_ID 不会再放进「只是校验参数非空」那类。
    READ_ID_LOOSE = re.compile(
        r"session|user|auth|token|principal|credential|identity|"
        r"account|subject|role|perm|api_key|apikey", re.I)
    DENY = re.compile(
        r"HTTPException\s*\(\s*(401|403)"
        r"|\braise\b\s+\w*(Error|Exception|Forbidden|Unauthorized)"
        r"|\babort\s*\(\s*(401|403)"
        r"|\bUnauthorized\b|\bForbidden\b"
        r"|\bjsonify\s*\(\s*\{[^}]*[\"']error[\"']\s*:"
        r"|\bResponse\s*\(\s*status_code\s*=\s*(401|403)"
        r"|\bstatus_code\s*=\s*(401|403)",
        re.I)

    # ★★★★★★ 10-07 补：沿转发链**追进被调用的函数**（最多 3 层）。
    #
    #   为什么必须追：实测 astra-quant-agent app.py:118
    #       def require_admin_header(token, session):
    #           return current_admin(session_tok, admin_tok)
    #   这个包装层**自己什么都不做**—— 连 `token` 字样都没有
    #   （参数名是 `x_astra_admin_token` 但被 `\btoken\b` 的词边界挡掉了）。
    #   READ_ID=False DENY=False → 只判一层的话直接返回 False。
    #   而真鉴权在 `current_admin` → `require_admin_token` 里。
    #
    #   ★ 为什么这次是「追」而不是放宽 READ_ID：
    #     放宽 READ_ID 到 `\w*token\w*` 很容易，但它**只救一层**，
    #     而真实形态是三层（端点 → require_admin_header → current_admin
    #     → require_admin_token）。追链子才够。
    #
    #   ★ 追链的三条纪律：
    #     ① 每层都重新跑 READ_ID + DENY 双条件 —— 不能因为「上一层像守卫」
    #        就认定它是鉴权（自测 2.x 反向档就是防这个）
    #     ② **必须查环**（自测 3.x）—— `def a(): return b()` / `def b(): return a()`
    #        不查会无限递归
    #     ③ 定义不在本文件就**放弃**（与原有口径一致：认不准不算鉴权）
    _seen = set()
    frontier = list(names)
    depth = 0
    # ★★★★★★ 10-07 补：找不到定义时回退到**全项目源码**。
    #
    #   实测代价：astra-quant-agent 的 `auth.py` / `dashboard.py` /
    #   `exchanges.py` 里 48 处端点判据认不出鉴权，
    #   因为 `require_admin_header` / `require_superadmin`
    #   **定义在 app.py**（端点在别的文件）→ 只搜本文件必然扑空。
    #
    #   ★ 为什么这**不是**硬凑：
    #     「端点调用的守卫定义在另一个文件」就是第 7 种写法
    #     （跨文件类型别名）同一个问题的另一种形态 ——
    #     守卫函数和路由函数不在一处，这在真实项目里是常态
    #     （auth.py放路由、app.py 放依赖是常见分层）。
    #     机制已有（`_ALL_MODULE_SRC`），这里只是复用。
    #
    #   ★ 但**优先级要保持**：先搜本文件，搜不到才回退全项目。
    #     理由是本文件定义能给出更精确的判定，
    #     而全项目里同名函数可能有多个（不同实现），要保守。
    ALL_SRC = _ALL_MODULE_SRC
    while frontier and depth < 3:
        nxt = []
        for nm in frontier:
            if nm in _seen:
                continue
            _seen.add(nm)
            body = defs.get(nm)
            # ★ 定义不在本文件 → 再在全项目源码里找一次
            if not body and ALL_SRC and ALL_SRC != module_src:
                body = _def_body_in(ALL_SRC, nm)
            if not body:
                continue          # 定义找不到 → 认不准，不算鉴权
            # ★ 两个条件必须同时成立：
            #   只有 READ_ID 没有 DENY → 只是读了个 session_id，不算鉴权（判据 5 反向档）
            #   只有 DENY 没有 READ_ID → 拒绝某种操作，不是鉴权
            if (READ_ID.search(body) or READ_ID_LOOSE.search(body)) \
                    and DENY.search(body):
                return True
            # 本层不含特征 → 看它调用了谁（可能是转发链的下一环）
            for m2 in _WRAPPER_CALL.finditer(body):
                fn2 = m2.group(1)
                if fn2 in _seen or fn2 in _NOT_AUTH_CTORS:
                    continue
                if fn2 not in defs and not (ALL_SRC and _def_body_in(ALL_SRC, fn2)):
                    continue          # ★ 两处都查不到 → 不追
                nxt.append(fn2)
        frontier = nxt
        depth += 1
    return False


def _find_inconsistent_auth(tree, lines, path, out):
    """★★ 检测「同一个文件内，端点鉴权不一致」

    ★★ 这条判据的来源（实测最有性价比的一条）：
    某项目 onboarding_manager.py 里 23 个端点挂了
    `Depends(get_current_user)`，13 个没挂 ——
    那 13 个里包括 `GET /api/onboarding/api-keys`
    （而它邻居 unmasked 版本反而有鉴权）。

    ★ 为什么这条比「逐个查端点有没有鉴权」准得多：
      - 天然排除「本来就不用鉴权」的端点（health/register/login）
        —— 它们不会造成「同文件内不一致」
      - 人的不一致是**相对的**：只要有一个同类端点做了鉴权，
        另一个没做就是嫌疑
      - 不依赖「有没有多用户模型」这个前提

    ★ 判定逻辑（保守，宁可少报）：
      同一文件里，若**有**端点挂了鉴权依赖、且**有**端点没挂 →
      把没挂的那些列为「鉴权不一致，可疑」
    """
    routes = []          # (line, path, has_dep)
    # ★ 第 6 种写法要追进被调函数看它做什么 → 必须拿到整个模块的源码文本。
    #   lines 是源码行列表，直接 join 即可（analyze()传进来的）。
    module_src = "\n".join(lines or [])
    #★★★★★ 第 9 种写法要用：先收集「本文件里哪些 router 变量挂了 dependencies」
    #   ★ 必须在 ast.walk 之前收集，且**只收集本文件**——
    #     router 变量和它的端点一定在同一个文件里（FastAPI 的写法就是这样）。
    #   （对比第 7 种写法：类型别名定义在 dependencies.py，所以要跨文件。）
    router_guards = _collect_router_guards(tree)
    # ★★ 必须用 ast.walk 而不是 tree.body ——
    #   端点常定义在「类的注册方法」里（FastAPI 常见写法）：
    #       class M:
    #           def setup(self):
    #               @self.app.get("/x")
    #               async def f(): ...
    #   只遍历顶层 → 一个端点都看不到（实测 ALwrity 整个文件都是这种写法）。
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_path = None
        for d in n.decorator_list:
            meth, p = _route_from_decorator(d)
            if p is not None:
                route_path = p
                break
        if route_path is None:
            continue
        # ★★ FastAPI 的 Depends 写在**参数默认值**里：
        #      async def f(user: User = Depends(get_current_user))
        #    → 必须同时检查 args.args 与 args.defaults（实测踩过这个坑）
        # 简化可靠做法：把整个签名 unparse 出来搜 Depends
        try:
            sig_src = ast.unparse(ast.arguments(
                posonlyargs=n.args.posonlyargs, args=n.args.args,
                vararg=n.args.vararg, kwonlyargs=n.args.kwonlyargs,
                kw_defaults=n.args.kw_defaults,
                kwarg=n.args.kwarg, defaults=n.args.defaults))
        except Exception:
            try:
                parts = [ast.unparse(a) for a in n.args.args]
                parts += ["=" + ast.unparse(d) for d in n.args.defaults]
                parts += [ast.unparse(a) + "=" + ast.unparse(d)
                          for a, d in zip(n.args.kwonlyargs, n.args.kw_defaults)
                          if d is not None]
                sig_src = " ".join(parts)
            except Exception:
                sig_src = ""
        has_dep = "Depends" in sig_src
        #★★★★★ 第 9 种写法（10-05 08:3x 补）：**router 级 dependencies**
        #   整个文件的端点共享的鉴权，端点自己一个字都不用挂：
        #       router = RhesisRouter(prefix="/services",
        #                             dependencies=[Depends(require_current_user_or_token)])
        #       @router.get("/github/contents")
        #       def get_github_contents(repo_url: str): ...
        #   ★ 必须在 `_route_from_decorator` 拿到路径的**同一个循环里**查 ——
        #     因为要靠装饰器反查「这个端点挂在哪个 router 变量上」。
        if not has_dep and router_guards:
            for d in n.decorator_list:
                rv = _router_var_of_deco(d)
                if rv and rv in router_guards:
                    has_dep = True
                    break
        # ★★★★★ 第 7 种写法（10-05 06:50 补）：类型别名注入
        #   Depends 藏在**一个变量赋值**里，端点签名一个 Depends 字都没有：
        #       # dependencies.py
        #       OwnedAgentByName = Annotated[str, Depends(get_owned_agent_by_name)]
        #       CurrentUser       = Annotated[User, Depends(get_current_user)]
        #       # router.py
        #       def list_agent_clients(agent_name: OwnedAgentByName, current_user: CurrentUser):
        #   ★ 实测后果（abilityai/trinity）：整个 client_portal/router.py 的端点
        #     全都被判成"无鉴权"，而它们其实全都有鉴权；
        #     而"同文件内 1/5 有鉴权"那个 1 来自别的写法 → 1 引爆点带出 4 处误报。
        #
        #   ★ 修法（**必须是跨文件的两趟**，不是单文件正则）：
        #     第1 趟：扫**全部**已加载文件，收集所有
        #             `别名 = Annotated[..., Depends(...)]` / `别名 = Depends(...)`
        #     第 2 趟：分析端点时，看签名里有没有用到这些别名
        #   ★ 为什么不能只看当前文件：别名几乎总是定义在 dependencies/auth 模块里，
        #     而路由文件只import 它 —— 单文件扫**必然漏**（我第一版就犯了这个错）。
        if not has_dep:
            auth_aliases = _auth_aliases()
            if auth_aliases:
                for al in auth_aliases:
                    if re.search(r"\b%s\b" % re.escape(al), sig_src):
                        has_dep = True
                        break
        # ★★ 还要看**函数体**里有没有直接调鉴权函数（第3 种写法）
        if not has_dep:
            try:
                body_src = ast.unparse(n)
                # 形如 require_admin_header(x, y) / verify_token(token)
                #
                # ★★★★★ 2026-10-05 06:58 修：词根表里`ensure` 造成假阳性。
                #   实测 abilityai/trinity：
                #       await asyncio.ensure_future(_run_status_computation(home_dir))
                #   `ensure_future` 是 asyncio 调度，**跟鉴权毫无关系**，
                #   但它命中了 `ensure\w*\s*\(` → 该端点被判成"有鉴权"。
                #   ★ 后果比"多认一个端点"严重得多：
                #     它成了「同文件内 1/N 有鉴权」那个**引爆点**，
                #     把同文件另外 4 个真正无鉴权的端点全部带了出来（1 引爆 4）。
                #
                #   ★★ 关键：不能简单写成 `and not _NOT_AUTH_CALL.search(...)`。
                #     那样"既有真鉴权调用、又有 ensure_future"的端点会被误杀
                #     → 制造假阴性（真洞被漏），比原来的假阳性危险。
                #     → 正确做法：**逐个匹配地排除**，
                #       只要还剩至少一个"不是排除项"的命中，就算有鉴权。
                if _has_auth_wordroot_call(body_src):
                    has_dep = True
                # ★★★ 第 4 种写法：中间件注入型
                #   身份不在签名里、也不调鉴权函数，而是从 request.state 读，
                #   读不到就抛 401/403：
                #       user_id = getattr(request.state, "user_id", None)
                #       if not user_id: raise HTTPException(401, "未登录")
                #   ★ 必须用 AUTH_MIDDLEWARE 常量，别写内联正则：
                #   ast.unparse 输出的是 `request.state, 'user_id'`（逗号+引号），
                #   写成 request\.state\.(\w+) 匹配不到 —— 我在这栽过一次。
                elif AUTH_MIDDLEWARE.search(body_src) and AUTH_DENY.search(body_src):
                    has_dep = True
                # ★★★★★ 第 6 种写法（本项目实测）：本文件自定义的鉴权包装函数
                #   hunter-community 把鉴权封成 _uid(request)：
                #       def _uid(request: Request) -> str:
                #           uid = getattr(request.state, "user_id", None)
                #           if not uid: raise HTTPException(401, "需要登录")
                #           return str(uid)
                #   端点里只写 `uid = _uid(request)`，前4 种写法全都匹配不到
                #   —— 因为 **_uid 这个名字里没有 verify/require/check/auth
                #   任何一个词根**，而它偏偏是最自然的命名。
                #   实测后果：hunter-community 16 个包装函数被调 49 次，
                #   判据把16 个文件里的端点全判成"无鉴权"→ 69 处假阳性。
                #
                #   ★修法不能是「把 _uid 加进词根表」—— 那是猜名字，
                #     下次叫 _me() / _whoami() / _ctx_user() 就又漏了。
                #   ★ 正确做法：**追进被调函数，看它到底做什么**。
                #     只有当那个函数体里同时出现「读身份」+「拒绝」时，
                #     才算它有鉴权 —— 这与判据 3/4 的语义保持一致。
                elif (_WRAPPER_CALL.search(body_src)
                      or _guard_called_names(body_src, self_name=n.name)):
                    #★★★★★ self_name=n.name —— 排除端点自己的 def 行
                    has_dep = _wrapper_is_auth(module_src, body_src,
                                               self_name=n.name)
            except Exception:
                pass
        routes.append((n.lineno, route_path, has_dep))

    if not routes:
        return
    with_dep = [r for r in routes if r[2]]
    without = [r for r in routes if not r[2]]
    # ★ 必须「同一个文件里两种都有」才报，否则单机工具会满屏误报
    if not with_dep or not without:
        return

    for ln, p, _ in without:
        if _is_exempt_path(p):
            continue
        # ★★ 排除自定义鉴权装饰器（@require_auth 之类）——
        #   这类装饰器的名字在装饰器行上，不在参数默认值里
        deco = ""
        for d in ast.walk(tree):
            if isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and d.lineno == ln:
                for dd in d.decorator_list:
                    try:
                        deco += ast.unparse(dd) + " "
                    except Exception:
                        pass
        if AUTH_HINT.search(deco) or AUTH_EXEMPT_HINT.search(deco):
            continue
        sl = lines[ln - 1].strip()[:140] if 0 < ln <= len(lines) else ""
        out["inconsistent_auth"]["hits"].append({
            "file": path, "line": ln,
            "kind": "同文件内 %d/%d 个端点有鉴权，这个没有" % (
                len(with_dep), len(routes)),
            "text": sl,
        })
        out["inconsistent_auth"]["n_hits"] += 1
        if path not in out["inconsistent_auth"]["hit_files"]:
            out["inconsistent_auth"]["hit_files"].append(path)


def _find_unauth_endpoints(tree, lines, path, out):
    """找出对外路由里没有鉴权痕迹的。"""
    # 先建立：模块级出现的鉴权符号（粗但有效 —— 宁可多报）
    module_auth = bool(AUTH_HINT.search("\n".join(lines)))
    #★★★★★ 第 9 种写法：router 级 dependencies（与 inconsistent_auth 同步）
    #   ★★ 两条判据**必须同步** —— 否则会出现
    #     「inconsistent_auth 说它有鉴权、unauth_endpoint 说它没有」
    #     的自相矛盾，而两条数字都不能信。
    router_guards = _collect_router_guards(tree)

    #★★★★★ 先收集所有「装饰器节点」的身份（10-05 新加）。
    #   为什么要单独收一遍：装饰器 `@router.get("/x")` 本身**也是一个 Call 节点**。
    #   形式一（挂在 def 上）和形式二（裸调用）会同时匹配到它 → 同一个端点
    #   被报两次（自测 4.1/4.2 就是这么炸出来的：2 处变 4 处）。
    #   ★ 这类重复不报错、不崩，只是数字翻倍 —— 靠 `seen` 去重救不了，
    #     因为两条记录的 route 字符串不一样。
    deco_ids = set()
    for _n in ast.walk(tree):
        if isinstance(_n, (ast.FunctionDef, ast.AsyncFunctionDef,
                           ast.ClassDef)):
            for _d in _n.decorator_list:
                deco_ids.add(id(_d))

    routes = []
    for node in ast.walk(tree):
        # 形式一：@app.get("/x") 装饰器
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                try:
                    dn = ast.unparse(d)
                except Exception:
                    continue
                # ★ 必须确认载体是路由对象（app/router/...），不是任意 .get
                m = re.match(r"^\s*@?([\w\.]+)\.(%s)\s*\(\s*[\"']([^\"']*)"
                             % "|".join(ROUTE_VERBS), dn)
                if not m:
                    continue
                base = m.group(1).split(".")[-1]
                if base not in ROUTE_BASES:
                    continue
                route = "%s.%s %s" % (m.group(1), m.group(2), m.group(3))
                # ★★ 局部变量叫 rpath，**不要叫 path** ——
                #   `path` 是本函数的入参（文件路径）。
                #   10-05：这里原来复用了 `path`，导致
                #     ① evidence 的 "file" 字段存成了路由路径（/chat、/），
                #        核实的时候根本不知道命中在哪个文件；
                #     ② hit_files 也用同一个值 → files_top 里
                #        27 处命中被压成 9 个「路由路径」桶，
                #        数据源分布完全失真。
                rpath = m.group(3)
                deco_src = dn
                body_src = "\n".join(lines[node.lineno - 1:
                                          min(len(lines),
                                              (node.end_lineno or node.lineno))])
                # ★★ 看**签名里的 Depends**：FastAPI 的鉴权写在参数默认值里
                #   （user: User = Depends(get_current_user)），
                #   只搜函数体文本会漏掉它。
                sig_src = "\n".join(lines[node.lineno:
                                        min(len(lines), node.lineno + 12)])
                # ★★★★★★ 但**别名匹配只能用精确的签名参数注解**，
                #   不能用上面那个 12 行窗口。
                #   ★ 这不是我猜的，是自测档 4.1 打出来的：
                #       @router.get('/nope')
                #       async def nope():
                #           note = 'CurrentUser'   ← 函数体里只是提到这个名字
                #       12 行窗口把这一行吞进去了 → 别名命中 → 端点被误认成有鉴权。
                #   → **这是假阴性方向（吃掉真阳性），比假阳性危险。**
                #   正确做法：用 ast.unparse 拿参数列表，不看函数体。
                try:
                    sig_ann = ast.unparse(ast.arguments(
                        posonlyargs=node.args.posonlyargs,
                        args=node.args.args,
                        vararg=node.args.vararg,
                        kwonlyargs=node.args.kwonlyargs,
                        kw_defaults=node.args.kw_defaults,
                        kwarg=node.args.kwarg,
                        defaults=node.args.defaults))
                except Exception:
                    sig_ann = sig_src
                has_auth = bool(AUTH_HINT.search(deco_src + "\n" + sig_src
                                                 + "\n" + body_src))
                # ★★★★★ 第 9 种写法：router 级 dependencies
                if not has_auth and router_guards:
                    for _d in node.decorator_list:
                        rv = _router_var_of_deco(_d)
                        if rv and rv in router_guards:
                            has_auth = True
                            break
                # ★ 中间件注入型（第4 种写法）：两个条件必须同时成立
                if not has_auth and AUTH_MIDDLEWARE.search(body_src) \
                        and AUTH_DENY.search(body_src):
                    has_auth = True
                # ★★★★★★★ 第 7 种写法（类型别名注入）—— 跨文件（10-05 补）
                #   别名定义在 dependencies.py，路由文件只 import 它：
                #       # src/backend/dependencies.py
                #       AuthorizedAgentByName = Annotated[str, Depends(get_authorized_agent_by_name)]
                #       # src/backend/routers/agents.py
                #       @router.get("/{agent_name}/terminal")
                #       async def terminal(agent_name: AuthorizedAgentByName, ...)
                #   ★ 机制早就有了（`_find_inconsistent_auth` 一直在用），
                #     **唯独这条判据没接** → 同一个别名在 inconsistent_auth 里
                #     被认得出来、在 unauth_endpoint 里认不出，
                #     两边自相矛盾。
                #   实测代价（measure_crossfile_alias.py 量29 个项目）：
                #     trinity 16 处（占它 64 处基数的 25%）+ jarvis 7 处。
                if not has_auth and _ALL_MODULE_SRC:
                    for al in _auth_aliases():
                        # ★★ 只看 **sig_ann**（精确的参数注解），不看 sig_src
                        if re.search(r"\b%s\b" % re.escape(al), sig_ann):
                            has_auth = True
                            break
                # ★ 第 6 种写法：自定义包装函数（如 _uid(request)）。
                #   ★ 与 _find_inconsistent_auth 里那处保持同一套逻辑 ——
                #   同一个盲区在两条判据里都要补，否则会出现
                #   「inconsistent_auth 说它有鉴权、unauth_endpoint 说它没有」
                #   的自相矛盾，两条数字都不能信。
                if not has_auth and (_WRAPPER_CALL.search(body_src)
                                  or _guard_called_names(body_src,
                                                        self_name=node.name)):
                    has_auth = _wrapper_is_auth("\n".join(lines or []),
                                                body_src,
                                                self_name=node.name)
                # ★ 本来就不该有鉴权的端点（注册/登录/健康检查…）
                exempt = bool(_is_exempt_path(rpath)
                              or AUTH_EXEMPT_HINT.search(deco_src + body_src))
                routes.append((node.lineno, route, has_auth, None, rpath, exempt))
        # ★★★★★★ 形式二（`app.post("/x", handler)` 裸调用）：**故意保持关闭**。
        #
        #   历史：这里原来写的是 `_name(node)`，它只 unparse `node.func`，
        #   得到 `"app.post"`（不含实参），而正则在`("` 处就断了
        #   → 这条分支**从来没匹配到过任何东西**，是个死分支。
        #
        #   10-05：我把它改活（`ast.unparse(node)`），跑全量 29 个项目量净效应，
        #   结果是**114 处业务命中，逐条看全是字典取键**：
        #       blueprint.get('topology')     route.get('target')
        #       server.get('name')            api.get('auth')
        #       web.get('title')              app.get('app_token')
        #   载体名 app/blueprint/route/server/web 全在 ROUTE_BASES 里，
        #   第一个参数又都是字面量字符串 → **语法上和路由注册无法区分**。
        #   加「≥2 个参数」后还剩 26 处，逐条看**仍然全是字典取键**
        #   （`route.get('legs', None)` 这种两参数取键）。
        #
        #   ★★ 结论：这条路走不通，已回滚。
        #      「死分支」在这里反而是安全状态 —— 它匹配不到东西，
        #      所以不产生误报。而**声称支持某种写法**，
        #      比不声称更危险：它让人以为「这种写法我们查过了，结论是干净的」。
        #
        #   ★★ 真要支持裸调用式路由，可行的判别信号不是参数个数，
        #      而是「这个对象在本文件里被构造成路由容器」的证据
        #      （例如 `app = FastAPI()` / `bp = Blueprint(__name__)`）
        #      —— 那需要跨语句的数据流分析，成本远大于收益。
        #      ★ 若将来真要做，**先在这29 个项目上量净效应**，
        #        别又拿「跑出来了」当「跑对了」。
        if False:                                        # noqa: SIM102
            if isinstance(node, ast.Call) and id(node) not in deco_ids:
                try:
                    nm = ast.unparse(node)
                except Exception:
                    nm = _name(node)
                m = re.match(r"^([\w\.]+)\.(%s)\s*\(\s*[\"']([^\"']*)"
                             % "|".join(ROUTE_VERBS), nm)
                if not m:
                    continue
                if m.group(1).split(".")[-1] not in ROUTE_BASES:
                    continue
                rpath = m.group(3)
                ln = node.lineno
                ctx = "\n".join(lines[max(0, ln - 12):min(len(lines),
                                                        ln + 14)])
                has_auth = bool(AUTH_HINT.search(ctx))
                exempt = bool(_is_exempt_path(rpath)
                              or AUTH_EXEMPT_HINT.search(ctx))
                routes.append((ln, "%s %s" % (m.group(1), m.group(2)),
                               has_auth, True, rpath, exempt))
                continue
            continue
        if isinstance(node, ast.Call) and id(node) in deco_ids:
            # 装饰器形式的 Call 归形式一管
            continue
        # ★ 形式二已在上方 `if False:` 处关闭（原因见那段注释）——
        #   到这里为止只处理完形式一。

    seen = set()
    for item in routes:
        ln, route, has_auth, inline = item[0], item[1], item[2], item[3]
        rpath = item[4] if len(item) > 4 else ""
        exempt = item[5] if len(item) > 5 else False
        key = (ln, route)
        if key in seen:
            continue
        seen.add(key)
        # ★ 有鉴权 → 不报；★ 本来就不该有鉴权 → 也不报（那是噪音）
        if has_auth or exempt:
            continue
        sl = lines[ln - 1].strip()[:140] if 0 < ln <= len(lines) else ""
        # ★★ "file" 必须是**文件路径**（入参 path），不是路由路径。
        #   路由路径另存到 "route" —— 核实的时候两个都要看。
        out["unauth_endpoint"]["hits"].append({
            "file": path, "route": rpath, "line": ln,
            "kind": "路由无鉴权痕迹" + ("（本文件其它地方有鉴权）" if module_auth else ""),
            "text": sl})
        out["unauth_endpoint"]["n_hits"] += 1
        if path not in out["unauth_endpoint"]["hit_files"]:
            out["unauth_endpoint"]["hit_files"].append(path)


def analyze_files(files, skip_tests=True):
    """对 {path: text} 跑判据。返回 (结果, 解析失败清单)。

    ★★★★★★ skip_tests：排除测试文件（10-05 补，我从第一版就漏了）。
      起因：核实 jarvis-registry 时看到
          registry/tests/unit/middleware/test_rbac.py:412  def stats():
      —— 测试夹具用 @app.get 造了假路由，被判成「同文件内 1/25 不一致」。
      回头量全部批次：**抽样 evidence 里 97% 来自测试文件，6 个 cell 全中**。
      这是判据级缺陷，不是项目个例。

      ★ 判定逻辑放在独立模块 is_test_path.py，**不在这里内联**：
        判据哈希是批次版本锁的锚点，动主干会让正在跑的批次全部作废；
        而「哪些路径算测试」是要反复调的规则 → 拆出去才能反复调而不动主干。
        （反向误杀的坑见 is_test_path 的注释：src/test_utils.py 是生产模块。）

      ★ 排除范围只影响**计入统计的文件**，不减少覆盖率分母里的 total_py
        —— 否则「覆盖率」会变成另一个含义的指标。
    """
    # ★★★★★ 第 7 种写法（类型别名注入）必须**跨文件**才能认出来：
    #   别名定义在 dependencies.py，路由文件只 import 它 →
    #   单文件扫必然漏（我第一版就写成了单文件，等于没修）。
    #   所以在**这个入口**做第 1 趟：全量收集鉴权别名，
    #   存进模块级变量供第 2 趟的_find_inconsistent_auth 读取。
    global _ALL_MODULE_SRC
    _ALL_MODULE_SRC = "\n".join(
        t for p, t in sorted(files.items()) if p.endswith(".py"))
    # ★★★★★★ 别名**在这里算一次**，缓存给两条判据用（10-07 补）。
    #   起因：两条判据都在**每个文件**内部读别名，
    #   而 `_collect_auth_aliases` 要扫整个 `_ALL_MODULE_SRC`
    #   —— 实测 Clawith 597 文件 / 865 万字符，
    #   单次 0.16 秒 × 595 个业务文件 = **92 秒白花**，
    #   而且那个项目一个别名都没有（纯浪费）。
    _AUTH_ALIASES_CACHE[0] = (None, set())   # 先清空，让 _auth_aliases() 自愈重算
    _auth_aliases()                          # ★ 在这里算一次，两条判据共用
    # ★★ 同理清空 `_def_body_in` 的缓存 ——它的键是 `id(src)`，
    #   而**上一个项目的 `_ALL_MODULE_SRC` 可能已被Python 回收**，
    #   新对象复用了同一个 id → 会拿到上一个项目的函数体。
    #★ 这是 id() 当缓存键的固有风险，必须在换项目时显式清。
    _DEF_BODY_CACHE.clear()

    agg = {}
    failed = []
    skipped_tests = 0
    for p, t in sorted(files.items()):
        if not p.endswith(".py"):
            continue
        if skip_tests:
            try:
                from is_test_path import is_test_path
            except ImportError:
                is_test_path = None
            if is_test_path is not None and is_test_path(p):
                skipped_tests += 1
                continue
        res, err = analyze(t, p)
        if err:
            failed.append({"file": p, "error": err})
            continue
        for k, v in res.items():
            agg.setdefault(k, {"label": v["label"], "hits": [],
                               "n_hits": 0, "hit_files": []})
            agg[k]["hits"].extend(v["hits"])
            agg[k]["n_hits"] += v["n_hits"]
            agg[k]["hit_files"] = sorted(set(agg[k]["hit_files"] + v["hit_files"]))
    # ★★ 「排掉多少测试文件」要随结果一起报出去 —— 不说清的话，
    #   别人看到 n_hits 变小会以为判据变严了，而不知道是数据源被过滤了。
    #
    #   ★★★ 但**绝对不能塞进 agg**（10-05 07:5x 踩过）：
    #   agg 里所有 value 都是同构的判据 cell（都有 n_hits / hits / label），
    #   而下游有 **6 处** `for k, v in agg.items()`（recheck / scan / cmp / backfill…）
    #   → 塞一个异构的 `_meta` 进去 = 给全部 6 处埋雷。
    #   ★ 实测后果：6 个分片全部跑到最后一步才 KeyError: 'n_hits'崩掉，
    #     每个白跑 5-8 分钟。
    #   → 走**模块级变量**，与 agg 物理隔离。
    global LAST_RUN_META
    LAST_RUN_META = {
        "skipped_test_files": skipped_tests,
        "analyzed_files": sum(1 for p in files
                              if p.endswith(".py")) - skipped_tests,
        "total_py": sum(1 for p in files if p.endswith(".py")),
        "skip_tests": bool(skip_tests),
    }
    return agg, failed


# ★★ 模块级：最近一次 analyze_files 的元信息（**与 agg 物理隔离**）
LAST_RUN_META = {}