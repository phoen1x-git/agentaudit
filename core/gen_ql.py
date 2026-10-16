"""内核 · QL 代码生成器（把 sinks.yml 变成真的 QL）。

    python -m core.gen_ql

做的事：
  1. 读AgentFuzz的 `ql/call/call.qll`，把里面的 `predicate is_sink` **改名**成 `is_sink_paper`
     （正文一个字不改 —— 基线必须原封不动）
  2. 用 `core/config/sinks.yml` 里 `source: extra` 的条目**生成** `is_sink_config`
  3. 追加 `predicate is_sink(cn) { is_sink_paper(cn) or is_sink_config(cn) }`
  4. 连同 util.qll 与三条查询，输出成一个**我们自己的 ql pack**（core/ql/）

★ 设计要点：**extra 为空时，is_sink 语义与AgentFuzz完全一致**。
  这是"开关可信"的前提 —— 不然开关一拨，变的不只是你想变的那个变量。

★ 为什么用"改名 + 并集"而不是"直接改 is_sink"：
  改了就没法回到基线了；并集可以（把 extra 清空即可）。
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
# Reference QL pack from the AgentFuzz paper release. It is only needed to *regenerate*
# the queries; the committed core/ql/*.ql work without it. Override with AF_PAPER_QL.
PAPER_QL = Path(os.environ.get("AF_PAPER_QL", str(ROOT / "agentfuzz-official" / "ql")))
OUT_QL = ROOT / "core" / "ql"
QUERIES = ["get_callchain_and_location.ql", "get_if.ql",
           "get_dataflow_str_constraint.ql"]


def _rename_predicate(src: str, name: str, new_name: str) -> tuple[str, str]:
    """把 `predicate <name>(...)  { ... }` 整体改名，返回 (新文本, 原正文)。"""
    marker = f"predicate {name}("
    i = src.find(marker)
    if i < 0:
        raise SystemExit(f"[FAIL] AgentFuzz call.qll 里找不到 {marker}")
    brace = src.find("{", i)
    if brace < 0:
        raise SystemExit("[FAIL] 找不到谓词体起始 `{`")
    depth, j = 0, brace
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    body = src[brace + 1:j]
    head = src[i:brace]
    new_head = head.replace(f"predicate {name}(", f"predicate {new_name}(", 1)
    # ★ 别把开头的 `{` 丢了 —— head 是 [i, brace)，不含花括号（踩过：丢了 `{`，
    #   谓词体和签名连在一起，报出一串莫名其妙的 "predicate cn2() conflicts"）
    return src[:i] + new_head + "{" + body + "}" + src[j + 1:], body


# ---------- util.qll 的路径过滤（★ 接线）----------
_UTIL_DOC_REL = """// ======== 路径过滤（由 core/gen_ql.py 生成，不要手改）========
// ★ 修的是什么：
//   AgentFuzz用 `s.matches("%test%")` 判路径（s = loc.toString()，**绝对路径**）
//   → **仓库目录名里含 "test" 就整仓被排除**。
//   实证：目标 `firetix/vibe-coding-penetration-**tester**`
//     · 修前：`[parse] 原始结果 0 条`（主查询空，而 argsrc 仍报 36 个 sink 位置）→ **假 0**
//     · 修后：`[parse] 原始结果 48 条` → 去重 11 条 → 判定层出 **vuln ×1**
//   同批 TaintP2X 里被整仓杀掉的还有 `GreyDGL/PentestGPT`（名字含 "pentest"）。
//   ★ 这是一整类：**任何取名带 pentest / tester / latest / contest 的 Agent 项目都会被静默跳过**。
// ★ 最小单变量修复：**把黑名单作用在 `getRelativePath()` 上**（去掉仓库目录名那一段），
//   其余语义（tests/ demo/ example/ 都排除）与AgentFuzz**逐字一致**。
"""

_UTIL_DOC = """// ======== 路径过滤（由 core/gen_ql.py 从 core/config/filters.yml 生成，不要手改）========
// ★ 为什么替换AgentFuzz的 isIncludeLocation2：
//   AgentFuzz是**子串黑名单** ["test","miniconda","demo","example","qltracer","newrepo","Python39"]，
//   判法是 `s.matches("%test%")` → **路径里任何位置含 "test" 就整仓被排除**。
//   ★ 实测踩到：目标 `firetix/vibe-coding-penetration-**tester**`（目录名含 "test"）
//     → 该目标**每一个文件被过滤** → 主查询 `原始结果 0 条`（而 argsrc 仍报 36 个 sink 位置）
//     → **一个整仓的假阴性（假 0）**，不是"漏一条"。
//   ★ 改法就是 filters.yml 头部早写好的三层设计（只是从没接线）：
//     ① 路径**段**精确匹配  ② 文件名正则  ③ 少数子串兜底（环境路径）。
//   开关：`AF_PATH_FILTER=0`（或 paper）→ 原样拷AgentFuzz的 util.qll。
"""


def _qlist(xs: list[str]) -> str:
    return "[" + ", ".join(
        '"' + str(x).replace("\\", "\\\\").replace('"', '\\"') + '"' for x in xs) + "]"


def _drop_block(src: str, head: str) -> str:
    """删掉 `head ... { ... }`（含其前面的 `bindingset[...]` 行）。"""
    i = src.find(head)
    if i < 0:
        return src
    brace = src.find("{", i)
    if brace < 0:
        return src
    depth, j = 0, brace
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    s = src[:i] + src[j + 1:]
    # 顺手把紧邻的 `bindingset[s]` 行去干净（否则报 "'s' is not an argument"）
    s = s.replace("bindingset[s]\n\n\n", "").replace("bindingset[s]\n\n", "")
    return s


def _util_qll() -> tuple[str, str]:
    """生成 util.qll 的【路径过滤】片段。返回 (QL 片段, 模式)。

    模式（`AF_PATH_FILTER`）：
      · `paper` / `0`  → 原样拷AgentFuzz（**基线**）
      · `rel`（**默认**）→ AgentFuzz那串子串黑名单，但**作用在 `getRelativePath()`** 上
                          ★ 这是**最小单变量修复**：只去掉"仓库目录名"这一段，
                            其余语义（tests/ demo/ example/ 一律排除）**与AgentFuzz逐字一致**。
      · `yml`          → `filters.yml` 的三层规则（段/文件名/子串）—— 更精确，但会
                          *放开* `testing_util.py` 这类原本被误伤的文件 → 属另一变量。
    """
    mode = os.environ.get("AF_PATH_FILTER", "rel").strip().lower()
    if mode in ("0", "paper", "off", "false"):
        return "", "paper"

    # AgentFuzz原黑名单（小写，用于相对路径）
    paper_subs = ["test", "miniconda", "demo", "example", "qltracer", "newrepo", "python39"]

    if mode != "yml":
        return _UTIL_DOC_REL + f'''
string substringBlack() {{ result = {_qlist(paper_subs)} }}

// ★ 兼容：AgentFuzz原列表
string getBlacklist() {{ result = ["test", "miniconda", "demo", "example", "qltracer", "newrepo", "Python39"] }}

predicate isIncludeLocation2(Location loc) {{
  exists(string p | p = loc.getFile().getRelativePath().replaceAll("\\\\", "/").toLowerCase() |
    // ★ 关键：用**相对路径**（去掉仓库目录名）→ "…-penetration-tester" 这类仓库名不再整仓被杀
    forall(string b | b = substringBlack() | not p.matches("%" + b + "%")))
}}

bindingset[s]
predicate isIncludeLocationStr(string s) {{
    forall(string black | black = substringBlack() | not s.matches("%" + black + "%"))
 }}

predicate isIncludeLocation(Location loc) {{ isIncludeLocation2(loc) }}
''', "rel(相对路径 + AgentFuzz原黑名单)"

    cfg = yaml.safe_load(
        (ROOT / "core" / "config" / "filters.yml").read_text(encoding="utf-8")) or {}
    segs = [str(x) for x in (cfg.get("path_segments") or [])]
    res = [str(x) for x in (cfg.get("filename_re") or [])]
    subs = [str(x) for x in (cfg.get("substrings") or [])]

    # ★ QL 坑（都实测踩过）：
    #   ① `string` 没有 split() → "split(string) cannot be resolved"；
    #   ② **独立谓词里用 `p.matches(pat)` 会报 "p is not bound to a value"**（matches 不产绑定）
    #      → 把段匹配**内联**进主谓词（p 在 `exists` 里已绑）。
    ql = _UTIL_DOC + f'''
predicate pathSegBlack(string x) {{ x = {_qlist(segs)} }}

string filenameRe() {{ result = {_qlist(res)} }}

string substringBlack() {{ result = {_qlist(subs)} }}

// ★ 兼容：AgentFuzz原列表（别的查询可能引用）
string getBlacklist() {{ result = ["test", "miniconda", "demo", "example", "qltracer", "newrepo", "Python39"] }}

predicate isIncludeLocation2(Location loc) {{
  exists(string p |
      p = loc.getFile().getAbsolutePath().replaceAll("\\\\", "/").toLowerCase()
    |
      // ① 路径**段**精确匹配（模式 %/段名/%；位置都是文件，被点名的目录段必以 /段名/ 出现）
      not exists(string seg, string pat |
            pathSegBlack(seg) and pat = "%/" + seg + "/%" and p.matches(pat))
      and
      // ② 文件名正则（test_*.py / *_test.py / conftest.py …）
      not exists(string re | re = filenameRe() |
                   loc.getFile().getBaseName().toLowerCase().regexpMatch(re))
      and
      // ③ 子串兜底（miniconda / python39 这类环境路径）
      not exists(string b | b = substringBlack() | p.matches("%" + b + "%")))
 }}

bindingset[s]
predicate isIncludeLocationStr(string s) {{
    forall(string black | black = substringBlack() | not s.matches("%" + black + "%"))
 }}

// deprecated（AgentFuzz baseline，保留但换成同样的段规则）
predicate isIncludeLocation(Location loc) {{ isIncludeLocation2(loc) }}
'''
    return ql, f"filters.yml(seg={len(segs)}/re={len(res)}/sub={len(subs)})"


def _write_util_qll() -> str:
    """AgentFuzz util.qll 去掉 3 个定义 + 追加 filters.yml 生成的过滤。"""
    import re
    src = (PAPER_QL / "util" / "util.qll").read_text(encoding="utf-8")
    gen, mode = _util_qll()
    if not gen:
        (OUT_QL / "util" / "util.qll").write_text(src, encoding="utf-8")
        return mode
    for head in ("predicate isIncludeLocation2(Location loc)",
                 "predicate isIncludeLocationStr(string s)",
                 "predicate isIncludeLocation(Location loc)",
                 "string getBlacklist()"):
        src = _drop_block(src, head)
    # ★ 删块后会留下**孤儿的 `bindingset[s]` 行** → 报 "'s' is not an argument to this predicate"
    #   （实测踩到）。AgentFuzz那部分只用它标 isIncludeLocationStr，而那已被删 → 全清。
    src = re.sub(r"[ \t]*bindingset\[s\][ \t]*\n", "", src)
    src = re.sub(r"\n{3,}", "\n\n", src).rstrip() + "\n"
    (OUT_QL / "util" / "util.qll").write_text(src + "\n" + gen, encoding="utf-8")
    return mode


def _clause(s: dict) -> str:
    """一条 sink → 一段 QL 子句。"""
    fn = s.get("func")
    obj = s.get("obj")
    name = s.get("name")
    if name:
        return f'cn.getFunction().(NameNode).getNode().toString() = "{name}"'
    if obj == "*":
        # ★ 任意对象：只看方法名。会很吵 —— 这是**故意**的，实验要测这个代价。
        return f'cn.getFunction().(AttrNode).getNode().getName() = "{fn}"'
    # ★★ obj_suffix：对象名**以某串结尾**即可命中。用途：一条规则同时覆盖
    #    `conn.query(...)` 与 `self.conn.query(...)` —— 精确 `obj=` 只能匹配前者，
    #    会把 bigquery_vector 那几条真阳漏掉。
    #    `getObject().getNode().toString()` 对 `self.conn.query` 给的是 "self.conn"，
    #    所以用 endsWith 而不是 =。
    osfx = s.get("obj_suffix")
    if osfx:
        # ★★ 必须**两条路**都查：
        #    `conn.query(...)` 的接收者是 Name 节点 → toString() = "conn"；
        #    但 `self.conn.query(...)` 的接收者是 Attribute 节点 →
        #    toString() 只给出类名 "Attribute"（不是 "self.conn"！）。
        #    the baseline也只用 toString()，所以它同样认不出 `self.X.method(...)` ——
        #    这是它只硬编码 requests/os/subprocess 这类模块级名字的原因。
        #    对 Attribute 节点必须改用 `.getNode().getName()` 取属性名。
        return (f'(cn.getFunction().(AttrNode).getNode().getName() = "{fn}" and\n'
                f'  (\n'
                f'   cn.getFunction().(AttrNode).getObject().getNode().toString()'
                f'.regexpMatch(".*{osfx}")\n'
                f'   or\n'
                f'   cn.getFunction().(AttrNode).getObject().(AttrNode)'
                f'.getNode().getName().regexpMatch(".*{osfx}")\n'
                f'  ))')
    if obj:
        return (f'(cn.getFunction().(AttrNode).getNode().getName() = "{fn}" and\n'
                f'   cn.getFunction().(AttrNode).getObject().getNode().toString() = "{obj}")')
    # ★★ obj2：**两层属性**的对象，形如 `os.path.join(...)`。
    #   实测：对 `os.path.join`，
    #     getObject().getNode().toString()          = "Attribute"（类名！不是 "os.path"）
    #     getObject().(AttrNode).getNode().getName() = "path"     （外层属性名）
    #   所以 `obj: os.path` 永远匹配不上。正确形态要**往下再钻一层**：
    #     外层属性名 == 点号后的那段（"path"）
    #     且 外层属性的对象 toString() == 点号前的那段（"os"）
    #   obj2 写成 "os.path" → 拆成 (head="os", tail="path")。
    obj2 = s.get("obj2")
    if obj2:
        head, _, tail = str(obj2).rpartition(".")
        return (f'(cn.getFunction().(AttrNode).getNode().getName() = "{fn}" and\n'
                f'   cn.getFunction().(AttrNode).getObject().(AttrNode)'
                f'.getNode().getName() = "{tail}" and\n'
                f'   cn.getFunction().(AttrNode).getObject().(AttrNode)'
                f'.getObject().getNode().toString() = "{head}")')
    # 只给方法名（不带对象）
    return f'cn.getFunction().(AttrNode).getNode().getName() = "{fn}"'


def _ql_str_list(names) -> str:
    return "[" + ", ".join(f'"{n}"' for n in names) + "]"


def _method_objchk(s) -> str:
    """`kind: method` 的**可选**接收者约束：只有调用接收者（属性链最末一段属性名）匹配才算源。

    ★ 为什么需要：`create` / `run` / `query` / `call` / `execute` 这类通用方法名到处都有，
      裸加会把 ORM 的 `Model.objects.create()`、`cursor.execute()` 也当成不可信输入，
      刻度当场失控。加约束后只剩 LLM 客户端那一批。

    ★★ 三层踩过的坑（全部是「看起来对、结果静默为空」型）：
      ① 不能包 `exists(...)` 引用外层绑定变量 `c` —— 嵌套 exists 触发 CodeQL 变量提升 →
         各分支绑定变量被提升成同名谓词 → "predicate c() conflicts" → **整包编译失败**。
      ② **不能**用 `toString()` 取接收者文本：CodeQL 的 `toString()` 对 `Name` 给标识符，
         对**链式属性 `client.chat.completions` 只给通用串 "Attribute"**
         （CFG 层是 "ControlFlowNode for Attribute"，AST 层同样只给 "Attribute"）→
         约束恒为假 → 整个 method 分支静默失效。自检 `tools/ab_sources_selftest.py` 逮到的。
      ③ 改用 `getObject().(Attribute).getName()`：对属性链给**最末一段属性名**
         （`client.chat.completions.create` → `completions`；`client.messages.create` → `messages`）。
         ✅ 这正好是真实 SDK 的书写形态；接收者是裸名字时类型转换失败 → 该分支不命中（保守，符合预期）。
      ★ 已知边界：TaintP2X 的原始定义是「全限定名 / 类型级」，我们只能做「语法级」——
        能对齐的只有**方法名字符串**与**属性链末段**，拿不到类型。这是**有意接受的近似**，不藏着。

    ★ 空值 → 返回空串，生成的 QL 与加此特性**之前逐字一致**（默认行为不变）。
    """
    names = s.get("obj_names")
    if not names:
        return ""
    if isinstance(names, str):
        names = [names]
    return (f'    c.getFunction().(AttrNode).getNode().(Attribute)'
            f'.getObject().(Attribute).getName() in {_ql_str_list(names)} and\n')


def _sources_qll() -> tuple[str, str, list]:
    """由 `core/config/sources.yml` 生成跨过程污点的两个文件（开关 dataflow-argsource）。

    ★★ 为什么必须**拆成两个文件**（踩过，报错信息还指错方向）：
       dataflow 库里定义了 `module Flow = Shared::Flow<...>`（VariableCapture.qll:125）。
       任何 `import ...DataFlow` 的文件，其作用域里就有了 `Flow` →
       **`CallNode` 会被解析成 `Flow::CallNode`（一个 dataflow 类，不是 AST 类）**，
       于是 `getArg(i).getAFlowNode()` 这类 AST 用法全部报
       "getAFlowNode() cannot be resolved for type Flow::ControlFlowNode"。
       → 把**只碰 AST**的谓词放进 `argsource_ast.qll`（它不 import dataflow），
         Config 放进 `argsource_cfg.qll`（import dataflow，但只用 `DataFlow::Node`）。
       ★ 两边不冲突的原因：`Flow::ControlFlowNode` 只是 AST `ControlFlowNode` 的**别名**
         （同一个 `@py_flow_node`），类型互通。
    """
    # ★ 可叠加的 source 表（开关 AF_SOURCES_FILE=<路径>，相对路径按仓库根解析）。
    #   ★ 默认**不加载** → A 组行为与加此特性之前逐字一致。
    #   用途：把外部知识（例：TaintP2X 的 94 条 LLM 接口定义）作为**单变量**加进来做 A/B。
    src_files = [ROOT / "core" / "config" / "sources.yml"]
    _extra_f = os.environ.get("AF_SOURCES_FILE", "").strip()
    if _extra_f:
        _p = Path(_extra_f)
        if not _p.is_absolute():
            _p = ROOT / _p
        if _p.exists():
            src_files.append(_p)
        else:
            print(f"★ [sources] AF_SOURCES_FILE 指向的文件不存在，已忽略：{_p}")
    # ★ 按 id 去重（先加载者优先）—— 防止两个文件里出现同 id 导致条目重复计数。
    srcs, _seen_ids = [], set()
    for _fp in src_files:
        _cfg = yaml.safe_load(_fp.read_text(encoding="utf-8"))
        for s in (_cfg.get("sources") or []):
            if s.get("enabled", True) and s.get("id") and s["id"] not in _seen_ids:
                _seen_ids.add(s["id"])
                srcs.append(s)
    if os.environ.get("AF_SOURCES_EXTRA", "1") == "0":
        srcs = []                     # ★ 关掉 = 只保留"函数参数"这一档（最保守基线）

    clauses = []
    ids = []
    for s in srcs:
        kind = s.get("kind")
        names = _ql_str_list(s.get("names") or [])
        if kind == "method":
            _objchk = _method_objchk(s)
            clauses.append(
                f'  exists(CallNode c, string nm |\n'
                f'    cn = c and\n'
                f'    c.getFunction().(AttrNode).getNode().getName() = nm and\n'
                f'{_objchk}'
                f'    nm in {names} and\n'
                f'    k = "{s["id"]}")')
        elif kind == "attr":
            objchk = (f'    a.getObject().toString().regexpMatch(".*{s["obj_suffix"]}") and\n'
                      if s.get("obj_suffix") else "")
            clauses.append(
                f'  exists(Attribute a, string nm |\n'
                f'    cn = a.getAFlowNode() and\n'
                f'{objchk}'
                f'    a.getName() = nm and\n'
                f'    nm in {names} and\n'
                f'    k = "{s["id"]}")')
        elif kind == "name":
            clauses.append(
                f'  exists(CallNode c, string nm |\n'
                f'    cn = c and\n'
                f'    c.getFunction().(NameNode).getNode().toString() = nm and\n'
                f'    nm in {names} and\n'
                f'    k = "{s["id"]}")')
        else:
            continue
        ids.append(s["id"])

    src_block = "\n  or\n".join(clauses) if clauses else "  none()"
    src_block = src_block

    ast_qll = f"""// ★ 由 core/gen_ql.py 从 core/config/sources.yml 生成，不要手改。
// ★★ 本文件**故意不 import dataflow 库** —— 一旦 import，`CallNode` 会被解析成
//    dataflow 的类，下面所有 AST 用法都会报"cannot be resolved"。详见 gen_ql.py。
import python
import call.call

/** sink 调用的实参节点（AST 层）。★ `CallNode.getArg(i)` 返回的就是 ControlFlowNode。 */
predicate isSinkArgCfg(ControlFlowNode cn) {{
  exists(CallNode c, int i |
    is_sink(c) and
    cn = c.getArg(i)
  )
}}

/**
 * 实参节点的「来源种类」（AST 层）。
 * 同一节点可能匹配多条 → 由查询层按优先级取。
 * （`param` 那一档在 argsource_cfg.qll 里，因为要用 dataflow 的 ParameterNode。）
 */
predicate srcKindCfg(ControlFlowNode cn, string k) {{
{src_block}
}}
"""

    # ★★ 开关 AF_ARGFLOW_ATTR（默认 **0 = 现状**）：
    #    补「属性读取」污点步。为什么需要：
    #      · `x = llm.invoke(...)` → `sink(x)`          ✅ 能追到
    #      · `r = client.chat.completions.create(...)` → `sink(r)` ✅ 能追到
    #      · 但 `sink(r.choices)` / `sink(r.choices[0].message.content)` ❌ 追不到
    #      · 而 `x`（参数）→ `sink(x[0])`                 ✅ 能追到（下标本身通）
    #    → **断点是「属性读取」**：`ArgSourceCfg` 实现的是 `DataFlow::ConfigSig`（值流），
    #      塞进 `TaintTracking::Global` 后**没有 taint steps** → `x.y` 不传播。
    #    ★ 独立开关的理由：本改动与 source 表无关，不能混进 source 的 A/B（单变量原则）。
    _attr_flow = os.environ.get("AF_ARGFLOW_ATTR", "0") == "1"
    if _attr_flow:
        _cfg_impl = """module ArgSourceCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { srcKind(n, _) }
  predicate isSink(DataFlow::Node n) { isSinkArgCfg(n.asCfgNode()) }
}

/** ★ 属性读取的污点步（AF_ARGFLOW_ATTR=1 时才挂）。 */
module AttrFlowX implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { srcKind(n, _) }
  predicate isSink(DataFlow::Node n) { isSinkArgCfg(n.asCfgNode()) }
  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(Attribute a |
      a = n2.asExpr().(Attribute) and
      n1.asExpr() = a.getObject()
    )
  }
}

module ArgFlow = TaintTracking::Global<AttrFlowX>;"""
    else:
        _cfg_impl = """module ArgSourceCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { srcKind(n, _) }
  predicate isSink(DataFlow::Node n) { isSinkArgCfg(n.asCfgNode()) }
}

module ArgFlow = TaintTracking::Global<ArgSourceCfg>;"""

    # These queries do not read CodeQL's Models-as-Data. Bridging the two would be a real
    # improvement -- a MaD model carries a type constraint (`openai.OpenAI`) which is more
    # precise than a bare method name in sources.yml, so it would not catch an unrelated
    # `Model.objects.create()` -- but it needs srcKind to consult
    # `ModelOutput::getASourceNode(...)` (`API::Node::asSource()`), and nothing here passes
    # `--model-packs`.
    _mad_branch = (
        "  or\n"
        "  // ★ MaD（开关 AF_MAD）：只认白名单里的 kind（AF_MAD_KINDS，当前 %s）。\n"
        "  //   桥接靠 `API::Node::asSource()` —— 与 CodeQL 标准库 DataFlowPrivate 同一写法。\n"
        "  (n = ModelOutput::getASourceNode(k).asSource() and (%s))\n"
    ) % ("/".join(_kinds), _kind_cond) if _mad else ""

    cfg_qll = """// ★ 由 core/gen_ql.py 生成，不要手改。
// ★ 本文件 import 了 dataflow 库 → 这里的 `CallNode` 不是 AST 那个，
//   所以**不要在这里写任何 AST 类型**（都在 argsource_ast.qll 里）。详见 gen_ql.py。
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
""" + """import argsource_ast

/** 源头种类：AST 层能认的（见 argsource_ast.qll）+ 函数参数这一档。 */
predicate srcKind(DataFlow::Node n, string k) {
  srcKindCfg(n.asCfgNode(), k)
  or
  (n instanceof DataFlow::ParameterNode and k = "param")
  // ★ 跨过程分析里，参数常常表现为**汇总节点**（toString 形如 "[summary param] position 1 in f"），
  //   它们不是 ParameterNode。不认它们会**静默丢行**（踩过：sample-toolkit exec 的 arg0 消失了）。
  or
  (n.toString().matches("[summary param]%") and k = "param")
""" + """}

""" + _cfg_impl + "\n"
    return ast_qll, cfg_qll, ids


def main() -> int:
    paper_call = (PAPER_QL / "call" / "call.qll").read_text(encoding="utf-8")
    renamed, body = _rename_predicate(paper_call, "is_sink", "is_sink_paper")

    cfg = yaml.safe_load((ROOT / "core" / "config" / "sinks.yml").read_text(encoding="utf-8"))
    # ★ group 开关：每个 group 一类，默认**关**，用环境变量单独开 ——
    #   这样"加某一类 sink"是一次可 A/B 的单变量改动。
    #     group: fs   → AF_SINKS_FS=1    （文件 I/O 类）
    #     group: http → AF_SINKS_HTTP=1  （httpx/aiohttp 类，补 requests→httpx 迁移的缺口）
    _GROUP_ENV = {"fs": "AF_SINKS_FS", "http": "AF_SINKS_HTTP"}

    def _group_on(s: dict) -> bool:
        g = s.get("group")
        if not g:
            return True                       # 无 group → 老行为：默认进
        return os.environ.get(_GROUP_ENV.get(g, "AF_SINKS_" + str(g).upper()), "0") == "1"

    extras = [s for s in (cfg.get("sinks") or [])
              if s.get("source") == "extra" and s.get("enabled", True)
              and s.get("cls") == "direct" and s.get("id")
              and _group_on(s)]
    # ★ AF_SINKS_EXTRA=0 → 生成"空 extra"，即**基线**（必须与AgentFuzz reference pack结果一致）
    if os.environ.get("AF_SINKS_EXTRA", "1") == "0":
        extras = []

    if extras:
        clauses = "\n  or\n  ".join(_clause(s) for s in extras)
        gen = f"""

// ======== 以下由 core/gen_ql.py 生成，不要手改 ========
// 来源：core/config/sinks.yml 里 source=extra 的 {len(extras)} 条
predicate is_sink_config(CallNode cn) {{
  {clauses}
}}

predicate is_sink(CallNode cn) {{ is_sink_paper(cn) or is_sink_config(cn) }}
"""
        ids = [s["id"] for s in extras]
    else:
        gen = """

// ======== 以下由 core/gen_ql.py 生成，不要手改 ========
// ★ extra 为空 → is_sink 与AgentFuzz**完全一致**（基线）
predicate is_sink_config(CallNode cn) { none() }

predicate is_sink(CallNode cn) { is_sink_paper(cn) }
"""
        ids = []

    # 组装我们的包
    (OUT_QL / "call").mkdir(parents=True, exist_ok=True)
    (OUT_QL / "util").mkdir(parents=True, exist_ok=True)
    (OUT_QL / "call" / "call.qll").write_text(renamed + gen, encoding="utf-8")
    # ★★ 接线：util.qll 不再原样拷AgentFuzz —— 路径过滤改成 filters.yml 的**段/文件名/子串**三层，
    #    修掉"仓库名含 test 就整仓被排除"的假 0。`AF_PATH_FILTER=0` 可回到AgentFuzz baseline。
    filt_mode = _write_util_qll()
    util_txt = (OUT_QL / "util" / "util.qll").read_text(encoding="utf-8")
    for q in QUERIES:
        shutil.copy2(PAPER_QL / q, OUT_QL / q)

    # ★ 跨过程实参来源（开关 dataflow-argsource）：两个文件由 sources.yml 生成，
    #   查询本体是手写模板（core/ql_src/），一起拷进包里。
    ast_qll, cfg_qll, src_ids = _sources_qll()
    (OUT_QL / "argsource_ast.qll").write_text(ast_qll, encoding="utf-8")
    (OUT_QL / "argsource_cfg.qll").write_text(cfg_qll, encoding="utf-8")
    ql_src = ROOT / "core" / "ql_src"
    own_queries = []
    if ql_src.exists():
        for q in sorted(ql_src.glob("*.ql")):
            shutil.copy2(q, OUT_QL / q.name)
            own_queries.append(q.name)

    # ★★ 包名 = `py-qs-kernel-<内容哈希>`。两个理由，都是踩出来的：
    #   ① 与AgentFuzz的 `py-qs` **不能同名** —— 同名会让两者结果缓存在数据库里
    #      同一个路径（`results/py-qs/...`）互相覆盖。
    #   ② 单纯改个固定名还不够 —— CodeQL 的缓存键是 (包名, 查询路径)，
    #      **不看库内容**。改了 call.qll 却仍报 "No need to rerun"，实验直接失效。
    #      → 把内容哈希写进包名：配置一变就是新包，缓存天然隔离；
    #        配置没变则仍能复用缓存。相当于给规则打了版本戳。
    import hashlib
    stamp = hashlib.sha1(
        (renamed + gen + ast_qll + cfg_qll + util_txt).encode("utf-8")).hexdigest()[:8]
    (OUT_QL / "qlpack.yml").write_text(
        f"library: false\nwarnOnImplicitThis: false\nname: py-qs-kernel-{stamp}\nversion: 0.0.2\n"
        "dependencies:\n  codeql/python-all: \"*\"\n  codeql/suite-helpers: \"*\"\n"
        "  codeql/util: \"*\"\n", encoding="utf-8")
    print(f"  包名 py-qs-kernel-{stamp}（内容哈希，配置变则包名变 → 缓存不会串）")

    print(f"生成 → {OUT_QL}")
    print(f"  extra 条目 {len(extras)} 个：{ids or '（空 → 与AgentFuzz一致，即基线）'}")
    print(f"  源头条目 {len(src_ids)} 个：{src_ids or '（空 → 只报 param，保守基线）'}")
    print(f"  自带查询 {own_queries or '（无）'}")
    print(f"  路径过滤 {filt_mode}（AF_PATH_FILTER=0 → 回到AgentFuzz的子串黑名单）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
