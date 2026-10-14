# -*- coding: utf-8 -*-
"""★★★ crit9 + 判据 1 联用：把「强弱并存」的噪声自动压下去

═══ 为什么这个组合是对的 ═══
`docs/74` 的实测：crit9 的 16 处 `not_real`，**理由全部是同一个**
```
「SQL 拼接仅使用内部常量列名与参数化取值，无外部污点」    astra
「表名来自内部 schema 常量而非外部输入」                  SampleOrch
「拼接的 operator 来自内部距离映射常量」                  agentUniverse
「eval 的参数是本地常量 '42'」                            AdalFlow
★ ★★ 也就是说：**噪声全来自「拼接进去的是内部常量，不是外部输入」。**
```

★ 而「这个变量是不是外部可控」正是**判据 1（外部输入判定）**在做的事
→ 所以 crit9 不该独立用，该和判据 1 联用。

═══ 但要小心一个陷阱 ═══
★ **不能只看变量名**。docs/42 记过一个坑：
   「某项目的子进程工具库写法很规范，却因形参名叫 `args` 被判成输入直落 3 处」
   →病根是**把「变量名长得像用户输入」当成「它就是用户输入」。

★ 所以判据 1 的口径必须是「**这个值怎么产生的**」，
   而不是「这个变量叫什么」：
   · 从请求参数 / 上传文件 / 模型输出 / 外部响应里取 → 真外部
   · 从常量 / 内部映射表 / 配置 / 自增 ID 取 → 内部
   · ★ 从函数形参来→ ★ 要再看这个形参在上游是怎么传的
"""
import ast
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import recheck

POOL = os.path.join(HERE, "..", "data", "target_pool")
OUT = os.path.join(POOL, "crit9_taint.json")

# ══════════════════════════════════════════════════════════════════
# 外部值的「产生方式」信号（判据 1 的口径）
# ══════════════════════════════════════════════════════════════════
# ★ 真外部：来自请求 / 上传 / 模型输出 / 外部响应
EXTERNAL_SIG = re.compile(
    r"(request\.(json|form|args|get_json|body|files|query|headers|"
    r"GET|POST|params|data|cookies)|"
    r"req\.(json|form|args|get_json|body|files|headers|params)|"
    r"\bawait\s+\w+\.read\(\)|"                    # UploadFile.read()
    r"\.(json\(\)|json\.loads?\()|"               # 外部响应体
    r"response\.(json|text|content)|"
    r"yield\s+\"|\bchunk\.choices|completion\.|"
    r"llm\.invoke|chat\.completions|acompletion|"
    r"input\(\)|user_input|user_message|question|prompt\b|"
    r"upload|attachment|scraped|crawled|fetched)",
    re.I)

# ★ 内部常量：从哪来的
INTERNAL_SIG = re.compile(
    r"(^\s*[A-Z_]{2,}\s*=|\"[^\"]*\"\s*$|'\s*[^']*'\s*$|"   # 常量字面量
    r"\.upper\(\)|\.lower\(\)|\.strip\(\)|\.split\("
    r"|list\(|dict\(|tuple\(|\.keys\(\)|\.items\(\)|"
    r"os\.environ|getenv|settings\.|config\.|CONF\b|CONFIG\b)",
    re.I)

# ★ 危险参数名（只是线索，不能单独定论 —— docs/42 的教训）
SUSPECT_NAME = re.compile(
    r"\b(table|column|expr|sql|query|statement|field|key|path|"
    r"filename|file|dir|directory|value|val|data|content|text|"
    r"name|names|attr|clause|fragment|part|s)\b", re.I)


def trace_var(func_node, var_name):
    """★ 追一个变量在这个函数里「怎么产生」。

    返回 (来源描述, 证据行)
    ★ 关键：**看赋值语句的右边是什么**，不是看名字像不像。
    """
    try:
        body = ast.unparse(func_node)
    except Exception:
        return None, ""
    lines = body.splitlines()
    base = func_node.lineno
    srcs = []
    for i, l in enumerate(lines, base):
        # var = <右边>
        m = re.match(r"\s*%s\s*=\s*(.+)$" % re.escape(var_name), l)
        if not m:
            continue
        rhs = m.group(1)
        if EXTERNAL_SIG.search(rhs):
            srcs.append(("external", i, rhs[:90]))
        elif INTERNAL_SIG.search(rhs) or rhs.strip().strip('"\''):
            srcs.append(("internal", i, rhs[:90]))
        else:
            srcs.append(("unknown", i, rhs[:90]))
    if not srcs:
        # 没赋值 → 形参？
        args = [a.arg for a in func_node.args.args + func_node.args.kwonlyargs]
        if var_name in args:
            return "param", ""
        return None, ""
    # ★ 有任何一个 external 来源 → 整条算外部
    if any(s[0] == "external" for s in srcs):
        return "external", srcs[0][1]
    kinds = set(s[0] for s in srcs)
    if kinds == {"internal"}:
        return "internal", srcs[0][1]
    return "unknown", srcs[0][1]


def find_interpolated_vars(node):
    """★ 找出 f-string / % / + 拼接里被塞进去的变量名。

    ★ 这是关键：**只看被「拼进去」的，不是看整个函数的参数** ——
       一个函数有 5 个参数不代表拼进 SQL 的那个是外部的。
    """
    out = []
    for n in ast.walk(node):
        # f-string
        if isinstance(n, ast.JoinedStr):
            for v in n.values:
                if isinstance(v, ast.FormattedValue):
                    try:
                        out.append((ast.unparse(v.value), n.lineno))
                    except Exception:
                        pass
        # % 格式化
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
            try:
                s = ast.unparse(n.left)
                if any(k in s.upper() for k in
                       ("SELECT", "INSERT", "UPDATE", "DELETE", "SELECT", "FROM",
                        "ALTER", "PRAGMA")):
                    out.append((s, n.lineno))
            except Exception:
                pass
        # 字符串 + 变量
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            for side in (n.left, n.right):
                try:
                    s = ast.unparse(side)
                    if any(k in s.upper() for k in
                           ("SELECT", "INSERT", "UPDATE", "DELETE", "FROM")):
                        other = n.right if side is n.left else n.left
                        out.append((ast.unparse(other), n.lineno))
                except Exception:
                    pass
    return out


def scan_file(path, src, hits):
    """hits 是 criterion9_duality.json 里该文件的相关命中。"""
    try:
        tree = ast.parse(src)
    except Exception:
        return
    weak_lines = set()
    for h in hits:
        weak_lines.update(h.get("weak_at") or [])
        weak_lines.add(h.get("start"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a, b = node.lineno, (getattr(node, "end_lineno", node.lineno)
                             or node.lineno)
        # ★ 这个函数里有没有 crit9 报过的弱写法
        if not any(a <= w <= b for w in weak_lines if w):
            continue
        vars_ = find_interpolated_vars(node)
        for expr, ln in vars_:
            # 表达式可能是 a.b.c 或 复杂形式，取最后一段名字
            name = expr.split(".")[-1].strip()
            if not name or not SUSPECT_NAME.search(name):
                # 也接受全部（有些不是可疑名）
                pass
            src_kind, ev_line = trace_var(node, expr)
            yield {
                "file": path, "func": node.name, "line": ln,
                "var_expr": expr[:80], "var_name": name,
                "taint": src_kind, "taint_line": ev_line,
                "evidence": (src_kind or "?") + " @line %s: %s" % (
                    ev_line or "?", expr[:60]),
            }


def main():
    hits = json.load(open(os.path.join(POOL, "criterion9_duality.json"),
                         encoding="utf-8"))
    byfile = defaultdict(list)
    for h in hits:
        byfile[(h["_repo"], h["file"])].append(h)

    recs = {}
    for line in open(os.path.join(POOL, "rc_v8_partial.jsonl"), encoding="utf-8"):
        line = line.strip()
        if line:
            d = json.loads(line)
            recs[d["repo"]] = d.get("branch") or "main"

    allres = []
    for (repo, path), hs in sorted(byfile.items()):
        br = recs.get(repo, "main")
        f, n, m = recheck.cache_files(repo, br)
        if not f:
            alt = "master" if br == "main" else "main"
            f, n, m = recheck.cache_files(repo, alt)
        if not f or path not in f:
            continue
        try:
            for r in scan_file(path, f[path], hs):
                r["_repo"] = repo
                r["_branch"] = br
                allres.append(r)
        except Exception as e:
            print("  ★ %s 扫描异常 %s" % (path.split("/")[-1], str(e)[:40]))

    json.dump(allres, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    print("★ crit9 × 判据1 联用：给「被拼接进去的变量」定污点")
    print("=" * 74)
    print("共 %d 处拼接点" % len(allres))
    print()
    c = Counter(r["taint"] or "unknown" for r in allres)
    for k, v in c.most_common():
        print("  %-10s %d" % (k, v))
    print()
    n_ext = c.get("external", 0)
    tot = len(allres)
    print("★ 拼接的是**外部数据**的比例 = %d/%d = **%.1f%%**"
          % (n_ext, tot, 100.0 * n_ext / max(1, tot)))
    print("★ → 这就是 crit9 精确率的上限（外部的才可能成洞）")
    print()
    print("★ external 的（★ 这才是要送LLM 判定的）：")
    for r in allres:
        if r["taint"] == "external":
            print("  %-20s %-22s::%-18s %s"
                  % (r["_repo"].split("/")[-1][:20],
                     r["file"].split("/")[-1][:22], r["func"][:18],
                     r["evidence"][:56]))
    print()
    print("★ unknown 的（★ 需要人工看一眼，可能有漏判）：")
    for r in allres:
        if r["taint"] == "unknown":
            print("  %-20s %-22s::%-18s %s"
                  % (r["_repo"].split("/")[-1][:20],
                     r["file"].split("/")[-1][:22], r["func"][:18],
                     r["evidence"][:56]))
    print("\n结果写入 %s" % OUT)


if __name__ == "__main__":
    main()