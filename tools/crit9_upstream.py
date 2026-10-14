# -*- coding: utf-8 -*-
"""★★★ 方案 C：让 LLM 判「这个形参在真实调用链上是不是外部可控的」

═══ 为什么这是最优解 ═══
`docs/75` 实测：手写 AST 反向污点追踪**追不动** ——
```
get_collection_info(collection_name)              ← 被拼接的形参
  ↑ database_postgresql.py __call__(...)          ← 同文件，能追
    ↑ ★★ 跨文件：工具层 / agent 调用层            ← ★ 这里断了
```
而且 `__call__` 还会误匹配（全项目一堆 `super().__call__()`）。

★★ **但这恰好是 LLM 的强项**：
   它能读懂「这是个数据库工具类，collection_name 是 LLM 传进来的」
   而 AST 不能。

→ 所以：**给 LLM 这个函数的源码 + 它所在类的上下文，让它判。**

═══ 与crit9 的组合 ═══
crit9（纯语法）已经把范围从 1582 缩到 100
    ↓ 这一步（LLM）判「形参的调用链上是否外部可控」
    ↓ 再送统一判定（两层：污点 + 职责）
→ 精确率应该能从 5.9% 提上去

═══ 为什么这还是「基础架构复用」═══
★ 换的只是「喂什么给 LLM」，判定流程、缓存、记账全部复用
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
import llm_client as LC
import llm_judge as J
import recheck

POOL = J.POOL
OUT = os.path.join(POOL, "crit9_upstream.json")

RUBRIC_UP = """你在判一个 Python Agent 项目的**参数来源**。

★ 背景：静态扫描发现某处代码把一个变量**拼进危险操作**
   （SQL 字符串 / eval / exec / 文件路径）。
   那个变量往往是某个函数的**形参**。

★ 你要回答的问题只有一个：
   **这个形参，在真实的调用链上，值是「外部可控的」还是「内部常量」？**

═══ 怎么判 ═══
看这个函数**所在类的性质**和**参数的语义**：

① ★ 外部可控（external）
   - 它是给 **LLM / Agent 用的工具**：调用方是模型，参数来自模型的工具调用
   - 它来自 HTTP 请求（框架注入的 request / payload / body）
   - 它是上传文件的内容
   - 它是另一个 API 的返回值 / 从外部抓取的网页
   ★ 典型信号：类名或 docstring 提到 tool / agent / LLM / tool_call；
     或者同类里已有 `xxx = request.xxx` 这样的赋值

② ★ 内部常量（internal）
   - 它是**开发者写死的**：模块级常量、配置里的表名/列名映射、
     固定的白名单、迁移脚本里的 schema 定义
   - ★ 它是**内部生成**的：自增 ID、`uuid4()`、哈希、时间戳、
     从已知常量表里查出来的
   ★ 典型信号：同一函数的紧邻代码里已经有参数化写法（说明作者会正确处理输入）；
     或者调用点在 `migrations/` `utils/` `setup/` 这类地方

③ 不确定（unclear）—— ★ 证据不足就给这个，不要猜

★★ 特别提醒：
   - ★ 「迁移/建表/初始化脚本」里的拼接 → **几乎总是 internal**
   - ★ 「给 LLM 用的工具」里的拼接 → **很可能是 external**
   - ★★ 不要只看参数名像不像外部输入
     （形参叫 `collection_name` 不代表它外部可控；
       形参叫 `name` 也可能来自 LLM）

═══ 输出 JSON ═══
{
  "kind": "tool_for_llm|http_api|upload|internal_migration|internal_config|other",
  "verdict": "external|internal|unclear",
  "confidence": 0.0-1.0,
  "evidence": "一句话，引用你看到的依据（类名/docstring/同文件参数化写法/调用方线索）",
  "why": "一句话，说明为什么是external 或 internal",
  "one_line": "一句话结论"
}

★ confidence 必须如实。证据不足时给 unclear 并降低 confidence，
  ★★ **不要因为「看起来像外部输入」就答 external** —— 那会把噪声当信号。"""


def collect_calls(repo, branch, fmap, fname):
    """★ 收集「谁调用了这个函数」+ 调用点所在文件。

    ★ 关键是**跨文件** —— 同文件的信息不够，因为工具类的调用方常在别的文件。
    """
    hits = []
    short = fname.split(".")[-1]
    for fp, src in fmap.items():
        if not fp.endswith(".py"):
            continue
        if fp == _cur_file[0]:
            continue          # ★ 跳过自己（自我调用不算外部入口）
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            try:
                fn = ast.unparse(node.func)
            except Exception:
                continue
            if fn.split(".")[-1] != short:
                continue
            args = []
            for a in node.args[:4]:
                try:
                    args.append(ast.unparse(a)[:70])
                except Exception:
                    args.append("?")
            # ★ 找调用点所在的函数（看它的上下文）
            holder = "<module>"
            for hn in ast.walk(tree):
                if isinstance(hn, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                   and hn.lineno <= node.lineno <= (
                       getattr(hn, "end_lineno", hn.lineno) or hn.lineno):
                    holder = hn.name
                    break
            hits.append({"file": fp, "line": node.lineno,
                         "caller": holder, "args": args})
    return hits[:12]


_cur_file = [""]


def module_ctx(fmap, fp, window=3):
    """★ 给出这个文件里函数前后的内容（帮助 LLM 判断类的性质）。"""
    src = fmap.get(fp)
    if not src:
        return ""
    L = src.splitlines()
    # 文件头（import + 前若干行）
    head = "\n".join("  " + x[:104] for x in L[:24])
    return head


def class_doc(fmap, fp, fname):
    """★ 找这个函数所属类的 docstring 和头部 —— ★ 这是判断「是不是给 LLM 用的工具」的关键。"""
    src = fmap.get(fp)
    if not src:
        return ""
    try:
        tree = ast.parse(src)
    except Exception:
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                   and m.name == fname:
                    doc = (ast.get_docstring(node) or "")[:300]
                    mdoc = (ast.get_docstring(m) or "")[:200]
                    return ("类 %s\n  docstring: %s\n  方法 docstring: %s"
                            % (node.name, doc or "(无)", mdoc or "(无)"))
    return ""


def main():
    hits = json.load(open(os.path.join(POOL, "criterion9_duality.json"),
                          encoding="utf-8"))
    recs = {}
    for line in open(os.path.join(POOL, "rc_v8_partial.jsonl"), encoding="utf-8"):
        line = line.strip()
        if line:
            d = json.loads(line)
            recs[d["repo"]] = d.get("branch") or "main"

    # ★ 每个（repo, file, func）只判一次
    todo = {}
    for h in hits:
        # ★ 只取 eval/exec/pickle/yaml 这几类 —— sql 类大多是内部拼接
        if h["cat"] not in ("eval_safe", "exec_safe", "pickle", "yaml",
                            "tls_verify_off", "shell_on"):
            continue
        k = (h["_repo"], h["file"], h["func"])
        todo.setdefault(k, h)

    print("★ 判「形参在真实调用链上是否外部可控」")
    print("  ★ 只判危险度高的类别（eval/exec/pickle/yaml/tls/shell），SQL 类略过")
    print("  待判%d 个函数" % len(todo))
    print()

    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    cost0 = LC.USAGE.cny
    fmaps = {}
    for (repo, path, func) in sorted(todo):
        key = "%s|%s|%s" % (repo, path, func)
        if key in out:
            continue
        if repo not in fmaps:
            br = recs.get(repo, "main")
            f, n, m = recheck.cache_files(repo, br)
            if not f:
                alt = "master" if br == "main" else "main"
                f, n, m = recheck.cache_files(repo, alt)
            fmaps[repo] = f
        fmap = fmaps[repo]
        src = fmap.get(path)
        if not src:
            continue
        _cur_file[0] = path

        # 函数源码
        fnode = None
        try:
            for n in ast.walk(ast.parse(src)):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                   and n.name == func:
                    fnode = n
                    break
        except Exception:
            continue
        if fnode is None:
            continue
        try:
            fbody = ast.unparse(fnode)
        except Exception:
            continue

        callers = collect_calls(repo, None, fmap, func)
        caller_txt = "\n".join(
            "  %s:%d  在 %s() 里，实参 = %s"
            % (c["file"].split("/")[-1], c["line"], c["caller"],
               ", ".join(c["args"])) for c in callers) or "  （没找到调用方）"

        user = ("【文件】%s\n【类上下文】\n%s\n\n"
                "【文件头部 import】\n%s\n\n"
                "【被扫描的函数源码】\n%s\n\n"
                "【★ 谁调用了它（跨文件）】\n%s\n\n"
                "这个函数的形参被拼进了危险操作。"
                "请判断它在真实调用链上，值是外部可控还是内部常量。"
                % (path, class_doc(fmap, path, func) or "（不在类里）",
                   module_ctx(fmap, path),
                   "\n".join("  " + x[:108] for x in fbody.splitlines()[:45]),
                   caller_txt))
        try:
            r = LC.ask_json(RUBRIC_UP, user, tag="crit9up", max_tokens=3600)
        except Exception as e:
            print("  ★ %s 失败 %s" % (func[:20], str(e)[:40]))
            continue
        r["_repo"] = repo
        r["_file"] = path
        r["_func"] = func
        r["_n_callers"] = len(callers)
        r["_cat"] = todo[(repo, path, func)]["cat"]
        out[key] = r
        json.dump(out, open(OUT, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("  %-20s %-20s %-26s %-10s 调用方%d %s"
              % (repo.split("/")[-1][:20], path.split("/")[-1][:20],
                 func[:26], r.get("verdict"), len(callers),
                 (r.get("one_line") or "")[:36]))

    print()
    c = Counter(v.get("verdict") for v in out.values())
    print("判定 %d 处：%s" % (len(out), dict(c)))
    print("类别分布：%s" % dict(Counter(v.get("_cat") for v in out.values())))
    print("花费 %.4f 元" % (LC.USAGE.cny - cost0))
    print()
    print("★ external 的（★ 这些才可能成洞）：")
    for k, v in out.items():
        if v.get("verdict") == "external":
            print("  %-20s %-22s::%-18s %s"
                  % (v["_repo"].split("/")[-1][:20],
                     v["_file"].split("/")[-1][:22], v["_func"][:18],
                     (v.get("why") or "")[:60]))
    print("\n结果写入 %s" % OUT)


if __name__ == "__main__":
    main()