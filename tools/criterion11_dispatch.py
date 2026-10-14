# -*- coding: utf-8 -*-
"""★★★ 第 11 类危险形态：**动态派发**（调用哪个函数由外部决定）

═══ 为什么需要它 ═══
`docs/77` 实测：crit10 v2 抓到了 5 个已确认漏洞里的 4 个，
★ **漏掉的正是 `SampleOrch` 的 `/_call`**：
```python
fname, call_args, call_kwargs = await request.json()      # ★ 外部指定函数名
r = await async_wrapper(getattr(func, fname), *call_args, **call_kwargs)
```
★★ 它**不在 `DANGER` 清单里**，
   因为它的形态不是「调用了危险函数」，而是「★ 调用哪个函数由外部决定」。

★★ **危害等价于任意代码执行，但静态形态完全不同** ——
   `exec`/`eval` 是「用某种方式执行代码」，
   `getattr(obj, 外部指定的)(...)` 是「**跳到任意函数**」。

═══ 为什么不能只 grep `getattr` ═══
实测 4 个项目里 `getattr(` 出现 **867 处** ——
★ 因为 `getattr` 绝大多数是「取个属性」（框架代码里到处都是）。
★ **必须限定「第二个参数来自外部」**。

═══ 判定方法（AST，不是正则）═══
1. 找所有 `X(...)(...)` 形态 —— 即「调用一个函数调用结果」
2. 追那个函数的**第二个参数**（函数名）的来源：
   · 来自 request/form/输入 → ★ 可控派发
   · 来自内部枚举/配置/白名单 → 不是
   · 是常量字符串 → 不是
3. ★★ 还要看「派发对象的类型」：如果是模块/类对象，
   可调范围是它的全部方法 → 危害更大
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
OUT = os.path.join(POOL, "criterion11_dispatch.json")

# ★ 外部来源信号（比 crit10 严：只看真正的外部输入）
EXT = re.compile(
    r"(request|req|websocket|ws|ctx)\s*\."
    r"(json|form|args|get_json|body|files|query|headers|params|POST|GET|data)"
    r"|\bawait\s+\w+\.read\(\)"
    r"|\bargs\b|\bkwargs\b"
    r"|\binput\s*\(\s*\)|\bsys\.argv"
    r"|\bUploadFile\b|\bFormData\b",
    re.I)

# ★ 内部来源（这些不是外部可控）
# ★★ 全部用 (?:...) 非捕获组 —— 10-08 实测踩过：用 (...) 会漏右括号，
#    re.compile 直接抛 "unbalanced parenthesis"，
#    而 main() 里的 except 把它吞了 → 只输出部分结果，看着像跑完了。
INT = re.compile(
    r"(?:^\s*\"|^\s*'|[A-Z_]{3,}\b|\.name\b|\.type\b|\.kind\b|\.method\b"
    r"|__name__|\.value\b|getattr\(\s*\w+\s*,\s*[\"']"
    r"|\.(?:keys|values|items)\(\)|\bLiteral\b|\benum\b)", re.I)


def trace_name(node, depth=0, seen=None):
    """★ 追「函数名的来源」。返回 (verdict, 证据)。"""
    if seen is None:
        seen = set()
    if depth > 3 or node is None:
        return "unknown", ""
    try:
        code = ast.unparse(node)
    except Exception:
        return "unknown", ""
    if len(code) > 200:
        code = code[:200]
    if EXT.search(code):
        return "external", code[:90]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "internal", "常量字符串 %r" % code[:60]
    # ★★ 变量名 → 看它在本函数里怎么来的。
    #   ★ 这里必须走文本判定而不是 INT 正则 ——
    #   INT 里的 `\.name\b` 在 re.I 下会匹配 `fname` 里的 "name"！
    #   ★ 实测 10-08 因此把 `fname`（← await request.json()）误判成 internal，
    #   漏掉了 SampleOrch 的 /_call。→ ★ 所以变量名一律查 src_of。
    if isinstance(node, ast.Name):
        return "unknown", code[:90]
    if INT.search(code):
        return "internal", code[:90]
    # ★ 变量 → 看它在本函数里怎么来的
    if isinstance(node, ast.Name):
        for n in ast.walk(ast.Module(body=[], type_ignores=[])) if False else []:
            pass
    return "unknown", code[:90]


def trace_text(code, src_of, depth=0):
    """★ 直接对**文本**判来源（不重新 parse）。

    ★ 为什么不能 `ast.parse(code, mode="eval")`：
      - `await request.json()` 在 eval 模式里是语法错误（await 只在 async 内合法）
      - ★ 实测 10-08 因此漏掉了 SampleOrch 的 `/_call`（一个已确认的洞）
      → 所以对「本函数里已记录的赋值」直接判文本，不再 parse。
    """
    if depth > 3:
        return "unknown", ""
    if EXT.search(code):
        return "external", ""
    if INT.search(code):
        return "internal", ""
    # ★ 又是变量 → 再往上追一层
    m = re.search(r"\b(\w+)\s*$", code.strip())
    if m:
        up = src_of.get(m.group(1))
        if up and up != code:
            v, e = trace_text(up, src_of, depth + 1)
            if v == "external":
                return v, ""
    return "unknown", ""


def scan_file(path, src):
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        # ★ 只吞语法错误（文件本来就坏），其他异常必须响
        print("  ★ 语法错跳过 %s:%s" % (path.split("/")[-1][:24], e.lineno))
        return []
    out = []
    # ★ 按函数切块，才能追变量来源
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a, b = fn.lineno, (getattr(fn, "end_lineno", fn.lineno) or fn.lineno)
        # ★ 收集这个函数里所有变量的赋值来源
        src_of = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
               and isinstance(n.targets[0], ast.Name):
                try:
                    src_of[n.targets[0].id] = ast.unparse(n.value)
                except Exception:
                    pass
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                try:
                    src_of[n.target.id] = ast.unparse(n.value)
                except Exception:
                    pass
            # ★★ 元组解包：★ 真实案例 `fname, call_args, _ = await request.json()`
            #   10-08 实测发现这是**第三��盲区** —— 只收集单目标 Assign 会全漏
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], (ast.Tuple, ast.List)):
                try:
                    rhs = ast.unparse(n.value)
                except Exception:
                    continue
                for el in n.targets[0].elts:
                    if isinstance(el, ast.Name):
                        src_of[el.id] = rhs   # ★ 整条 rhs 都记下（多个都指向它）

        for n in ast.walk(fn):
            # 形态1：getattr(obj, NAME)(args)—— 立刻调用
            hit = None
            if isinstance(n, ast.Call):
                f = n.func
                # getattr(...)(...)
                if isinstance(f, ast.Call):
                    try:
                        fname = ast.unparse(f.func)
                    except Exception:
                        continue
                    if fname == "getattr" and len(f.args) >= 2:
                        hit = {"kind": "getattr_immediate",
                               "name_arg": f.args[1], "line": n.lineno}
                # globals()[NAME](args)
                elif isinstance(f, ast.Subscript):
                    try:
                        base = ast.unparse(f.value)
                    except Exception:
                        base = ""
                    if base == "globals()" or base == "locals()":
                        hit = {"kind": base, "name_arg": f.slice,
                               "line": n.lineno}
                # obj[NAME](args) —— dict 派发
                elif isinstance(f, ast.Subscript):
                    try:
                        base = ast.unparse(f.value)
                    except Exception:
                        base = ""
                    hit = {"kind": "subscript_call:" + base[:24],
                           "name_arg": f.slice, "line": n.lineno}
            # ★★★ 形态3：**作为实参被传走**（10-08 实测才发现的盲区）
            #   真实案例：async_wrapper(getattr(func, fname), *args)
            #   → getattr 的返回值没有当场被调用，而是交给别的函数去调
            #   → ★ 只匹配「立即调用」会完全漏掉这一类
            if hit is None and isinstance(n, ast.Call):
                for a in list(n.args) + [k.value for k in n.keywords]:
                    if not isinstance(a, ast.Call):
                        # ★★ 不能在这里 break！★ 实测 10-08 因此漏掉了
                        #   SampleOrch 的 /_call —— 第一个实参不是 getattr，
                        #   break 掉就再也不会看后面的实参了。
                        continue
                    try:
                        inner = ast.unparse(a.func)
                    except Exception:
                        continue
                    if inner == "getattr" and len(a.args) >= 2:
                        hit = {"kind": "getattr_as_argument",
                               "name_arg": a.args[1], "line": n.lineno,
                               "★_holder": ast.unparse(n.func)[:40]}
                        break          # ★ 只在匹配到时才 break
            # 形态2：f = getattr(obj, NAME) 然后 f(...)
            elif isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Name) and f.id in src_of:
                    rhs = src_of[f.id]
                    m = re.match(r"getattr\s*\(.*?,\s*([^,)]+)\)", rhs)
                    if m:
                        try:
                            hit = {"kind": "getattr_deferred",
                                   "name_arg": ast.parse(m.group(1).strip(),
                                                         mode="eval").body,
                                   "line": n.lineno}
                        except Exception:
                            pass
            if not hit:
                continue
            verdict, ev = trace_name(hit["name_arg"])
            if verdict == "unknown" and isinstance(hit["name_arg"], ast.Name):
                rhs = src_of.get(hit["name_arg"].id)
                if rhs:
                    # ★★ 不能用 mode="eval" —— `await request.json()` 在 eval 模式
                    #    里是语法错误（await 只在 async 函数体内合法），
                    #    ★ 实测 10-08 就是因此漏掉了 SampleOrch的 /_call。
                    v2, e2 = trace_text(rhs, src_of)
                    verdict, ev = v2, (e2 + "← 来自 " + rhs[:56])
            if verdict != "external":
                continue
            out.append({
                "file": path, "func": fn.name, "line": hit["line"],
                "kind": hit["kind"],
                "evidence": ev[:110],
                "callable_code": (ast.unparse(n)[:150]),
            })
    return out


TEST_PATH = re.compile(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                       r"benchmarks?|docs?)(/|$)", re.I)
TEST_NAME = re.compile(r"(^test_|_test\.py$|^conftest\.py$|^mock_|_mock\.py$)", re.I)


def main():
    recs = {}
    for line in open(os.path.join(POOL, "rc_v8_partial.jsonl"), encoding="utf-8"):
        line = line.strip()
        if line:
            d = json.loads(line)
            recs[d["repo"]] = d.get("branch") or "main"

    print("★ 第 11 类危险形态：动态派发（调用哪个函数由外部决定）")
    print("  ★ 不是 grep getattr —— 实测 getattr( 在 4 个项目里有 867 处")
    print("  ★ 必须用 AST 追「函数名的来源」")
    print()
    allhits = []
    for repo in sorted(recs):
        br = recs[repo]
        f, n, m = recheck.cache_files(repo, br)
        if not f:
            alt = "master" if br == "main" else "main"
            f, n, m = recheck.cache_files(repo, alt)
        if not f:
            continue
        hits = []
        for path, src in f.items():
            if not path.endswith(".py"):
                continue
            p = path.replace("\\", "/")
            if TEST_PATH.search(p) or TEST_NAME.search(os.path.basename(p)):
                continue
            for h in scan_file(path, src):
                h["_repo"] = repo
                hits.append(h)
        if hits:
            allhits.extend(hits)
            print("  %-30s %d %s" % (repo.split("/")[-1][:30], len(hits),
                                       dict(Counter(h["kind"].split(":")[0]
                                                    for h in hits))))

    json.dump(allhits, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print()
    print("=" * 78)
    print("★ 合计 %d 处（getattr 原始命中 867 处 → 收窄到 %d）"
          % (len(allhits), len(allhits)))
    print("=" * 78)
    print("按形态：%s" % dict(Counter(h["kind"].split(":")[0] for h in allhits)))
    print()
    print("★ 明细：")
    for h in allhits:
        print("  %-20s %-22s::%-16s %s"
              % (h["_repo"].split("/")[-1][:20],
                 h["file"].split("/")[-1][:22], h["func"][:16], h["kind"][:24]))
        print("     函数名来源: %s" % h["evidence"][:88])
        print("     调用: %s" % h["callable_code"][:88])
    print("\n结果写入 %s" % OUT)


if __name__ == "__main__":
    main()