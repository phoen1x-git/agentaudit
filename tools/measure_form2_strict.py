# -*- coding: utf-8 -*-
"""★ 量：形式二加上「第二个参数存在」检查后，还剩多少。

为什么必须加这个检查
-------------------
复活形式二之后跑全量29 个项目，命中 154 处，
其中 114 处在业务代码里 —— 逐条看发现绝大多数是**字典取键**，不是路由注册：

    blueprint.get('topology')       ← 拿字典的一个键
    server.get('name')             ← 同上
    route.get('target')             ← 同上
    api.get('auth')                 ← 同上

它们和真正的路由注册 `app.post('/x', handler)` 在语法上**几乎一样**：
载体名 `app`/`blueprint`/`route`/`server` 都在 ROUTE_BASES 里，
第一个参数都是字面量字符串。**光看语法区分不了。**

★ 唯一的可用区分信号：**第二个参数**。
    路由注册：app.post("/x", handler)      ← 有第二个参数（处理函数）
    字典取键：blueprint.get("topology")    ← 只有一个参数
  Flask 的 route.get("/x", methods=[...]) 也带第二参 → 满足。

★ 教训（这是本轮第二个「机制对但结论错」的实例）：
    判据声称支持形式二，我信了，复活它 ——
    结果它带来的是纯误报。
    **「代码里写了支持某种写法」≠「这种写法真的被支持着」。**
    和 docs/44 那个「12 处误报当成判据修对了」是同一个病根：
    只验证了「它能跑出结果」，没验证「跑出来的结果对不对」。

用法：python tools/measure_form2_strict.py
"""
import ast
import io
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402

POOL = os.path.join(HERE, "..", "data", "target_pool")


def load_targets():
    import glob
    out = []
    for f in sorted(glob.glob(os.path.join(POOL, "rc_v5_*.txt"))):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line and line != "-" and "/" in line:
                out.append(line)
    return sorted(set(out))


ROUTE_RE = re.compile(r"^([\w\.]+)\.(%s)\s*\(\s*[\"']([^\"']*)"
                      % "|".join(A.ROUTE_VERBS))


def scan(files):
    """扫出形式二候选，带宽松/严格两个口径。"""
    loose, strict = [], []
    for p, src in files.items():
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        deco_ids = set()
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef)):
                for d in n.decorator_list:
                    deco_ids.add(id(d))
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call) or id(n) in deco_ids:
                continue
            try:
                nm = ast.unparse(n)
            except Exception:
                continue
            m = ROUTE_RE.match(nm)
            if not m:
                continue
            base = m.group(1).split(".")[-1]
            if base not in A.ROUTE_BASES:
                continue
            rec = (p, n.lineno, m.group(1), m.group(2), m.group(3),
                   n.args if isinstance(n, ast.Call) else None,
                   nm[:70])
            loose.append(rec)
            # ★ 严格口径：至少两个位置参数
            if len(n.args) >= 2:
                strict.append(rec)
    return loose, strict


def main():
    targets = load_targets()
    print("目标数：%d" % len(targets))
    print("=" * 74)
    rows = []
    tot_l = tot_s = 0
    for t in targets:
        repo, _, branch = t.partition("#")
        branch = branch or "main"
        try:
            files, n_py, miss = recheck.cache_files(repo, branch)
        except Exception:
            continue
        if not files:
            continue
        loose, strict = scan(files)
        lb = [h for h in loose if not is_test_path(h[0])]
        sb = [h for h in strict if not is_test_path(h[0])]
        if not loose:
            continue
        tot_l += len(lb)
        tot_s += len(sb)
        rows.append((repo, len(lb), len(sb), sb))
        print("%-46s宽松 %-4d → 严格 %-4d" % (repo, len(lb), len(sb)))

    print("=" * 74)
    print("业务代码命中：宽松 %d处 → 严格 %d 处" % (tot_l, tot_s))
    print()
    print("=== 严格口径下活下来的（这些是真路由注册，判据应该报）===")
    for repo, l, s, sb in rows:
        for (p, ln, obj, verb, rpath, _a, nm) in sb:
            print("  %s" % repo)
            print("      %s:%s  %s.%s('%s')" % (p, ln, obj, verb, rpath))
    if tot_s == 0:
        print("  （一条都没有）")
        print()
        print("★ 结论：**形式二这个写法在这 29 个项目里根本不存在**。")
        print("  那些命中 100% 是字典取键。所以正确做法是")
        print("  **给形式二加「≥2 个参数」这条约束**，而不是原样复活。")


if __name__ == "__main__":
    sys.exit(main())