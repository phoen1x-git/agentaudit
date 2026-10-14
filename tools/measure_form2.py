# -*- coding: utf-8 -*-
"""量「形式二复活」在**全部 29 个项目**上的净效应。

背景（10-05）
-------------
`_find_unauth_endpoints` 的形式二（`app.post("/x", handler)` 裸调用）
原来是条**死分支** —— 用了 `_name(node)`，只拿到 `"app.post"`，
而正则要求后面跟 `("` → 一条都匹配不到。
改成 `ast.unparse(node)` 后才真正生效。

★ 为什么要专门量它：这类「本来没在跑」的分支一旦复活，
  会让某个项目的数字**变大**。变大可能是「补回了漏报」（好），
  也可能是「引入了误报」（坏）。**不看集合差就不知道是哪种。**

判定标准：
  · 新增命中必须**逐条看过源码**才敢认
  · 集中在 tests/ 里的（测试文件已被skip_tests 排除）→ 不影响线上数字
  · 出现在业务代码里的 → 要一条条核实

用法：python tools/measure_form2.py
"""
import ast
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402

POOL = os.path.join(HERE, "..", "data", "target_pool")


def load_targets():
    """从 rc_v5_*.txt 分片清单读目标（29 个）。"""
    import glob
    out = []
    for f in sorted(glob.glob(os.path.join(POOL, "rc_v5_*.txt"))):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line and line != "-" and "/" in line:
                out.append(line)
    return sorted(set(out))


def scan_form2(files):
    """扫出形式二能匹配到的裸调用（排除装饰器）。"""
    hits = []
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
            import re
            m = re.match(r"^([\w\.]+)\.(%s)\s*\(\s*[\"']([^\"']*)"
                         % "|".join(A.ROUTE_VERBS), nm)
            if not m:
                continue
            if m.group(1).split(".")[-1] not in A.ROUTE_BASES:
                continue
            hits.append((p, n.lineno, m.group(1), m.group(2), m.group(3)))
    return hits


def main():
    targets = load_targets()
    if isinstance(targets, dict):
        targets = list(targets.keys())
    print("目标数：%d" % len(targets))
    print("=" * 74)
    total = 0
    in_test = 0
    in_biz = 0
    per = []
    for t in targets:
        if not isinstance(t, str) or "/" not in t:
            continue
        repo, _, branch = t.partition("#")
        branch = branch or "main"
        try:
            files, n_py, miss = recheck.cache_files(repo, branch)
        except Exception as e:
            print("%-46s  读缓存失败 %s" % (repo, e))
            continue
        if not files:
            print("%-46s  无缓存" % repo)
            continue
        hits = scan_form2(files)
        if not hits:
            continue
        t_hits = [h for h in hits if is_test_path(h[0])]
        b_hits = [h for h in hits if not is_test_path(h[0])]
        total += len(hits)
        in_test += len(t_hits)
        in_biz += len(b_hits)
        per.append((repo, len(hits), len(t_hits), len(b_hits), b_hits))
        print("%-46s 形式二命中 %-4d (测试 %d / 业务 %d)"
              % (repo, len(hits), len(t_hits), len(b_hits)))

    print("=" * 74)
    print("合计 %d 处 —— 测试文件 %d（已被 skip_tests 排除，不进结果），业务 %d"
          % (total, in_test, in_biz))
    print()
    if in_biz:
        print("★★★ 业务代码里的命中，必须逐条核实：")
        for repo, n, t, b, b_hits in per:
            for (p, ln, obj, verb, rpath) in b_hits:
                print("  %s" % repo)
                print("      %s:%s  %s.%s('%s')" % (p, ln, obj, verb, rpath))
    else:
        print("★ 业务代码里0 处 —— 形式二复活对最终数字**没有任何影响**，")
        print("  说明死分支里藏着的全是测试代码。这是个好消息：")
        print("  修对了，但不改变任何已发布结论，也不需要重跑批次。")


if __name__ == "__main__":
    sys.exit(main())