# -*- coding: utf-8 -*-
"""决定性实验：`unauth_endpoint` 记录层修复 + 形式二复活后的集合差。

背景（10-05）
-------------
两处改动：
  A. **记录层**：evidence 的 "file" 从路由路径改成文件路径（路由另存 "route"）
  B. **死分支复活**：形式二（`app.post("/x", handler)` 裸调用）
     原来用 `_name(node)` 只拿到 `"app.post"`，正则要求后面跟 `("` → 一条都匹配不到
     改成 `ast.unparse(node)` 后才真正生效

★ 为什么必须做集合差，不能只看总数：
  改动 B 会**多检出**（以前漏的现在报了），改动 A 不改变检出数、
  只改记录位置。所以：
    - `file` 集合变小 → 正常（本来是路径错乱导致同一个文件被拆成多桶）
    - `route` 集合变大 → 正常（形式二复活了）
    - **`route` 集合变小 → 有问题**，说明形式二把本该报的吞了
    - 出现反向差异（新判据少报/多报的交集不对称）→ 更严重

判据：`file` 集合只会因为 A 而变干净（去重），不应有**丢失**。
     所以这里同时打 `route` 集合，用来暴露 B 的净效应。
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


def collect(files):
    """跑当前判据，返回 {(file, route)} 集合。"""
    res, failed = A.analyze_files(files, skip_tests=True)
    out = set()
    for h in res["unauth_endpoint"]["hits"]:
        out.add((h.get("file"), h.get("route") or h.get("file")))
    return out, res


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "rhesis-ai/rhesis"
    branch = sys.argv[2] if len(sys.argv) > 2 else "main"

    files, total, miss = recheck.cache_files(repo, branch)
    if not files:
        print("缓存里没有 %s，先跑一次拉取" % repo)
        return 1
    print("repo=%s  py=%d  cached=%d  miss=%d" % (repo, total, len(files),
                                                   len(miss)))

    new, res = collect(files)
    print()
    print("=== 当前判据 ===")
    print("unauth_endpoint 命中 %d 处" % res["unauth_endpoint"]["n_hits"])
    hf = res["unauth_endpoint"]["hit_files"]
    print("hit_files（文件数）= %d" % len(hf))

    # ★ 复原「旧口径」：从 hit 里去掉重复 —— 旧版同一文件被拆成多个路由桶，
    #   数字上等于「按 (route) 分桶的命中数」。用唯一 route 数近似。
    uniq_routes = len({r for (_f, r) in new})
    uniq_files = len({f for (f, _r) in new})
    print()
    print("按 route 去重 = %d   按 file 去重 = %d" % (uniq_routes, uniq_files))
    print("→ 旧版 files_top 里 27 处被压成 9 个桶，就是因为它按 route 分桶")

    # ---- 形式二到底救回了多少 ----
    form2 = []
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
            if isinstance(n, ast.Call) and id(n) not in deco_ids:
                try:
                    nm = ast.unparse(n)
                except Exception:
                    continue
                if ".get(" in nm or ".post(" in nm:
                    base = nm.split("(")[0].split(".")[0].split(".")[-1]
                    if base in A.ROUTE_BASES:
                        form2.append((p, n.lineno, nm[:60]))
    print()
    print("=== 形式二能匹配到的裸调用（全项目扫）: %d 处 ===" % len(form2))
    for p, ln, nm in form2[:20]:
        print("  %s:%s  %s" % (p, ln, nm))
    if len(form2) > 20:
        print("  ... 还有 %d 处" % (len(form2) - 20))
    return 0


if __name__ == "__main__":
    sys.exit(main())