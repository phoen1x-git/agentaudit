# -*- coding: utf-8 -*-
"""修好记录层之后，「数据源分布」终于能看了 —— 摊开 unauth_endpoint 按文件分组。

★★★ 为什么必须先修记录层（10-05）
   修之前 evidence 的 "file" 存的是路由路径，所以 files_top 里
   27 处命中被压成 9 个「路由」桶 —— 我看到的分布是假的。
   ★ 教训：**files_top 是「先怀疑数据源」那一步的入口**，
     它自己失真的时候，那一步整个失效，而且看不出来。

用法：python tools/dump_unauth_files.py <repo> [branch]
"""
import io
import os
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "rhesis-ai/rhesis"
    branch = sys.argv[2] if len(sys.argv) > 2 else "main"
    files, total, miss = recheck.cache_files(repo, branch)
    if not files:
        print("缓存里没有 %s" % repo)
        return 1
    res, failed = A.analyze_files(files, skip_tests=True)
    hits = res["unauth_endpoint"]["hits"]

    by = defaultdict(list)
    for h in hits:
        by[h.get("file")].append(h)

    print("repo=%s  命中 %d 处，涉及 %d 个文件"
          % (repo, res["unauth_endpoint"]["n_hits"], len(by)))
    print("=" * 78)
    for f in sorted(by, key=lambda x: -len(by[x])):
        print("\n### %s  (%d 处)" % (f, len(by[f])))
        for h in sorted(by[f], key=lambda x: x.get("line") or 0):
            print("   L%-5s %-32s %s"
                  % (h.get("line"), h.get("route") or "?",
                     h.get("kind", "")))
            print("         %s" % (h.get("text") or "")[:100])

    # ★ 顺手分个类：examples / demos / tests 占比 ——
    #   这类目录里的端点**不是真实部署的攻击面**，
    #   混进来会让「检出数」看起来很热闹，其实没法报。
    print("\n" + "=" * 78)
    print("=== 按目录性质分类 ===")
    buckets = {"示例/演示": 0, "测试": 0, "真实业务": 0}
    for f in by:
        lf = f.lower()
        if "test" in lf or "spec" in lf:
            buckets["测试"] += len(by[f])
        elif ("example" in lf or "demo" in lf or "sample" in lf
              or "tutorial" in lf or "quickstart" in lf
              or "getting_started" in lf):
            buckets["示例/演示"] += len(by[f])
        else:
            buckets["真实业务"] += len(by[f])
    for k, v in buckets.items():
        print("  %-10s %d 处  %s" % (k, v, "#" * v))
    return 0


if __name__ == "__main__":
    sys.exit(main())