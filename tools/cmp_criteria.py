#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""★★ 改判据后的「决定性实验」工具：跑两套口径，逐 cell 出差 + 集合差。

起因
----
我 10-05 早上连续两次栽在同一个地方：**改完判据看不出变好还是变坏**。
- 补第 6 种写法 → inc 从 2 涨到 14，我以为「修对了」，实际 12 处全是误报
- 修 `ensure_future` 假阳性 → 数字降了，但没验证降的是不是该降的

★ 所以定一条纪律：**改判据后，先跑这个工具拿到「差值 + 集合差」再说话。**

它能回答什么
------------
| 输出 | 回答的问题 |
|---|---|
| 每cell 的 `A -> B` | 数字变了多少 |
| `仅A` / `仅B` 的条数 | ★ 是「同一批改了数量」还是「换了一批」 |
| 变化样本 | 那几条具体长什么样（人工核实入口） |

★ **集合差比差值重要**。
  差值 +2 可能是「多认了 2 个端点」，也可能是「原来认的那 2 个不见了、
  换成了另外 2 个」—— 后者意味着修错了方向，而差值完全看不出。

用法
----
    python tools/cmp_criteria.py <repo> [repo...]
    python tools/cmp_criteria.py --cells inconsistent_auth,unauth_endpoint <repo>

性能
----
默认**只跑一遍** AST（不带排除），再按 `is_test_path` 之类把命中分流。
理由：`analyze_files` 逐文件独立分析（第 1 趟别名收集是全局的，
但它对生产/测试文件一视同仁），所以分流结果与「真的排除后重跑」一致。
→ 成本从 2N 降到 N。
"""
from __future__ import print_function
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import recheck as R              # noqa: E402
import ast_criteria as A         # noqa: E402

DEFAULT_CELLS = ["inconsistent_auth", "unauth_endpoint", "injection_surface",
                 "code_exec_sink", "agent_tool_surface", "auth_surface"]


def _hitkey(h):
    return "%s:%s" % (h.get("file"), h.get("line"))


def _load():
    """判定口径变体：名字 -> 命中过滤器。★ 每个变体一条独立规则。"""
    from is_test_path import is_test_path
    return {
        "含测试文件": lambda h: True,
        "排除测试文件": lambda h: not is_test_path(h.get("file") or ""),
    }


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    cells = DEFAULT_CELLS
    for a in argv[1:]:
        if a.startswith("--cells"):
            cells = a.split("=", 1)[1].split(",") if "=" in a \
                else a.split(" ", 1)[1].split(",")
    if not args:
        print(__doc__)
        return 1

    variants = _load()
    summary = {}
    for repo in args:
        files, total_py, miss = R.cache_files(repo, "main")
        if files is None:
            print("== %-46s 缓存缺（先跑一次让它落盘）" % repo)
            continue
        print("== %-46s py %d" % (repo, len(files)))
        print("   " + " | ".join(
            "%s: %d" % (n, sum(1 for f in files if fn({"file": f}) and f.endswith(".py")))
            for n, fn in variants.items()))
        agg, _ = A.analyze_files(files, skip_tests=False)
        # ★★不要写 `agg.pop("_meta", {})` —— 判据已经**物理隔离**元信息了
        #   （ast_criteria.LAST_RUN_META）。10-05 07:5x 踩过：
        #   元信息一旦进 agg，下游 6 处 `for k,v in agg.items()` 全会崩。
        #   这里顺手做一次**结构自检** —— 判据 cell 必须是同构的。
        for k, v in agg.items():
            if not all(x in v for x in ("n_hits", "hits", "label")):
                print("   ★★ 判据返回值里混进了异构键 %r（keys=%s）"
                      " —— 下游遍历会 KeyError" % (k, sorted(v)))
                return 1
        for cell in cells:
            if cell not in agg:
                continue
            hits = agg[cell]["hits"]
            buckets = {n: [_hitkey(h) for h in hits if fn(h)]
                       for n, fn in variants.items()}
            names = list(variants)
            A_ = set(buckets[names[0]])
            B_ = set(buckets[names[1]])
            d = len(B_) - len(A_)
            print("   %-24s %s -> %s  %+d" % (cell, len(A_), len(B_), d))
            if A_ != B_:
                only_a = sorted(A_ - B_)[:3]
                only_b = sorted(B_ - A_)[:3]
                print("        ★ 集合不同：仅%s有=%d  仅%s有=%d"
                      % (names[0], len(A_ - B_), names[1], len(B_ - A_)))
                for k in only_a:
                    print("           - %s" % k)
                for k in only_b:
                    print("           + %s" % k)
        print()
        summary[repo] = {c: {n: len([1 for h in agg.get(c, {}).get("hits", [])
                                     if fn(h)])
                             for n, fn in variants.items()} for c in cells}

    with open(os.path.join(HERE, "_cmp_last.json"), "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
