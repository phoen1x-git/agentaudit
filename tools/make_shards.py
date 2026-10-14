#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""★ 按「实测体量」重排分片，避免大项目把整片拖死。

起因
----
10-05 07:2x 第三次重排分片。前两次都犯了同一个错：
**按"仓库名看起来大不大"分片**，而不是按实际文件数。
结果 v3_1~4 每片都混进了一个巨无霸：
    sampleagent(1561 py / 967 测试) · another project · another-org/another-agent
→ 4 片里有 3 片卡在同一个项目上，另几片早就跑完了在空转。

★ 为什么不能沿用旧分片：
  排除测试文件后体量变了。sampleagent 967 个文件被排除 → 实际分析量从 1561 降到 594。
  分片必须按**新约定下的实际分析量**排，不是旧的约定。

★ 关键设计：**大项目单独成片，不与别的混**
  一个大项目跑 20 分钟，和它同片的 6 个小项目就得等 20 分钟。
  单独成片后：它跑它的，其他片跑完就结束。
  → 「大项目 = 一个只跑一个项目的分片」

用法
----
    python tools/make_shards.py --out-prefix data/target_pool/rc_v4 --shards 5 \
        <repo> [repo...]
"""
from __future__ import print_function
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import recheck as R                      # noqa: E402
from is_test_path import is_test_path    # noqa: E402

# ★ 单片文件数上限。超过就自己成一片。
BIG = 900


def main(argv):
    # ★★★ 参数解析要放在"收集非-- 开头参数"**之前**，否则 `=` 形式
    #   解析出 prefix 后，紧跟的 -- 判定会把值也当成普通参数。
    #   上一版先收集 args 再解析 options，导致 --out-prefix=X 的值 X
    #   被当成 repo 名（写文件时变成 "X.txt"），而 args 里一个 repo 都没有
    #   → 直接 print(__doc__) 退出，看起来像"参数没传"。
    prefix = "data/target_pool/rc_v4"
    nshard = 5
    args = []
    rest = argv[1:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--out-prefix":
            prefix = rest[i + 1]; i += 2; continue
        if a.startswith("--out-prefix="):
            prefix = a.split("=", 1)[1]; i += 1; continue
        if a == "--shards":
            nshard = int(rest[i + 1]); i += 2; continue
        if a.startswith("--shards="):
            nshard = int(a.split("=", 1)[1]); i += 1; continue
        if a.startswith("--"):
            print("! 未知参数: %s" % a); i += 1; continue
        args.append(a); i += 1
    if not args:
        print(__doc__)
        return 1

    sizes = {}
    for repo in args:
        # ★★ 只数**磁盘缓存**里有多少个 .py.txt，不发网络请求。
        #   第一版对 29 个项目逐个 cache_files()，那会真去 GitHub 拉
        #   未缓存的项目 → 分片脚本自己卡了 20 分钟。
        #   ★ 「查规模」和「拉源码」是���件事，别用同一条路径。
        n = R.cache_files_quiet(repo, "main")
        if not n:
            sizes[repo] = (BIG + 1, 0)      # ★ 未知 → 按大项目处理（保守）
            print("  ?? %-46s 缓存缺→ 单跑一片" % repo)
            continue
        sizes[repo] = (n, n)
        print("  %-46s 缓存 py %5d" % (repo, n))

    # ★ 降序排：大的先分出去，避免最后剩一堆积压在一片里
    order = sorted(args, key=lambda r: (-sizes[r][0], -sizes[r][1]))

    shards = []
    for repo in order:
        n = sizes[repo][0]
        if n >= BIG:
            shards.append([repo])            # ★ 大项目/未知 → 独占一片
            continue
        # ★ 装进当前负载最小的片（先排序再放 → 天然均衡）
        shards.sort(key=lambda s: sum(sizes[r][0] for r in s))
        if not shards:
            shards.append([repo])
        else:
            shards[0].append(repo)

    #★★ 分片数上限：**只合并小片，大项目片永不合并**。
    #   ★ 踩过的坑：第一版 `while len(shards) > nshard: 合并最小片`
    #     会把「sampleagent」「another project」这些各自单跑的大项目片也塞进同一个片
    #     → 合并回"4 片里3 片卡在同一个巨无霸"的状态，等于没分。
    #   → 目标片数是给**小项目**用的；大项目该几片就几片。
    big_shards = [s for s in shards if len(s) == 1 and
                  sizes[s[0]][0] >= BIG]
    small_shards = [s for s in shards if not (len(s) == 1 and
                                             sizes[s[0]][0] >= BIG)]
    while len(small_shards) > max(1, nshard - len(big_shards)):
        small_shards.sort(key=lambda s: sum(sizes[r][0] for r in s))
        a = small_shards.pop(0)
        small_shards[0].extend(a)
    shards = big_shards + small_shards

    print()
    print("分 %d 片（大项目 %d 个各占一片，小项目 %d 片）:"
          % (len(shards), len(big_shards), len(small_shards)))
    #★ 大片先跑：它们最慢，早点开始，整体收尾更早
    shards.sort(key=lambda s: -sum(sizes[r][0] for r in s))
    for i, sh in enumerate(shards, 1):
        load = sum(sizes[r][0] for r in sh)
        p = "%s_%d.txt" % (prefix, i)
        with open(p, "w", encoding="utf-8") as f:
            for r in sh:
                f.write(r + "\n")
        print("  %-28s %6d 文件  %d 个项目%s"
              % (p, load, len(sh),
                 "  ★单跑" if len(sh) == 1 else ""))
        for r in sh:
            print("        %-46s %5d" % (r[:46], sizes[r][0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
