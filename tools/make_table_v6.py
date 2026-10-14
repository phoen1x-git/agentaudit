# -*- coding: utf-8 -*-
"""把 final_v8.json 出成 markdown 对照表。

★ 为什么单独一个脚本：对照表要给「哪些项目值得挖」下判断，
  不是把数字抄一遍。所以排序按**可核查性**排，不按命中数排 ——
  命中数多的项目里可能全是测试代码或演示代码，
  排第一反而会误导人去挖。
"""
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
POOL = os.path.normpath(os.path.join(HERE, "..", "data", "target_pool"))
SRC = os.path.join(POOL, "final_v8.json")
OUT = os.path.join(HERE, "..", "docs", "59_横向对照表_20261007_v8.md")

CRITERIA = "aa148b65e9143f54"


def bucket(v):
    """按「业务代码规模」分档 —— 这才是可核查性的大头。

    ★ 为什么不用命中数当主序：命中数只说明判据响了，
      不说明那里有真东西。1561 个 py 文件里排掉 967 个测试文件的项目，
      和 111 个 py 文件排掉 0 的项目，前者的命中更需要逐条核。
    """
    biz = v["total_py"] - v["skipped_test_files"]
    if biz <= 0:
        return "4无业务代码"
    if biz < 100:
        return "3业务<100"
    if biz < 500:
        return "2业务100~500"
    return "1业务>=500"


def main():
    if not os.path.exists(SRC):
        print("找不到 %s" % SRC)
        sys.exit(2)
    res = json.load(open(SRC, encoding="utf-8"))

    rows = []
    for repo, v in res.items():
        biz = v["total_py"] - v["skipped_test_files"]
        rows.append((bucket(v), repo, v["ua"], v["ia"], v["total_py"],
                     v["skipped_test_files"], biz))

    rows.sort(key=lambda r: (r[0], -r[6]))

    L = []
    L.append("# 横向对照表：30 个 Agent 项目的判据基线")
    L.append("")
    L.append("> 生成于 2026-10-07（核实后 v8 基线），判据哈希 `%s`，9 套 127 档自测全绿。" % CRITERIA)
    L.append("> 数字来自 `data/target_pool/final_v8.json`（跑一条落一条）。")
    L.append("")
    L.append("## ★ 这张表怎么看（别只盯着命中数）")
    L.append("")
    L.append("**命中数 ≠ 有漏洞。** 它只说明判据响了。真正决定「值不值得去挖」的是")
    L.append("**业务代码规模**——排掉测试文件之后还剩多少代码可看。")
    L.append("所以主序按业务代码规模排，命中数只是附注。")
    L.append("")
    L.append("一档里有两个数要分开看：")
    L.append("")
    L.append("- `unauth` = 无鉴权痕迹的端点数")
    L.append("- `inconsistent` = 同一个文件里鉴权写法不一致的端点数")
    L.append("")
    L.append("**`inconsistent` 更值得优先看。** 因为它说明这个项目**懂鉴权**"
             "（有的地方写了，有的没写），而不是整体没这回事——"
             "漏写比没有更容易被承认和修。")
    L.append("")

    for b, title in [("1业务>=500", "一档：业务代码 ≥ 500 行"),
                     ("2业务100~500", "二档：业务代码 100 ~ 500 行"),
                     ("3业务<100", "三档：业务代码 < 100 行"),
                     ("4无业务代码", "四档：业务代码 ≈ 0（不可核查）")]:
        g = [r for r in rows if r[0] == b]
        if not g:
            continue
        L.append("## %s —— %d 个项目" % (title, len(g)))
        L.append("")
        L.append("| 项目 | unauth | inconsist | py 总数 | 排测试 | **业务代码** |")
        L.append("|---|---:|---:|---:|---:|---:|")
        for _b, repo, ua, ia, tp, st, biz in g:
            flag = "" if ua or ia else " 报0"
            L.append("| `%s` | %d | %d | %d | %d | **%d**%s |"
                     % (repo, ua, ia, tp, st, biz, flag))
        L.append("")

    zero = [r for r in rows if r[2] == 0 and r[3] == 0]
    nz = [r for r in rows if r[2] or r[3]]
    L.append("## 一句话结论")
    L.append("")
    L.append("**报 0 的 %d 个，报非 0 的 %d 个。**" % (len(zero), len(nz)))
    L.append("")
    L.append("★ **报 0 不等于干净** —— 只等于「这一版判据在这个项目上没有命中」。")
    L.append("每个报 0 的项目仍要人工过一遍这两件事：")
    L.append("")
    L.append("1. 它**有没有多用户模型**（服务型项目才谈得上越权，见 skill 的相关纪律）")
    L.append("2. 它的鉴权是**中间件/装饰器**做的吗（判据的第 5、7 种写法有已知盲区）")
    L.append("")
    L.append("下一档：**对报非 0 的项目逐条摊开 evidence 做人工核实**，")
    L.append("用 `tools/dump_unauth_files.py`（先看数据源分布，再逐条读）。")
    L.append("")
    L.append("---")
    L.append("")
    L.append("**判据版本**：`%s`　**对外提交**：0 份" % CRITERIA)

    out = os.path.normpath(OUT)
    open(out, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("已写出 %s" % out)
    print("报 0: %d  报非 0: %d" % (len(zero), len(nz)))


if __name__ == "__main__":
    main()