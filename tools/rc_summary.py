#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""把重核结果汇总成一张前后对照表。

★ 为什么单独写这个：recheck.py 每次只跑一个分片，
   手工拼表容易漏字段、也容易把"没变"看成"没跑"。
   这里统一处理：*.json（整批完成）和 *_partial.jsonl（跑到一半）都能吃。

用法:
    python tools/rc_summary.py                # 全部
    python tools/rc_summary.py rc_v2_2.json   # 指定文件
"""
import json
import os
import sys
import glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "target_pool")

# ★ 只关心这两个判据 —— 本轮修的只有鉴权相关的
WATCH = ("inconsistent_auth", "unauth_endpoint")


def n_of(v):
    """cells[k] 可能是 int、可能是 {'n':..,'label':..}、可能是 list。统一成 int 或 None。"""
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, dict):
        x = v.get("n")
        return x if isinstance(x, int) else None
    if isinstance(v, list):
        return len(v)
    return None


def load(fn):
    """返回 [(源文件, record)]。json 走 list，jsonl 逐行。"""
    p = fn
    if not os.path.isabs(p):
        # ★ 已经在 pool 目录下的相对路径不要重复拼 POOL。
        #   之前写成 `os.path.join(POOL, fn)` 无条件拼，
        #   传 "data/target_pool/night_result.jsonl" 就变成
        #   ".../data/target_pool/data/target_pool/night_result.jsonl"
        #   → 文件不存在 → 静默返回 0 条（★ 最坏的失败方式：看起来像"没数据"）
        if os.path.exists(fn):
            p = fn
        else:
            p = os.path.join(POOL, fn)
    if not os.path.exists(p):
        # ★ 显式告警：之前这个分支是静默 return []，
        #   上层看起来像"这批没有记录"，实际上是路径拼错了。
        #   「没有数据」和「找不到文件」必须能区分 —— 同"0 处检出"vs"压根没查"是同一类。
        print("  ! 找不到文件: %s" % p)
        return []
    out = []
    if p.endswith(".jsonl"):
        with open(p, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    # ★ 半行 = 正在写，最后一行常被截断。跳过而不是崩。
                    continue
                if isinstance(r, dict) and r.get("repo"):
                    out.append((os.path.basename(p), r))
    else:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print("  ! 读不了 %s: %s" % (os.path.basename(p), e))
            return []
        if isinstance(d, list):
            for r in d:
                if isinstance(r, dict) and r.get("repo"):
                    out.append((os.path.basename(p), r))
    return out


def pick_files(argv):
    if argv:
        return argv
    # 排除 recheck 自己吐的 rc_one/rc_a/rc_b —— 那些是单项目试跑
    fs = sorted(glob.glob(os.path.join(POOL, "rc_v2_*.json")))
    fs += sorted(glob.glob(os.path.join(POOL, "rc_v2_*_partial.jsonl")))
    fs += sorted(glob.glob(os.path.join(POOL, "rc_rest*.jsonl")))
    return fs


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    files = pick_files(sys.argv[1:])
    seen = {}
    order = []
    for f in files:
        for src, r in load(f):
            # ★★ 同一 repo 多次跑时选哪一条？**先按判据版本，再按覆盖率**。
            #   理由：coverage 高不代表该取 —— 旧判据跑的批次覆盖率可能更高，
            #   拿它当代表就是"用旧判据的数字冒充新判据的结果"。
            #   （这个坑与 old_counts() 取错基准同源，只是方向相反。）
            key = r["repo"].lower()
            ver = r.get("criteria_ver") or ""
            cov = round(float(r.get("coverage") or 0), 3)
            rank = (ver, cov)          # 版本优先，版本相同再比覆盖率
            if key in seen:
                orank = (seen[key][1].get("criteria_ver") or "",
                         round(float(seen[key][1].get("coverage") or 0), 3))
                if rank <= orank:
                    continue
            seen[key] = (src, r)
            if key not in order:
                order.append(key)

    if not order:
        print("没有可用记录。先跑 tools/recheck.py --list <清单> --out <输出>")
        return

    print("重核对照表  ·  判据: %s" % " / ".join(WATCH))
    # ★ 口径文案必须与实际选取逻辑一致（原来是"coverage 最高"，
    #   实际早就改成"版本优先、再比覆盖"—— 行为对、文案错。
    #   这跟 10-05 早上 academic-commercialization 那次是同一类错误：
    #   **数字对不代表说法对，说法会误导下一个读的人。**）
    print("记录 %d 条  (同 repo 多次跑时取判据版本最新那次，版本相同再取 coverage 最高)"
          % len(order))
    # ★ 判据版本一致性检查：不同版本的数字不能并排比
    vers = {}
    for key in order:
        vers.setdefault(seen[key][1].get("criteria_ver") or "(无版本记录)", []).append(
            seen[key][1]["repo"])
    if len(vers) > 1:
        print()
        print("★★ 判据版本不一致 —— 下面这些数字**不能直接互相比较**：")
        for v, repos in vers.items():
            print("   %s  %d 个项目" % (v, len(repos)))
        print()
        print("   ★ 这是**有意为之**，不是出错（10-05 实测，详见 docs/47）：")
        print("     PEP 695 类型别名 + `.well-known` 豁免这条修复，")
        print("     实测只影响 jarvis-registry 的 9 个端点（measure_pep695.py量过），")
        print("     为它把 29 个项目全重跑 ≈ 40 分钟，不划算。")
        print("     → 规则：判据改动后**先量影响面**，只重跑受影响的项目。")
        print("     → 前提：每个项目的判据版本必须印在表上（见版本列）。")
    print()

    changed = []
    #★★★★★ 表里直接带判据版本列 —— 这是「分两版跑」能自洽的前提。
    #   10-05 的做法：PEP 695 修复只影响 1 个项目 9 个端点，
    #   为它把 29 个项目全重跑不划算 → 只重跑那1 个，其余按旧戳跑。
    #   ★ 代价是**这张表里混了两个版本的数字**。
    #   ★ 不把版本印在表上 = 下一个读表的人会把它们当同口径比较。
    #     「数字对不代表说法对」—— 说法会误导下一个读的人。
    hdr = "%-42s %-9s %5s %5s  %-22s %s"
    print(hdr % ("repo", "判据版本", "cov", "full",
                 "inconsistent_auth", "unauth_endpoint"))
    print("-" * 108)
    for key in order:
        src, r = seen[key]
        cells = r.get("cells") or {}
        old = r.get("old") or {}
        cov = float(r.get("coverage") or 0)
        full = "Y" if r.get("full_mode") else (old.get("_base_full") and "Y" or "?")
        ver = (r.get("criteria_ver") or "?")[:8]
        line = "%-42s %-9s %5.3f %5s  " % (r["repo"][:42], ver, cov, full)
        for k in WATCH:
            o = n_of(old.get(k))
            n = n_of(cells.get(k))
            if o is None and n is None:
                line += "%-22s " % "-"
            elif o is None:
                line += "%-22s " % ("%s (新)" % n)
            else:
                mark = "" if o == n else "  <<< %+d" % (n - o)
                line += "%-22s " % ("%s -> %s%s" % (o, n, mark))
                if o != n:
                    changed.append((r["repo"], k, o, n, src, cov,
                                    old.get("_base_cov")))
        print(line.rstrip())

    print()
    # ★ 可比性检查放最后：覆盖差太大时，差值不能归因于判据
    bad = []
    for repo, k, o, n, src, cov, bc in changed:
        if bc is None:
            continue
        if abs(cov - float(bc)) > 0.15:
            bad.append((repo, k, o, n, cov, float(bc)))
    if bad:
        print("可比性检查（新旧覆盖率差 >15 个百分点 → 差值不可直接归因于判据）:")
        for repo, k, o, n, cov, bc in bad:
            print("  ! %-44s %s %s->%s  新%.1f%% vs 基准%.1f%%" %
                  (repo[:44], k, o, n, cov * 100, bc * 100))
    else:
        print("可比性检查: 全部通过（覆盖差 <= 15 个百分点）")

    if changed:
        print()
        print("有变化的 %d 项:" % len(changed))
        for repo, k, o, n, src, cov, bc in changed:
            print("  %-44s %-20s %s -> %s   (%s)" % (repo[:44], k, o, n, src))
    else:
        print()
        print("★ 全部无变化 —— 这本身是结论：这几个项目里没有第 6 种写法。")

    _verdict_section(seen, order)


# ★★★★ 「同文件内 1/N」是假阳性的高发形态，排序依据写在这里，别只记在脑子里。
_SUSPECT_KINDS = (":: 同文件内 1/",       # 0->1 跃迁：1 个假阳性带出 N-1 个
                  "（本文件其它地方有鉴权）")  # 模块级有鉴权但这个端点没有


def _verdict_section(seen, order):
    """按「可核实性」给项目排序，输出核实优先级。

    ★ 为什么需要这一节：判据报的是**不一致**，不是「没鉴权」。
      一个项目里有多少命中是真洞，取决于它的判定依据形态：
      -「同文件内 3/5」→ 同文件有 3 个端点被认成有鉴权，形态可信度较高
      - 「同文件内 1/15」→ **只有 1 个被认成有鉴权，其余 14 个全是被带出来的**，
        一个假阳性就能引爆 14 处（docs/44 的 12 处、docs/45 的 4 处都是这个形态）
    → 排序直接决定先核实谁。
    """
    rows = []
    for key in order:
        r = seen[key][1]
        cells = r.get("cells") or {}
        n = n_of(cells.get("inconsistent_auth")) or 0
        if n <= 0:
            continue
        hist = r.get("kind_hist") or {}
        # 「同文件内 1/N」的总条数 = 分子为 1 的形态数
        weak = sum(v for k, v in hist.items()
                   if k.startswith("inconsistent_auth ::") and ":: 同文件内 1/" in k)
        strong = n - weak
        rows.append((weak / float(n), weak, strong, n, r["repo"]))

    if not rows:
        print()
        print("核实优先级: 没有 inconsistent_auth 命中，无需定性。")
        return

    rows.sort(key=lambda t: (-t[0], -t[3]))
    print()
    print("=" * 104)
    print("核实优先级（按『弱形态占比』降序 —— 占比越高越可能是判据缺陷而非真洞）")
    print("  弱形态 = kind 判据是「同文件内 1/N」：只有 1 个端点被认成有鉴权，")
    print("           其余 N-1 个全是被它带出来的 → 1 个假阳性就能引爆一片")
    print("-" * 104)
    for ratio, weak, strong, n, repo in rows:
        tag = "★先核实" if ratio >= 0.5 else ("可疑" if ratio > 0 else "")
        print("  %-44s inc=%-5s 弱 %-5s 强 %-5s  %3.0f%%弱  %s"
              % (repo[:44], n, weak, strong, ratio * 100, tag))

    star = [t for t in rows if t[0] >= 0.5]
    if star:
        print()
        print("★ 这 %d 个项目先核实：弱形态占比 >=50%%，很可能是判据问题。" % len(star))
        print("  核实动作：看 files_top 里命中最集中的那个文件 + kind_hist 的分母，")
        print("           再抽 2~3 条读源码确认那个『1』到底是不是真的。")
    print("  ★ 只有落了 kind_hist / files_top 的记录能这么排（10-05 07:0x 起才有）；")
    print("    旧记录缺这两个字段 → 上表会低估它的弱形态占比，别当结论用。")


if __name__ == "__main__":
    main()
