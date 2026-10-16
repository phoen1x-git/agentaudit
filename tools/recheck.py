# -*- coding: utf-8 -*-
"""
规则改动后重核：不碰网络，只重跑 AST 规则那一层。

★ 为什么可以只读缓存
--------------------
scan.py 里取文件走的是带磁盘缓存的 api_raw(repo, path, branch, "f__repo__path")，
网络拉过一次就落盘了。规则改动只影响 ast_criteria.analyze_files 这一步，
**与文件内容无关地可重算**。
→ 所以重核不需要重新 clone / 重新请求，纯离线几分钟就能跑完 11 个项目。

实测意义：原来 11 个项目重跑一遍要 小时（大部分时间在等 GitHub），
现在 <1 分钟。**「重跑一遍」和「重算一遍」是两件事，别混。**

用法：
    python tools/recheck.py --list data/target_pool/recheck.txt
    python tools/recheck.py --list ... --out data/target_pool/recheck_new.json

★ 规则自己坏没坏，用 tools/selftest_auth.py 的标准答案验证；
  本脚本只管把新数字算出来，并跟旧数字并排摆着方便对比。
"""
import argparse
import json
import os
import sys
import time

# ★ 输出重定向到文件时是块缓冲（8KB 才刷），
#   而本脚本总共就十几行输出 → 永远填不满缓冲区，进度条形同虚设。
#   而且进程被杀时缓冲区里的内容会全丢，违反「每步落盘」。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(line_buffering=True)
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import fetch_src_probe as fsp
import ast_criteria as astc

# ★ 只关心这几个规则的变化（其余规则没动，结果必然一致）
WATCH = ["inconsistent_auth", "unauth_endpoint"]


# ★★★ 规则版本
#   起因：06:40 启动 4 个重核分片 → 06:42 核实 sampleagent 时改了规则
#   → 06:46 发现已跑出的 3 条记录是**旧代码**的结果。
#   ★ 危险在于它看起来完全正常：有数字、有覆盖率、有证据，
#     只是规则版本不对 → 不查就会把旧数字当新结论。
def _kind_hist(agg):
    """★ 把「判定依据」的分布单独统计出来（不抽样）。

    起因：核实 sampleagent 时我从 `kind` 字段里看到
    「同文件内 **1/15** 个端点有鉴权」这个**分母**，才意识到
    another project 那 12 处全是误报。

    ★ 关键：那个分母是规则自证的信息（1/N 意味着「只有 1 个被认成有鉴权，
      其余全被带出来」，是假阳性的高发形态），**不该藏在 evidence 抽样里**。
      前 8 条里如果只有第 1 条是 1/15，抽样就看不见了。

    → 不依赖具体行号，只按 kind 字符串聚合。**这一项不占额外空间**，
      但让"能不能只凭落盘数据判断结果可信"从"要翻代码"变成"看一个字段"。
    """
    hist = {}
    for k, v in agg.items():
        for h in v["hits"]:
            kind = h.get("kind") or "(无)"
            key = "%s :: %s" % (k, kind)
            hist[key] = hist.get(key, 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: -kv[1]))


def _files_top(agg, limit=8):
    """★ 命中最集中的文件（核实工作从这里下手最省力）。

     核实 sampleagent 就是这么定位的：先看哪个文件命中最多，
    8 条 evidence 里7 条挤在 git.py → 一眼看出是「1 引爆 N」。
    """
    cnt = {}
    for k, v in agg.items():
        for h in v["hits"]:
            f = h.get("file")
            if not f:
                continue
            cnt.setdefault(f, {}).setdefault(k, 0)
            cnt[f][k] += 1
    rank = sorted(cnt.items(), key=lambda kv: -sum(kv[1].values()))
    return [{"file": f,
             "n": sum(cells.values()),
             "cells": cells}
            for f, cells in rank[:limit]]


def _criteria_hash():
    import hashlib
    p = os.path.join(HERE, "ast_criteria.py")
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def _criteria_stamp():
    """返回本批次启动时打的时间戳（同一批共用一个）。"""
    global _STAMP
    if _STAMP is None:
        import time as _t
        _STAMP = _t.strftime("%Y-%m-%d %H:%M:%S")
    return _STAMP


_STAMP = None


def cache_files_quiet(repo, branch):
    """★ 只看**磁盘缓存**统计，不发任何网络请求。返回 (n_cached, ) 或 None。

    为什么需要它
    ----------------------
    排分片时我想按「每个项目有多少文件」分片，于是对 29 个项目逐个调
    `cache_files()` —— 而它内部走 `fsp.api_get` / `api_raw`，
    **对没缓存的项目会真的去 GitHub 拉**（another project / another project 那种几百个文件）
    → 分片脚本自己先卡了 20 分钟，一个片都没排出来。

    ★ 教训：**「查一个项目的规模」和「把那个项目拉下来」是两件事**，
      偏像同一条代码路径。排片阶段只需要前者。

    缓存命名规则：`f__<repo把/ 换成_>__<path把/ 换成_>.py.txt`
    （见 fetch_src_probe.api_raw 的 cache_name 拼法）
    → 直接扫目录前缀就能计数，不用解缓存内容。
    """
    import glob as _glob
    import re as _re
    cd = os.path.join(HERE, "..", "data", "target_pool", "_src_cache")
    if not os.path.isdir(cd):
        return None
    pref = "f__%s__" % repo.replace("/", "_")
    n = 0
    for name in os.listdir(cd):
        if name.startswith(pref) and name.endswith(".py.txt"):
            n += 1
    if n == 0:
        return None
    return n


def cache_files(repo, branch):
    """只从缓存读，不发任何网络请求。返回 (files, total_py, miss)。"""
    tree = fsp.api_get(
        "https://api.github.com/repos/%s/git/trees/%s?recursive=1"
        % (repo, branch), "tree__%s__%s" % (repo, branch))
    entries = tree.get("tree") or []
    paths = [e.get("path") or "" for e in entries
             if e.get("type") in (None, "blob")]
    pys = [p for p in paths if p.endswith(".py")]
    if len(pys) < 30:
        return None, len(pys), []

    files = {}
    miss = []
    for p in pys:
        c = fsp.api_raw(repo, p, branch, "f__%s__%s" % (repo, p))
        if c:
            files[p] = c
        else:
            miss.append(p)
    return files, len(pys), miss


# ★ 只认这 6 个「原始扫描」产物当基准。
#   特意不认recheck 自己吐出来的 rc_*.json —— 那是重核结果，
#   拿它当基准等于自己跟自己比，第二轮重核会得到「零变化」的假象。
BASE_FILES = ("night_result.jsonl", "refill_result.jsonl",
              "refill2_result.jsonl", "refill3_result.jsonl",
              "lowcov_result.json")


def old_counts(repo):
    """从已有结果里翻出旧数字。

    ★★ 这里踩过一个严重的约定坑 Originally: 找到第一条就return，
    而文件顺序是night → refill → ...。night 批次多数项目走的是**抽样**
    （cov 0.1~0.3），refill 批次才是**全量**（cov 0.9+）。
    → 同一个项目在 night 里inc_auth=0、在 refill 里 inc_auth=4，
      按顺序取会拿到抽样那个 0，对比表就写成「0→4」，
      **看起来像规则新增了 4 个真阳性，实际那 4 个在抽样模式下本来就看不见。**
    → 报告里这么写会误导读者，也让规则迭代看起来在虚涨检出。

    正确约定：**遍历所有来源，取 coverage 最高的那条当基准。**
    （coverage 高的那次看得文件多，规则结论更可信。）
    """
    pool = os.path.join(ROOT, "data", "target_pool")
    best = None
    best_cov = -1.0
    for fn in BASE_FILES:
        fp = os.path.join(pool, fn)
        if not os.path.exists(fp):
            continue
        try:
            if fn.endswith(".jsonl"):
                rows = []
                for line in open(fp, encoding="utf-8"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
            else:
                rows = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(rows, list):
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            if (r.get("repo") or "").lower() != repo.lower():
                continue
            cov = r.get("coverage")
            cov = float(cov) if isinstance(cov, (int, float)) else 0.0
            if cov > best_cov:
                best_cov = cov
                best = r
    if best is None:
        return {}
    rec = _pull(best)
    # ★ 把基准的覆盖率和模式一起带出来 —— 不然读者无法判断这个基准可不可信
    rec["_base_cov"] = round(best_cov, 3)
    rec["_base_full"] = bool(best.get("full_mode"))
    return rec


def _pull(r):
    cells = r.get("cells") or {}
    return {k: (cells.get(k) or {}).get("n") for k in WATCH}


def main():
    ap = argparse.ArgumentParser(description="离线重核算规则")
    ap.add_argument("--list", required=True, help="批次文件（每行 owner/repo）")
    ap.add_argument("--out", default="", help="输出 JSON")
    ap.add_argument("--no-full", action="store_true",
                    help="只重核被抽样的文件（默认全量，与 --full 对齐）")
    a = ap.parse_args()

    with open(a.list, "r", encoding="utf-8") as f:
        repos = [l.strip() for l in f
                 if l.strip() and not l.startswith("#")]

    out = []
    # ★ 两个路径各司其职，别混：
    #   partial (.jsonl) —— 逐条追加的中途落盘，进程被杀也不丢
    #   a.out    (.json) —— 跑完后的完整汇总，给下游读
    #   （之前两者混用一个路径，导致 .json 里躺的是 JSONL 内容、只有一条时
    #     看起来像个 dict，下游按 list 读直接崩。）
    base = os.path.splitext(a.out)[0] if a.out else os.path.join(
        os.path.dirname(a.list), "_recheck")
    partial_path = base + "_partial.jsonl"

    def flush_out():
        """★ 每完成一个项目立刻落盘 —— 与 night_runner 同一条纪律。
        单个项目的 AST 分析可能十几分钟，中途被杀不该丢掉已算好的部分。"""
        with open(partial_path, "w", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

    for i, repo in enumerate(repos, 1):
        t0 = time.time()
        info = fsp.api_get("https://api.github.com/repos/%s" % repo,
                           "repo__%s" % repo)
        if "_error" in info or "full_name" not in info:
            print("[%d/%d] %s  取信息失败" % (i, len(repos), repo))
            continue
        branch = info.get("default_branch") or "main"

        files, total_py, miss = cache_files(repo, branch)
        if files is None:
            print("[%d/%d] %s  py 只有 %d 个（<30），跳过"
                  % (i, len(repos), repo, total_py))
            continue

        agg, pf = astc.analyze_files(files)
        cov = len(files) / float(total_py)
        # ★★★ 证据落盘：全量 + 显式上限
        #   起因：核实 sampleagent 时发现 evidence 只有 8 条，而 n_hits=103。
        #   两者不矛盾（前者计数、后者抽样），但**报告里不写清就会让人
        #   以为"8 条就是全部"** —— 我不能替那 95 条背书。
        #
        #   为什么全量而不是截断：整个流水线的核心是"检出≠有洞，靠人工核实"，
        #   而重跑一个项目要十几分钟 AST 分析。**抽样等于把核实工作变成不可行**。
        #   上限只是防极端项目（几千处命中）把 jsonl 撑爆。
        EV_CAP = 2000
        #★★★★ 落盘前结构自检。
        #   起因：我在 `analyze_files` 里往 agg 塞了个 `_meta`，它没有 `n_hits`
        #   → 下面这个 dict 推导式直接 KeyError，
        #   → **6 个分片全部跑到最后一步才崩，每个白跑 分钟。**
        #   ★ 这类"同构字典里混进一个异构键"的错，**在产出这一环就该拦住**，
        #     而不是等到别的工具遍历时才炸。
        for _k, _v in agg.items():
            if not isinstance(_v, dict) or not all(
                    x in _v for x in ("n_hits", "hits", "label")):
                print("  ★★ 规则返回值里混进异构键 %r（keys=%s）—— 已中止，"
                      "别把这批数据落盘" % (
                          _k, sorted(_v) if isinstance(_v, dict) else type(_v)))
                return 1
        rec = {
            "repo": repo, "branch": branch,
            "total_py": total_py, "cached": len(files),
            "coverage": round(cov, 3),
            "n_miss": len(miss), "parse_failed": pf,
            "secs": round(time.time() - t0, 1),
            # ★★★ 规则版本随记录一起落盘
            #  起因：06:40 启动分片 → 06:42 改了规则 → 06:46 发现已跑出的
            #   3 条是**旧代码**的结果，而它们看起来完全正常（有数字有证据）。
            #   → 每条记录自证「我是用哪版规则跑的」，不用靠记忆。
            "criteria_ver": _criteria_hash(),
            "criteria_stamped": _criteria_stamp(),
            "cells": {k: {"n": v["n_hits"], "label": v["label"]}
                      for k, v in agg.items()},
            # ★★★ 三项自证数据（不再只留8 条抽样）
            "evidence_n": {k: v["n_hits"]
                           for k, v in agg.items() if v["n_hits"]},
            "evidence_capped": {k: v["n_hits"] > EV_CAP
                                for k, v in agg.items() if v["n_hits"]},
            "kind_hist": _kind_hist(agg),
            "files_top": _files_top(agg),
            "evidence": {k: v["hits"][:EV_CAP]
                         for k, v in agg.items() if v["n_hits"]},
            #★★ 规则运行元信息（★ 与 agg 物理隔离，见 ast_criteria.LAST_RUN_META）
            #   必须落盘：「排掉多少测试文件」是解释数字变化的**前提**——
            #   没有它，看到 n_hits 变小只会以为规则变严了。
            "criteria_meta": dict(astc.LAST_RUN_META),
        }
        old = old_counts(repo)
        rec["old"] = old
        out.append(rec)
        flush_out()          # ★ 先落盘，再 print

        print("[%d/%d] %-52s cov=%3.0f%% 新不一致鉴权=%-4s 旧=%-4s(基准cov=%s)"
              % (i, len(repos), repo, cov * 100,
                 agg.get("inconsistent_auth", {}).get("n_hits"),
                 old.get("inconsistent_auth"),
                 ("%.0f%%" % (old["_base_cov"] * 100))
                 if "_base_cov" in old else "?"))

    if a.out:
        # ★ 必须写 list —— 之前这里写 list，但 rc_a.json 里读出来是 dict，
        #   说明中途有别的路径把单条记录写进了同一个文件。
        #   保险做法：写前先删旧文件，且始终以 list 形式落盘。
        try:
            os.remove(a.out)
        except OSError:
            pass
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        print("\n写入 %s（%d 条）" % (a.out, len(out)))

    # 汇总：只有覆盖够的才能出结论
    print("\n" + "=" * 78)
    print("%-50s %5s %-16s %-16s" % ("repo", "cov", "不一致鉴权新/旧", "无鉴权新/旧"))
    print("-" * 78)
    for r in out:
        o = r.get("old") or {}
        print("%-50s %4.0f%% %7s/%-6s(base%3.0f%%) %7s/%-6s"
              % (r["repo"][:50], r["coverage"] * 100,
                 (r["cells"].get("inconsistent_auth") or {}).get("n"),
                 o.get("inconsistent_auth"),
                 (o.get("_base_cov") or 0) * 100,
                 (r["cells"].get("unauth_endpoint") or {}).get("n"),
                 o.get("unauth_endpoint")))
    good = [r for r in out if r["coverage"] >= 0.6]
    print("-" * 78)
    print("覆盖>=60%% 可出结论: %d/%d" % (len(good), len(out)))

    # ★★ 只有「新旧基准覆盖可比」时，差值才允许解释成「规则变化带来的」。
    #   如果新扫描 cov=98% 而基准是抽样 cov=26%，那 +4 可能只是
    #   「基准那次没看到那么多文件」，不是规则变松/变严。
    print("\n可比性检查（新旧覆盖率差 >15 个百分点 → 差值不可直接归因于规则）:")
    incomparable = []
    for r in out:
        o = r.get("old") or {}
        bc = o.get("_base_cov")
        if bc is None:
            incomparable.append((r["repo"], "无基准"))
        elif abs(r["coverage"] - bc) > 0.15:
            incomparable.append((r["repo"], "新%.0f%% vs 基准%.0f%%"
                                % (r["coverage"] * 100, bc * 100)))
    if incomparable:
        for repo, why in incomparable:
            print("  ! %-50s %s" % (repo[:50], why))
    else:
        print("  全部可比")
    return 0


if __name__ == "__main__":
    sys.exit(main())
