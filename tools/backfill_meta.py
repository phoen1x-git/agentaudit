#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""★离线给旧记录补上 kind_hist / files_top / 全量 evidence。

起因（2026-10-05 07:0x）
----------------------
recheck.py 原先只落盘`v["hits"][:8]`，于是：
- `n_hits=103` 但 `evidence` 只有 8 条 → 报告里不写清就会让人以为「8 条就是全部」
- 更要紧的是：**判据自证所需的信息被截断了**。
  核实 academic-commercialization 那 12 处时，我是看到 `kind` 里的分母
  「同文件内 **1/15**」才发现全是误报。那个分母藏在 evidence 抽样里，
  前 8 条只要不正好包含它，抽样就永远看不见。

判据改动会让正在跑的批次作废，所以不能靠「改判据→重跑」解决。
但 `cache_files()` 只从 HTTP 缓存读、不发网络请求，
而**判据本身（ast_criteria.py）没变** →
→ **只需要把 `_find_inconsistent_auth` 这一趟重跑一遍，就能从缓存还原全量 hits。**
   不用重跑整个analyze_files（那才是十几分钟 AST 分析的大头）。

用法
----
    python tools/backfill_meta.py <partial.jsonl> [更多文件...]
    python tools/backfill_meta.py --out <新.jsonl> <输入...>

原地覆写（默认）：同路径写回，**先写 .tmp 再 replace**，中途被杀不会毁掉原文件。
"""
from __future__ import print_function
import ast
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ast_criteria as astc            # noqa: E402
import recheck as R                    # noqa: E402


def _one(repo, branch):
    """重算单条记录的 meta 字段。返回 (结果, 状态)。"""
    files, total_py, miss = R.cache_files(repo, branch)
    if files is None:
        return None, "py 太少(缓存缺)"
    # ★★ 走与 analyze_files() **完全同一条代码路径**：
    #   先设 _ALL_MODULE_SRC（否则第 7 种写法失效 → 会算出更多命中，
    #   变成假阴性方向的错），再逐文件调 analyze()，最后用同样的方式合并。
    #   ★ 我第一版想自己造 agg 结构，结果发现 empty_cells 是函数内部的
    #     —— 抄一份结构出来就是第二份实现，改判据时会漏改 → 数字对不上。
    #   复用一个入口，是这里唯一靠得住的做法。
    astc._ALL_MODULE_SRC = "\n".join(
        t for p, t in sorted(files.items()) if p.endswith(".py"))
    agg = {}
    failed = []
    for p, t in sorted(files.items()):
        if not p.endswith(".py"):
            continue
        res, err = astc.analyze(t, p)
        if err:
            failed.append({"file": p, "error": err})
            continue
        for k, v in res.items():
            agg.setdefault(k, {"label": v["label"], "hits": [],
                               "n_hits": 0, "hit_files": []})
            agg[k]["hits"].extend(v["hits"])
            agg[k]["n_hits"] += v["n_hits"]
            agg[k]["hit_files"] = sorted(
                set(agg[k]["hit_files"] + v["hit_files"]))
    astc._ALL_MODULE_SRC = ""
    return {"agg": agg, "total_py": total_py, "miss": miss,
            "pf": len(failed)}, "ok"


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    outpath = None
    for a in argv[1:]:
        if a.startswith("--out"):
            outpath = a.split("=", 1)[1] if "=" in a else None
    if not args:
        print(__doc__)
        return 1

    EV_CAP = 2000
    for path in args:
        if not os.path.exists(path):
            print("! 找不到文件: %s" % path)
            continue
        recs = []
        for line in io.open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                pass
        if not recs:
            print("! %s 里没有可读记录" % path)
            continue

        # ★ 判据版本一致性：缓存不在时不能补算（会拿新判据算旧项目，造出假变化）
        cur_ver = R._criteria_hash()
        new = []
        n_ok = 0
        for r in recs:
            repo = r.get("repo")
            ver = r.get("criteria_ver") or ""
            if ver and ver != cur_ver:
                new.append(r)
                print("  跳过 %-44s 记录版本 %s≠ 当前 %s"
                      % (repo[:44], ver, cur_ver))
                continue
            res, why = _one(repo, r.get("branch") or "main")
            if res is None:
                new.append(r)
                print("  跳过 %-44s %s" % (repo[:44], why))
                continue
            agg = res["agg"]
            old_n = (r.get("cells") or {}).get("inconsistent_auth", {}).get("n")
            new_n = agg["inconsistent_auth"]["n_hits"]
            r["kind_hist"] = R._kind_hist(agg)
            r["files_top"] = R._files_top(agg)
            r["evidence_n"] = {k: v["n_hits"] for k, v in agg.items()
                               if v["n_hits"]}
            r["evidence_capped"] = {k: v["n_hits"] > EV_CAP for k, v in agg.items()
                                    if v["n_hits"]}
            r["evidence"] = {k: v["hits"][:EV_CAP] for k, v in agg.items()
                             if v["n_hits"]}
            mark = "" if old_n == new_n else "★★ 数字变了 %s->%s" % (old_n, new_n)
            print("  %-44s inc %-5s(原 %-5s) %s"
                  % (repo[:44], new_n, old_n, mark))
            if old_n != new_n:
                # ★ 这是补算最该警惕的事：同版本判据、同项目，重算不该改数字。
                #   变了说明有**别的因素**在动（缓存不完整 / 上游变了 / 判据非确定性）。
                #   不标出来就会被我当成「判据修好了」——10-05 早上刚栽过这个。
                r["_backfill_mismatch"] = {"old": old_n, "new": new_n,
                                          "ver": cur_ver}
            new.append(r)
            n_ok += 1

        dst = outpath or path
        tmp = dst + ".tmp"
        with io.open(tmp, "w", encoding="utf-8") as f:
            for r in new:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        if os.path.exists(dst):
            os.replace(tmp, dst)      # ★ 原子替换：中途被杀不毁原文件
        else:
            os.rename(tmp, dst)
        print("→ 写回 %s（补算 %d/%d 条）\n" % (dst, n_ok, len(recs)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
