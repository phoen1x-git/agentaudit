"""A1 自用版入口 · 从版本基准里挑出**这一轮要真扫的目标**。

    python app/select_version_targets.py [--min-mb 0.3] [--max-mb 25]

选择规则（写死在这里，便于复盘）：
  1. `in_size_budget`（发包 ≤ max-mb）
  2. 公告给了代码定位（文件名/函数名）—— 否则没法自动评测
  3. 发包 ≥ min-mb —— 更小的基本是"空壳包"（代码在别的包），扫了等于没扫
  4. **去掉老基准已经覆盖过的公告**（GHSA-6mj8 / GHSA-rrqq / GHSA-vv2h）→ 两个基准不重复计数
  5. (scan_package, scan_version) 去重

输出 `data/target_pool/version_runlist.json`（格式同 version_benchmark.json，
可直接喂给 app/prepare_pkg_targets.py）。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BM = ROOT / "data" / "target_pool" / "version_benchmark.json"
OUT = ROOT / "data" / "target_pool" / "version_runlist.json"

# 老基准（docs/103~111）已经算过的唯一漏洞 → 不再重复计入
OLD_BENCH_KEYS = {"CVE-2026-4229", "CVE-2024-5826", "CVE-2024-12366"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-mb", type=float, default=0.05,
                    help="★ 0.01MB 那档是空壳包（代码在同仓库别的包里）；0.1MB 的是真的小包")
    ap.add_argument("--max-mb", type=float, default=25.0)
    a = ap.parse_args()
    bm = json.load(open(BM, encoding="utf-8"))
    sel, seen = [], set()
    for it in bm["items"]:
        if not it["in_size_budget"] or it["size_mb"] > a.max_mb:
            continue
        if not (it.get("target_file") or it.get("target_function")):
            continue
        if it["size_mb"] < a.min_mb:
            continue
        if it["key"] in OLD_BENCH_KEYS:
            continue
        k = (it["scan_package"], str(it["scan_version"]))
        if k in seen:
            continue
        seen.add(k)
        sel.append(it)
    doc = {"_meta": {"note": "本轮要真扫的版本靶（app/select_version_targets.py）",
                     "n": len(sel), "n_targets": len(seen),
                     "min_mb": a.min_mb, "max_mb": a.max_mb},
           "items": sel}
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(sel)} 条基准条目 / {len(seen)} 个靶")
    for it in sel:
        print(f"  {it['scan_package']:22}=={it['scan_version']:<12} {it['size_mb']:6.2f}MB "
              f"[{it['precision']:6}] {it['target_function'] or '-'}() @ {it['target_file']}  "
              f"({it['key']})")
    print(f"\n→ {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
