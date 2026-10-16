# -*- coding: utf-8 -*-
"""对比两轮 findings 的判定分布（单变量 A/B 用）。

    python tools/compare_rounds.py out/round-batch3 out/round-batch3-oparg

★ 为什么要它：改动规则后必须同时看「稳定性」和「刻度」。
  本工具给：① ai_verdict 分布差 ② 逐条结论变化（谁翻了、翻成什么）
  ③ 关键主观字段（by_design / scope_exceeds / guards_real / arg_source）的变动数。
★ 用来比的两轮**必须同目标、同静态前端**，否则比较无意义（脚本会检查目标集合）。
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(rd: Path) -> dict:
    p = rd / "findings.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    rows = d if isinstance(d, list) else list(d.values())
    return {r.get("fingerprint"): r for r in rows}


def dist(rows: dict, field: str) -> Counter:
    return Counter(str(r.get(field)) for r in rows.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--field", default="ai_verdict")
    args = ap.parse_args()
    A = load((ROOT / args.a) if not Path(args.a).is_absolute() else Path(args.a))
    B = load((ROOT / args.b) if not Path(args.b).is_absolute() else Path(args.b))

    ka, kb = set(A), set(B)
    print(f"A = {args.a}  ({len(A)} 条)")
    print(f"B = {args.b}  ({len(B)} 条)")
    if ka != kb:
        print(f"  ★ 警告：两轮指纹集合不同（A 独有 {len(ka-kb)}，B 独有 {len(kb-ka)}）"
              "—— 非同目标/同前端时，下面的对比不可靠")
    common = ka & kb

    for f in ("ai_verdict", "by_design", "scope_exceeds", "guards_real", "arg_source"):
        da, db = dist(A, f), dist(B, f)
        if da == db:
            print(f"\n[{f}] 无变化：{dict(da)}")
            continue
        print(f"\n[{f}] A: {dict(da)}")
        print(f"{'':>{len(f)+3}}B: {dict(db)}")

    print("\n=== 逐条结论变化（同指纹） ===")
    flips = [(k, A[k].get("ai_verdict"), B[k].get("ai_verdict"))
             for k in common if A[k].get("ai_verdict") != B[k].get("ai_verdict")]
    print(f"结论翻转 {len(flips)}/{len(common)} 条")
    for k, va, vb in flips[:40]:
        r = B[k]
        print(f"  {va:11} → {vb:11}  {r.get('project')}/{str(r.get('file')).split('/')[-1]}:{r.get('line')}")
        print(f"      A: {str(A[k].get('ai_reason'))[:90]}")
        print(f"      B: {str(r.get('ai_reason'))[:90]}")
    out = ROOT / "data" / "target_pool" / "_ab_compare.json"
    out.write_text(json.dumps({"a": args.a, "b": args.b, "n_a": len(A), "n_b": len(B),
                               "n_common": len(common), "flips": [
                                   {"fp": k, "a": va, "b": vb} for k, va, vb in flips],
                               "dist_a": {f: dict(dist(A, f)) for f in
                                          ("ai_verdict", "by_design", "scope_exceeds",
                                           "guards_real", "arg_source")},
                               "dist_b": {f: dict(dist(B, f)) for f in
                                          ("ai_verdict", "by_design", "scope_exceeds",
                                           "guards_real", "arg_source")}},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n→ {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
