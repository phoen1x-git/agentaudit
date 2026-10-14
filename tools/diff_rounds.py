#!/usr/bin/env python
"""对比两轮 run_round 的 findings.tsv（同一批靶、不同开关）。

用途：单变量 A/B —— 例如 `ch388-base`(全默认) vs `ch388-plus`(开判定开关)，
看哪个条目的 ai_verdict / arg_source / 置信度变了。

用法：
    python tools/diff_rounds.py out/round-ch388-base out/round-ch388-plus
    python tools/diff_rounds.py out/round-A out/round-B --only-changed
    python tools/diff_rounds.py out/round-A out/round-B --json out/diff.json

匹配键：用 (file, line, sink) —— 不依赖 fingerprint，因为改判据不改 fingerprint。
输出：新增 / 消失 / 结论变化 / 来源变化 四类，外加汇总计数与成本对比。
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

FIELDS = ["project", "file", "line", "sink", "depth", "guards",
          "ai_verdict", "conf", "arg_source", "by_design", "scope_exceeds",
          "guards_real", "snippet", "ai_reason"]


def _key(row: dict) -> str:
    return f"{row.get('file','')}:{row.get('line','')}:{row.get('sink','')}"


def load(round_dir: str) -> dict:
    p = os.path.join(round_dir, "findings.tsv")
    if not os.path.isfile(p):
        raise SystemExit(f"找不到 {p}")
    rows = list(csv.DictReader(open(p, encoding="utf-8-sig"), delimiter="\t"))
    return {_key(r): r for r in rows}


def meta(round_dir: str) -> dict:
    p = os.path.join(round_dir, "meta.json")
    if not os.path.isfile(p):
        return {}
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}


def cost_of(m: dict) -> str:
    for k in ("llm_cost_cny", "cost_cny", "judge_cost_cny"):
        if k in m:
            return str(m[k])
    for k in ("judge", "llm"):
        v = m.get(k)
        if isinstance(v, dict):
            for kk in ("cost_cny", "total_cost_cny"):
                if kk in v:
                    return str(v[kk])
    return "?"


def verdict_dist(rows: dict) -> dict:
    d: dict = {}
    for r in rows.values():
        d[r.get("ai_verdict", "?")] = d.get(r.get("ai_verdict", "?"), 0) + 1
    return dict(sorted(d.items(), key=lambda kv: -kv[1]))


def short(v: str, n: int = 46) -> str:
    v = (v or "").replace("\n", " ")
    return v if len(v) <= n else v[: n - 1] + "…"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir_a", help="基线轮目录（全默认）")
    ap.add_argument("dir_b", help="实验轮目录（开开关）")
    ap.add_argument("--only-changed", action="store_true", help="只打印有差异的条目")
    ap.add_argument("--json", help="把结构化 diff 写到这里")
    ap.add_argument("--show-reason", action="store_true", help="打印实验轮的新理由")
    a = ap.parse_args()

    A = load(a.dir_a)
    B = load(a.dir_b)
    only_a = [k for k in A if k not in B]
    only_b = [k for k in B if k not in A]
    common = [k for k in A if k in B]

    changed_v, changed_s, changed_c = [], [], []
    for k in common:
        ra, rb = A[k], B[k]
        if ra.get("ai_verdict") != rb.get("ai_verdict"):
            changed_v.append(k)
        if ra.get("arg_source") != rb.get("arg_source"):
            changed_s.append(k)
        try:
            ca, cb = float(ra.get("conf") or 0), float(rb.get("conf") or 0)
            if abs(ca - cb) >= 0.05:
                changed_c.append(k)
        except ValueError:
            pass

    print("=" * 78)
    print(f"A(基线) = {a.dir_a}   条数 {len(A)}   {verdict_dist(A)}")
    print(f"B(实验) = {a.dir_b}   条数 {len(B)}   {verdict_dist(B)}")
    print(f"成本 A={cost_of(meta(a.dir_a))} 元   B={cost_of(meta(a.dir_b))} 元")
    print("=" * 78)

    def dump(title: str, keys: list, side: str) -> None:
        if not keys:
            return
        print(f"\n### {title}（{len(keys)}）")
        for k in sorted(keys):
            r = B[k] if side == "b" else A[k]
            mark = ""
            if k in changed_v:
                mark = f"  结论 {A[k].get('ai_verdict')}→{B[k].get('ai_verdict')}"
            print(f"  {r.get('ai_verdict','?'):12s} conf={r.get('conf','?'):5s} "
                  f"asrc={short(r.get('arg_source'),20):20s} {short(k,60)}{mark}")
            if a.show_reason and side == "b":
                print(f"      ↳ {short(r.get('ai_reason'),180)}")

    if only_b:
        dump("B 新增（基线没有）", only_b, "b")
    if only_a:
        dump("A 独有（实验轮消失）", only_a, "a")

    print(f"\n### 结论变化 ai_verdict（{len(changed_v)}）")
    for k in sorted(changed_v):
        print(f"  {A[k].get('ai_verdict'):12s} → {B[k].get('ai_verdict'):12s} "
              f"conf {A[k].get('conf','?')}→{B[k].get('conf','?')}  {short(k,54)}")

    print(f"\n### arg_source 变化（{len(changed_s)}）")
    for k in sorted(changed_s):
        print(f"  {short(A[k].get('arg_source'),18):18s} → {short(B[k].get('arg_source'),18):18s}  {short(k,54)}")

    print(f"\n### 置信度漂移 ≥0.05（{len(changed_c)}）")
    for k in sorted(changed_c):
        print(f"  conf {A[k].get('conf','?'):5s} → {B[k].get('conf','?'):5s}  "
              f"{A[k].get('ai_verdict','?'):12s}→{B[k].get('ai_verdict','?'):12s}  {short(k,48)}")

    if a.json:
        out = {
            "a": {"dir": a.dir_a, "n": len(A), "dist": verdict_dist(A), "cost": cost_of(meta(a.dir_a))},
            "b": {"dir": a.dir_b, "n": len(B), "dist": verdict_dist(B), "cost": cost_of(meta(a.dir_b))},
            "only_b": only_b, "only_a": only_a,
            "changed_verdict": [{"key": k, "a": A[k].get("ai_verdict"), "b": B[k].get("ai_verdict"),
                                 "conf_a": A[k].get("conf"), "conf_b": B[k].get("conf"),
                                 "reason_b": B[k].get("ai_reason")} for k in sorted(changed_v)],
            "changed_arg_source": [{"key": k, "a": A[k].get("arg_source"), "b": B[k].get("arg_source")}
                                   for k in sorted(changed_s)],
            "conf_drift": [{"key": k, "a": A[k].get("conf"), "b": B[k].get("conf")} for k in sorted(changed_c)],
        }
        json.dump(out, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print(f"\n→ {a.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
