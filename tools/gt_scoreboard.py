#!/usr/bin/env python
"""外部真值记分板 —— 把 `ground_truth_external_CURATED.json` 跑成一张可复现的表。

为什么需要它：分母是**手工核定**的（`docs/149`），命中要标**层级**（探测器/判定层）
和**开关状态**。这些信息散在多个 `out/round-*/` 里，人工对账容易错（`docs/143` 踩过：
"我命中了/没命中"这句话必须 grep 原始产物才能说）。

★ 单一事实源 = `ground_truth_external_CURATED.json` 里每条 `evidence` 字段
  （指向哪个轮次 / 要哪些开关 / 期望 verdict / locus）。
  本工具只做**核对**，不改判。

用法：
    python tools/gt_scoreboard.py
    python tools/gt_scoreboard.py --json out/gt_score.json
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CURATED = os.path.join(ROOT, "data", "target_pool", "ground_truth_external_CURATED.json")


def load_findings(rel: str) -> list:
    p = os.path.join(ROOT, rel, "findings.tsv")
    if not os.path.isfile(p):
        return []
    return list(csv.DictReader(open(p, encoding="utf-8-sig"), delimiter="\t"))


def check_round(ev: dict) -> tuple[bool, str]:
    rows = load_findings(ev["round"])
    if not rows:
        return False, f"缺 findings.tsv（{ev['round']}）"
    locus = ev.get("locus") or ""
    want = ev.get("expect_verdict")
    hit = [r for r in rows if locus in r.get("file", "") and r.get("ai_verdict") == want]
    if hit:
        r = hit[0]
        return True, (f"{r['file'].split('/')[-1]}:{r['line']} "
                      f"{r['ai_verdict']} conf={r['conf']} asrc={r.get('arg_source','')}")
    near = [r for r in rows if locus in r.get("file", "")]
    if near:
        got = ", ".join(f":{r['line']}={r['ai_verdict']}" for r in near)
        return False, f"locus 在结果里但不是 {want}（{got}）"
    return False, "locus 不在结果里"


def check_regression(ev: dict) -> tuple[bool, str]:
    p = os.path.join(ROOT, ev["regression"], "summary.json")
    if not os.path.isfile(p):
        return False, f"缺 summary.json（{ev['regression']}）"
    d = json.load(open(p, encoding="utf-8"))
    n = d.get("n_hits", 0)
    locus = ev.get("locus") or ""
    covered = any(locus in h.get("file", "") for h in d.get("hits", []))
    exp = ev.get("expect_n_hits")
    ok = covered and (exp is None or n >= exp)
    return ok, (f"回退实验 n_hits={n}（期望≥{exp}）locus覆盖={covered} "
                f"[{d.get('repo')}@{d.get('fix_commit')} 的父提交]")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()

    d = json.load(open(CURATED, encoding="utf-8"))
    items = d["items"]
    now_in = [it for it in items if it.get("scope_now")]
    now_out = [it for it in items if not it.get("scope_now")]

    print("=" * 80)
    print("外部真值记分板（分母 = 手工核定，见 docs/149）")
    print("=" * 80)

    hits, results = 0, []
    for it in now_in:
        key = f"{it['repo']}#{it['number']}"
        ev = it.get("evidence") or {}
        if "regression" in ev:
            ok, why = check_regression(ev)
        elif "round" in ev:
            ok, why = check_round(ev)
        else:
            ok, why = False, "无 evidence"
        hits += 1 if ok else 0
        sw = " ".join(ev.get("switches") or []) or "（默认）"
        orig = "原始在射程" if it.get("in_pipeline_scope") else "★原始不在，本轮补了能力"
        print(f"\n[{'✔' if ok else '✗'}] {key} —— {it.get('class')}")
        print(f"    报告: {(it.get('title') or '')[:72]}")
        print(f"    开关: {sw}   ({orig})")
        print(f"    核对: {why}")
        results.append({"key": key, "class": it.get("class"), "ok": ok,
                        "switches": ev.get("switches") or [], "detail": why})

    print("\n" + "=" * 80)
    print(f"射程内命中 = {hits} / {len(now_in)}")
    if len(now_in) < 5:
        print("★ 分母 <5 → 按项目规矩**只报绝对数，不报百分比**（docs/149 规矩 1）")
    print(f"（射程外 {len(now_out)} 条不计入）")
    for it in now_out:
        print(f"    exclude: {it['repo']}#{it['number']} —— {it.get('class')}")

    if a.json:
        json.dump({"hits": hits, "denominator": len(now_in), "items": results},
                  open(os.path.join(ROOT, a.json), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print(f"\n→ {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
