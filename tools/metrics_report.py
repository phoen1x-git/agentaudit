"""算 P / R / Y 三个验收指标（`docs/166`）。**以前从没算过 —— 这是"改工具无锚"的根因。**

定义（`docs/166`）：
  · **P 精确率** = 过四关的 ÷ 判为 `vuln` 的     → 判定层的可信度（低 = 在制造噪声）
  · **R 召回率** = 外部真值命中 ÷ 外部真值总数   → 发现能力（★ 分母 <10 只报绝对数）
  · **Y 产出率** = 过四关的 ÷ 扫过的靶数         → ★★★ 最该盯的数

数据来源：
  · 分子（过四关）→ `data/target_pool/candidates_passed.json`     ← 手工维护（四关全过才写）
  · 分母 P       → `data/target_pool/judge_round*.json`            ← 判定层产出
  · 分母 R       → `data/target_pool/ground_truth_external_CURATED.json`
  · 分母 Y       → `data/target_pool/target_security_audit_*.json`（扫过的靶；或 --n-targets 手工给）

★ 用法：
    python tools/metrics_report.py
    python tools/metrics_report.py --n-targets 30
"""
from __future__ import annotations

import argparse
import glob
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, "data", "target_pool")


def _load(p: str):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-targets", type=int, default=0, help="扫过的靶数（不给则自动估）")
    a = ap.parse_args()

    # ---- 分子：过四关 ----
    passed = _load(os.path.join(D, "candidates_passed.json")) or {}
    P_pass = passed.get("passed", []) or []

    # ---- 分母 P：判为 vuln 的总数 ----
    n_vuln = 0
    n_judged = 0
    for f in glob.glob(os.path.join(D, "judge_round*.json")):
        d = _load(f) or {}
        for r in d.get("results", []):
            n_judged += 1
            if r.get("verdict") == "vuln":
                n_vuln += 1

    # ---- 分母 R：外部真值 ----
    gt = _load(os.path.join(D, "ground_truth_external_CURATED.json")) or {}
    items = gt.get("items", []) or []
    n_gt = len(items)
    n_gt_hit = sum(1 for it in items if str(it.get("our_result", "")).startswith("HIT"))

    # ---- 分母 Y：扫过的靶 ----
    # ★ 优先从**实际扫描记录**统计（out/round-*/findings.json 的 unique project）——
    #   这才是"真正扫过的靶"。--n-targets 可手工覆盖。
    n_targets = a.n_targets
    scanned: set = set()
    for f in glob.glob(os.path.join(ROOT, "out", "round-*", "findings.json")):
        d = _load(f) or {}
        for v in d.values():
            pj = v.get("project")
            if pj:
                scanned.add(pj)
    # 去掉版本变体后缀（litellm-1_82_2 → litellm），避免把同一靶的数个版本算多次
    import re as _re
    scanned = {_re.split(r"[-_]\d", str(p))[0] if _re.split(r"[-_]\d", str(p))[0] else str(p)
               for p in scanned}
    if not n_targets:
        n_targets = len(scanned)

    print("=" * 62)
    print("验收指标（docs/166）——★ 只报数，不粉饰")
    print("=" * 62)

    print(f"\n【P 精确率】 过四关 {len(P_pass)} ÷ 判为 vuln {n_vuln}")
    if n_vuln:
        print(f"    = {len(P_pass)/n_vuln*100:.1f}%   （判了 {n_judged} 条，其中 vuln {n_vuln}）")
        print(f"    → 判定层每判出 {n_vuln} 条 vuln，只有 {len(P_pass)} 条是真的")
    else:
        print("    = 无数据")

    print(f"\n【R 召回率】 外部真值命中 {n_gt_hit} ÷ 外部真值总数 {n_gt}")
    if n_gt < 10:
        print(f"    ⚠️ 分母 {n_gt} < 10 → ★ **只报绝对数，不报百分比**（既定规矩）")
        print(f"    绝对数：命中 {n_gt_hit} 条")
    else:
        print(f"    = {n_gt_hit/n_gt*100:.1f}%")

    print(f"\n【Y 产出率】 过四关 {len(P_pass)} ÷ 扫过的靶 {n_targets or '?'}")
    if n_targets:
        print(f"    Y_raw = {len(P_pass)}/{n_targets}  ≈ {len(P_pass)/n_targets*100:.1f}%")
        # ★★ 2026-10-11 用户提醒：Y 低**可能不是工具的错，是靶的错**
        #    （已被人审过 → 洞被摘完；已归档 → 报了没人修；质量差 → 本身没洞）
        #    → 所以要用「**有效靶**」当分母：活着 + 标题里从没 security 报告。
        eff: set = set()
        audit = _load(os.path.join(D, "target_security_audit.json")) or {}
        clean = {r.split("/")[-1].lower() for r, v in (audit.get("targets") or {}).items()
                 if isinstance(v, dict) and v.get("n") == 0}
        alive = set()
        try:
            al = _load(os.path.join(D, "candidate_alive_20261011.json")) or {}
            alive = {r["repo"].split("/")[-1].lower() for r in al.get("results", [])
                     if r.get("verdict") == "PASS"}
        except Exception:
            pass
        for p in scanned:
            if clean and p.lower() not in clean:
                continue
            if alive and p.lower() not in alive:
                continue
            eff.add(p)
        if eff:
            print(f"    ★ Y_eff = {len(P_pass)}/{len(eff)}  ≈ {len(P_pass)/len(eff)*100:.1f}%"
                  f"   （分母只算『有效靶』：活着 + 没被人审过）")
            print(f"       有效靶：{sorted(eff)}")
        else:
            print("    （算 Y_eff 需要 target_security_audit.json + candidate_alive_*.json）")

    print("\n" + "-" * 62)
    print("★ 改工具的判据：**任何改动后重算这三个数，Y 不升就回滚。**")
    print("★ 当前过四关的候选：")
    for c in P_pass:
        print(f"    · {c.get('project')} {c.get('file')}:{c.get('line')} ({c.get('class')})")
    if not P_pass:
        print("    （空）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
