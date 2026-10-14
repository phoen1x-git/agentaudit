"""建 TaintP2X 标准评估集（ICSE 2026）—— 用它当"公认的尺子"（`docs/170` 第 1 步）。

数据来源：`_targets/taintp2x/dataset_full.7z`（78.87MB，8 路分片下的）
  · `dataset/real world/ds_source/simple_vulnerability_info.txt`   → 522 条标注 `仓库·issue·True/False`
  · `dataset/real world/ds_source/vulnerability_statistics.json`   → 每条带 reason / triggering_conditions / vulnerability_types
  · `dataset/real world/ds_source/<repo>/<issue>/file_paths_and_lines.json` → ★ `[{file_path,line_number,function_name}]`

★ 为什么它比我们自己的 5 条真值强（`docs/170`）：
  · **210 条正例**（召回分母，比 5 条大 42 倍）
  · **312 条负例**（★ 我们以前完全没有 → 精确率也算不了）
  · **每条有 file/line/function** → 可直接对定位
  · ★ 论文数字现成：**TaintP2X 77.1% / LLMSmith 17/35 / AgentFuzz 20%** → 能直接并列

★ 用法：
    python tools/build_taintp2x_bench.py
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAINT = os.path.abspath(os.path.join(ROOT, "..", "_targets", "taintp2x"))
DS = os.path.join(TAINT, "gt", "dataset", "real world", "ds_source")
DS_ALL = os.path.join(TAINT, "gt_all", "dataset", "real world", "ds_source")
OUT = os.path.join(ROOT, "data", "target_pool", "taintp2x_benchmark.json")


def load_labels() -> list[dict]:
    p = os.path.join(DS, "simple_vulnerability_info.txt")
    rows = []
    for ln in open(p, encoding="utf-8", errors="replace").read().splitlines()[1:]:
        if not ln.strip():
            continue
        parts = ln.split("\t")
        if len(parts) >= 3:
            rows.append({"repo": parts[0].strip(), "issue": parts[1].strip(),
                         "is_vuln": parts[2].strip().lower() == "true"})
    return rows


def load_stats() -> dict:
    p = os.path.join(DS, "vulnerability_statistics.json")
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}


def load_locus(repo: str, issue: str) -> list[dict]:
    for base in (DS_ALL, DS):
        p = os.path.join(base, repo, issue, "file_paths_and_lines.json")
        if os.path.exists(p):
            try:
                d = json.load(open(p, encoding="utf-8"))
                return d if isinstance(d, list) else []
            except Exception:
                return []
    return []


def main():
    labels = load_labels()
    stats = load_stats()
    print(f"标注 {len(labels)} 条（True={sum(1 for x in labels if x['is_vuln'])} / "
          f"False={sum(1 for x in labels if not x['is_vuln'])}）")

    # 把 stats 的 reason / types 挂上去
    reason_idx: dict[tuple, dict] = {}
    for repo, v in (stats or {}).items():
        for it in (v.get("issues") or []):
            reason_idx[(repo, str(it.get("issue_number")))] = it

    pos, neg, no_locus = [], [], 0
    for r in labels:
        rec = {
            "repo": r["repo"],
            "issue": r["issue"],
            "is_vuln": r["is_vuln"],
            "locus": load_locus(r["repo"], r["issue"]),
        }
        st = reason_idx.get((r["repo"], r["issue"]))
        if st:
            rec["reason"] = st.get("reason", "")
            rec["triggering_conditions"] = st.get("triggering_conditions", "")
            rec["vulnerability_types"] = st.get("vulnerability_types", [])
        if not rec["locus"]:
            no_locus += 1
        (pos if r["is_vuln"] else neg).append(rec)

    with_loc = sum(1 for x in pos + neg if x["locus"])
    out = {
        "_meta": {
            "source": "TaintP2X (ICSE 2026), repo security-pride/TaintP2X, dataset.7z",
            "paper_numbers": {"TaintP2X": "27/35 = 77.1%(在它自己的 35 条公告子集上)",
                              "LLMSmith": "17/35", "AgentFuzz": "7/35 = 20%"},
            "note": "★ 本表 522 条是作者的完整标注；论文那个 35 条是其中'真实公告'子集。",
            "counts": {"total": len(labels), "positive": len(pos), "negative": len(neg),
                       "with_locus": with_loc, "without_locus": no_locus},
            "usage": "召回 = 命中 positive 数 / len(positive)；精确 = 命中的里 is_vuln=True 的比例",
        },
        "positive": pos,
        "negative": neg,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    print(f"★ positive {len(pos)} / negative {len(neg)}")
    print(f"★ 有定位（file/line）的：{with_loc} 条；无定位：{no_locus} 条")
    print(f"★ 带 reason 的：{sum(1 for x in pos+neg if x.get('reason'))} 条")
    print(f"JSON: {OUT}")
    # 抽一条看
    ex = next((x for x in pos if x["locus"]), None)
    if ex:
        print("\n样本（positive）:", ex["repo"], "#", ex["issue"])
        print("  locus:", json.dumps(ex["locus"][:2], ensure_ascii=False))
        print("  types:", ex.get("vulnerability_types"))
        print("  reason:", (ex.get("reason") or "")[:120])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
