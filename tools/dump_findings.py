"""列某轮里的判定条目（默认只列 not_vuln），供"回源码抽核"用。

    python tools/dump_findings.py out/round-a1b-ctxon [--verdict not_vuln] [--limit 60]

★ 为什么不用 awk/sed：findings.tsv 里 ai_reason 含**引号包裹的换行**，
  按行切会错位（踩过：89 行 ≠ 67 条）。必须走 csv 解析。
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("round_dir")
    ap.add_argument("--verdict", default="not_vuln")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--full", action="store_true", help="打印完整 ai_reason")
    a = ap.parse_args()
    rd = Path(a.round_dir)
    rows = list(csv.DictReader(open(rd / "findings.tsv", encoding="utf-8-sig"),
                               delimiter="\t"))
    print(f"{len(rows)} 条（总）")
    sel = [r for r in rows if r.get("ai_verdict") == a.verdict]
    print(f"{len(sel)} 条 ai_verdict={a.verdict}\n")
    for i, r in enumerate(sel[: a.limit], 1):
        rsn = (r.get("ai_reason") or "").replace("\n", " ")
        if not a.full:
            rsn = rsn[:260]
        print(f"[{i:2}] {r['project']:12} {r['file']}:{r['line']:>5}  sink={r['sink']}")
        print(f"     by_design={r.get('by_design')} scope_exceeds={r.get('scope_exceeds')} "
              f"guards_real={r.get('guards_real')} arg_source={r.get('arg_source')}")
        print(f"     理由: {rsn}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
