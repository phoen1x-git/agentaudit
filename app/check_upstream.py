"""A1 自用版入口 · 上游核实（第⑤步的前半）。

    python app/check_upstream.py out/round-20261009

产出 `upstream.json`，然后重新生成报告，让"上游状态"那一节从「未查询」变成实测内容。

★ 2026-10-12：本文件不再自己读 tsv —— **改调 `core.upstream.run_round_dir()`**，
  和 `app/run_round.py` 共用同一实现（两份逻辑早晚算出不一样的数）。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import upstream as UP  # noqa: E402


def main() -> int:
    rd = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not rd or not (rd / "findings.tsv").exists():
        print("用法: python app/check_upstream.py <round-dir>")
        return 1
    only = "vuln"
    if "--all-verdicts" in sys.argv:
        only = ""
    res = UP.run_round_dir(rd, on_log=print, only_verdict=only)
    if res:
        print(f"\n== 上游核实完成 → {rd/'upstream.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
