"""Check the upstream status of the candidates in a round.

    python app/check_upstream.py out/round-my-round

Writes `upstream.json`, after which the report's "Upstream status" section can be
regenerated from "not checked" into what was actually observed.

This shares one implementation with `app/run_round.py` (core.upstream.run_round_dir);
two copies of the same lookup would eventually disagree.
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
