"""A1 自用版入口 · 把 `_targets/pkgdb/` 里**已经建好的**版本靶汇成目标表。

    python app/make_pkg_targets.py [--out core/config/targets_pkg.yml]

★ 为什么单独有它：`prepare_pkg_targets.py` 会把"要下的"和"要建的"一起做，
  但有时只想**用现成的库**先跑一轮（下载慢，不等了）。这个脚本只扫磁盘。
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT.parent
SRC_ROOT = WS / "_targets" / "pkg"
DB_ROOT = WS / "_targets" / "pkgdb"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "core" / "config" / "targets_pkg.yml"))
    a = ap.parse_args()
    import yaml
    tgt = {"version": 1, "note": "按公告版本建的靶（app/make_pkg_targets.py 扫磁盘生成）",
           "targets": {}}
    for d in sorted(DB_ROOT.glob("*-db")):
        if not (d / "codeql-database.yml").exists():
            continue
        key = d.name[:-3]
        src = SRC_ROOT / key
        if not src.exists():
            continue
        tgt["targets"][key] = {
            "repo": "",
            "db": Path(os.path.relpath(d, ROOT)).as_posix(),
            "src": Path(os.path.relpath(src, ROOT)).as_posix(),
        }
    Path(a.out).write_text(yaml.safe_dump(tgt, allow_unicode=True, sort_keys=False),
                           encoding="utf-8")
    print(f"{len(tgt['targets'])} 个靶 → {a.out}")
    for k in tgt["targets"]:
        print("  " + k)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
