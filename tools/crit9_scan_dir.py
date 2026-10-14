"""Run criterion-9 (strong/weak form coexistence) over a LOCAL source tree.

The original tools/criterion9_duality.py is wired to an old corpus cache; this
adapter reuses its scanner (scan_file / DUALITY_PAIRS) on a local directory so we
can test it on freshly downloaded targets.

    python tools/crit9_scan_dir.py ../_targets/a1src/can4hou6joeng4__boss-agent-cli
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import criterion9_duality as C9  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    total = 0
    for target in sys.argv[1:]:
        root = Path(target)
        if not root.exists():
            print(f"  [skip] {target} 不存在")
            continue
        hits = []
        nfiles = 0
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.endswith(".py"):
                    continue
                p = Path(dirpath) / fn
                rel = p.relative_to(root).as_posix()
                if C9.TEST_PATH.search(rel) or C9.TEST_NAME.search(fn):
                    continue
                try:
                    src = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                nfiles += 1
                for h in C9.scan_file(rel, src):
                    h["file"] = rel
                    hits.append(h)
        total += len(hits)
        print(f"\n===== {root.name}  扫了 {nfiles} 个 .py，命中 {len(hits)} 处 =====")
        for h in hits:
            print(f"  [{h.get('cat')}] {h.get('file')}::{h.get('func')}")
            print(f"      ★ 弱: {str(h.get('weak_code', [''])[0])[:100]}")
            print(f"      √ 强: {str(h.get('strong_code', [''])[0])[:100]}")
    print(f"\n== 合计 {total} 处 ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
