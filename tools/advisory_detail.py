"""取指定 OSV 公告的完整详情（给人工/代码核实用）。

    python tools/advisory_detail.py GHSA-mwxm-35fvg2 GHSA-7735-w2jp-gvg6
"""
from __future__ import annotations

import json
import sys
import urllib.request


def get(url: str) -> dict:
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(urllib.request.Request(url, headers={"User-Agent": "af-kernel"}),
                 timeout=45) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    ids = sys.argv[1:] or [
        "GHSA-5gpgvx", "GHSA-8fppw-56vw", "GHSA-w832-v3c6-m6rg",
        "GHSA-7735-w2jp-gvg6", "GHSA-mwxm-35fvg2",
    ]
    for vid in ids:
        try:
            d = get(f"https://api.osv.dev/v1/vulns/{vid}")
        except Exception as e:      # noqa: BLE001
            print(f"!! {vid}: {e}")
            continue
        print("=" * 78)
        print(f"{d.get('id')}  aliases={d.get('aliases')}")
        print(f"summary   : {d.get('summary')}")
        print(f"published : {d.get('published')}  modified: {d.get('modified')}")
        for a in d.get("affected") or []:
            pkg = (a.get("package") or {}).get("name")
            rng = []
            for r in a.get("ranges") or []:
                rng.append("/".join(f"{k}={v}" for e in r.get("events") or [] for k, v in e.items()))
            print(f"affected  : {pkg}  {rng}")
        print("--- details ---")
        print((d.get("details") or "").strip())
        refs = [x.get("url") for x in (d.get("references") or [])]
        print("--- refs ---")
        for u in refs:
            print("  " + str(u))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
