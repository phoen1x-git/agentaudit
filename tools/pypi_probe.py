"""探 PyPI 某个版本的发包体积（给"按包建靶"路线用）。

    python tools/pypi_probe.py sample-index==0.10.37 samplebi==0.3.4

★ 为什么需要：仓库 tarball 动辄几十 MB（本机 ~26 KB/s，拉不动），
  而 **sdist / wheel 通常只有几 MB** —— 想按"公告指的那个版本"评估，
  用 PyPI 发包比拉整个仓库现实得多。
"""
from __future__ import annotations

import json
import sys
import urllib.request


def get(url: str) -> dict:
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(urllib.request.Request(url, headers={"User-Agent": "af-kernel"}),
                 timeout=40) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    specs = sys.argv[1:] or ["sample-index==0.10.37"]
    for spec in specs:
        if "==" in spec:
            name, ver = spec.split("==", 1)
        else:
            name, ver = spec, None
        d = get(f"https://pypi.org/pypi/{name}/json")
        releases = d.get("releases") or {}
        if ver is None:
            ver = d["info"]["version"]
        files = releases.get(ver) or []
        print("=" * 70)
        print(f"{name}=={ver}  （可用版本 {len(releases)} 个）")
        if not files:
            print("  !! 该版本没有文件记录")
            continue
        for f in files:
            mb = (f.get("size") or 0) / 1024 / 1024
            print(f"  [{f.get('packagetype'):8}] {mb:7.2f} MB  {f.get('filename')}")
            print(f"           {f.get('url')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
