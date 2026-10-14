# -*- coding: utf-8 -*-
"""摊开某个项目 inconsistent_auth 的全部命中 + 数据源分布。

★★★ 用法上的一条纪律（10-05 被自己坑出来的）：
   **核实之前先看 files_top / kind_hist，再逐条读。**
   我漏了整夜就是因为只做后者 ——
   抽 8 条逐条判"是不是漏洞"，从没问过"数据源是不是被污染了"。
"""
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")


def main():
    path = sys.argv[1]
    only = sys.argv[2] if len(sys.argv) > 2 else "inconsistent_auth"
    rec = json.load(open(path, encoding="utf-8"))
    recs = rec if isinstance(rec, list) else [rec]
    for r in recs:
        if r.get("repo") != os.environ.get("WANT_REPO", r.get("repo")):
            pass
        print("=" * 78)
        print("repo:", r.get("repo"))
        print("判据版本:", r.get("criteria_ver"))
        print("元信息:", json.dumps(r.get("criteria_meta", {}),
                                    ensure_ascii=False))
        print()
        print("--- files_top（数据源分布，先看这个）---")
        for f in (r.get("files_top") or [])[:10]:
            print("  %-68s n=%-4d %s" % (f["file"], f["n"], f["cells"]))
        print()
        print("--- kind_hist（判定依据分布）---")
        for k, v in list((r.get("kind_hist") or {}).items())[:12]:
            print("  %-70s %d" % (k, v))
        print()
        ev = (r.get("evidence") or {}).get(only, [])
        print("--- %s 全部 %d 处（非抽样）---" % (only, len(ev)))
        for i, h in enumerate(ev, 1):
            print()
            print("  [%d] %s:%s" % (i, h.get("file"), h.get("line")))
            print("      kind: %s" % h.get("kind"))
            print("      text: %s" % (h.get("text") or "").strip()[:180])


if __name__ == "__main__":
    main()
