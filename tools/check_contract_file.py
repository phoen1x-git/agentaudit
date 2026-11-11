# -*- coding: utf-8 -*-
"""核一份 candidates.jsonl：逐条过 schema，并把 entry_profile / sibling_entry 的分布打出来。"""
import json
import sys
from pathlib import Path

import jsonschema

PROJ = Path(__file__).resolve().parent.parent
schema = json.loads((PROJ / "schemas" / "candidates.v1.json").read_text(encoding="utf-8"))
V = jsonschema.Draft7Validator(schema)

path = Path(sys.argv[1])
rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
errs = [(r.get("file"), r.get("line"), e.message) for r in rows for e in V.iter_errors(r)]
print("条数 %d ｜ schema 错 %d" % (len(rows), len(errs)))
for f, l, m in errs[:5]:
    print("  X %s:%s %s" % (f, l, m))

print("\n--- entry.kind / sibling ---")
for r in rows:
    p = r.get("entry_profile") or {}
    s = p.get("sibling_entry") or {}
    print("%-42s %-6s entry=%-8s sibling=%-5s via=%-12s %s"
          % (r["file"][-42:], r["line"], r["entry"]["kind"], s.get("kind") or "-",
             s.get("via") or "-", (s.get("evidence") or "")[:60]))

print("\n--- profile.kind 是否都等于 entry.kind ---")
bad = [r["file"] for r in rows
       if (r.get("entry_profile") or {}).get("kind") not in (None, r["entry"]["kind"])]
print("不一致：%d" % len(bad))
