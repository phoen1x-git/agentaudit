# -*- coding: utf-8 -*-
"""本轮改动（记录层+ 跨文件别名接入）在 29 个项目上的决定性实验。

判定标准：
  · unauth_endpoint **只应减少或不变**（跨文件别名把有鉴权的认出来了）
  · 若某项目反而变多→ 说明别名机制误伤了真阳性，必须逐条看
"""
import io, os, sys, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A
import recheck
from is_test_path import is_test_path

POOL = os.path.join(HERE, "..", "data", "target_pool")

def targets():
    import glob
    out = []
    for f in sorted(glob.glob(os.path.join(POOL, "rc_v5_*.txt"))):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line and line != "-" and "/" in line:
                out.append(line)
    return sorted(set(out))

res_all = {}
for t in targets():
    repo, _, br = t.partition("#"); br = br or "main"
    try:
        files, n, miss = recheck.cache_files(repo, br)
    except Exception:
        continue
    if not files:
        print("%-46s 无缓存" % repo); continue
    r, f = A.analyze_files(files, skip_tests=True)
    res_all[repo] = {
        "ua": r["unauth_endpoint"]["n_hits"],
        "ia": r["inconsistent_auth"]["n_hits"],
        "meta": dict(A.LAST_RUN_META),
    }
    print("%-46s unauth=%-5d inconsistent=%-5d (py=%d, 排测试 %d)"
          % (repo, res_all[repo]["ua"], res_all[repo]["ia"],
             res_all[repo]["meta"]["total_py"],
             res_all[repo]["meta"]["skipped_test_files"]))

json.dump(res_all, open(os.path.join(POOL, "final_v6.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=1)
print()
print("=" * 74)
print("判据版本 %s" % A.__dict__.get("VERSION", "(无)"))
print("结果已存 data/target_pool/final_v6.json")
