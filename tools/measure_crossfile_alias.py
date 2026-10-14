# -*- coding: utf-8 -*-
"""量：跨文件类型别名（第 10 种写法）的规模。

问题
----
`ascending-llc/jarvis-registry` 的`registry/src/registry/api/management_routes.py`
7个端点被判「无鉴权」，实际全都有鉴权 —— 鉴权写在**另一个文件**：

    # registry/src/registry/auth/dependencies.py
    type CurrentUser = Annotated[UserContextDict, Depends(get_current_user)]
    # registry/src/registry/api/management_routes.py
    async def management_list_users(..., user_context: CurrentUser = None)

★ 单文件原理上认不出这个。PEP 695 我今天修了，但那是**同一个文件里**的定义。
  这里要的是**项目级**的别名表。

★ 为什么必须先量再动手：
  别名正则会同时命中大量小写的实例变量（store / signer / oauth2_config…），
  噪声极高。当前的 `_collect_auth_aliases` 只收大驼峰，正是为了避开这些。
  跨文件版必须沿用同一标准，否则会把几百个变量名当鉴权依据。

判定标准：能减掉多少假阳性 vs 要引入什么新机制。
"""
import ast
import io
import os
import re
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402

POOL = os.path.join(HERE, "..", "data", "target_pool")

# ★ 与线上一致：大驼峰 / 前导下划线，且排除普通小写变量
ALIAS_RE = re.compile(
    r"^[ \t]*(?:type\s+)?([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
    r"(?:Annotated\s*\[[^]]{0,300}?Depends\s*\(|\s*Depends\s*\()",
    re.M)


def load_targets():
    import glob
    out = []
    for f in sorted(glob.glob(os.path.join(POOL, "rc_v5_*.txt"))):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line and line != "-" and "/" in line:
                out.append(line)
    return sorted(set(out))


def main():
    targets = load_targets()
    print("目标数：%d" % len(targets))
    print("=" * 74)
    grand_fp = grand_alias = 0
    for t in targets:
        repo, _, branch = t.partition("#")
        branch = branch or "main"
        try:
            files, n_py, miss = recheck.cache_files(repo, branch)
        except Exception:
            continue
        if not files:
            print("%-46s 无缓存" % repo)
            continue

        # ---- 1. 全项目大驼峰 Depends 别名 ----
        aliases = defaultdict(list)
        for p, src in files.items():
            if is_test_path(p):
                continue
            for m in ALIAS_RE.finditer(src):
                aliases[m.group(1)].append(p)
        if not aliases:
            continue

        # ---- 2. 当前判据报出的 unauth_endpoint ----
        res, _ = A.analyze_files(files, skip_tests=True)
        hits = res["unauth_endpoint"]["hits"]

        # ---- 3. 哪些命中所在文件用到了这些别名 ----
        fixed = []
        for h in hits:
            src = files.get(h["file"])
            if not src:
                continue
            for a in aliases:
                # 用 token 级匹配，避免 abc 命中 ab
                if re.search(r"[:\s=,(]\s*%s\s*[:=,)]" % re.escape(a), src):
                    fixed.append((h, a, aliases[a]))
                    break
        grand_fp += len(fixed)
        grand_alias += len(aliases)
        print("%-46s 别名 %-3d 个，命中里 %d 处用到别名"
              % (repo, len(aliases), len(fixed)))
        for h, a, srcs in fixed[:6]:
            print("      %s:%s %s  ← 别名 %s (定义在 %s)"
                  % (h["file"].split("/")[-1], h.get("line"),
                     h.get("route"), a, srcs[0].split("/")[-1]))
        if len(fixed) > 6:
            print("      ... 还有 %d 处" % (len(fixed) - 6))

    print("=" * 74)
    print("合计：大驼峰 Depends 别名 %d 个；命中里可被它解释的 %d 处"
          % (grand_alias, grand_fp))
    if grand_fp == 0:
        print()
        print("★ 结论：跨文件类型别名这条路**收益极低** —— "
              "它解释不了任何现有假阳性。")
        print("  不做。理由和 docs/47 里「嵌套实参假阴性」一样："
              "量出来几乎不存在，就降级为已知盲区，别动判据。")


if __name__ == "__main__":
    sys.exit(main())