"""量化：靶用到的第三方库，有多少被 CodeQL 官方模型覆盖？

★ 为什么要这个（2026-10-13）：
  「框架中介」缺口的本质是 —— **危险动作在依赖库里，而 CodeQL 只编译靶自己的源码**。
  这种缺口的**唯一自动补偿**是 CodeQL 官方给库写的模型（`semmle/python/frameworks/*.qll`
  + MaD 的 `*.model.yml`，本机 **111 个库 / 85 个 .qll**）。
  ⇒ 覆盖率 = 「跨库污点能不能自动传播」的上限。覆盖率低 = 框架中介缺口大。

口径说明（★ 别当成"漏检率"读）：
  · 「有模型」只表示 CodeQL **认识这个库**，不等于认识**我们关心的那个函数**；
  · 「无模型」也不必然漏 —— 如果靶把依赖 vendored 进了源码树，CodeQL 直接看得见实现。
  所以这是**上限估计**，不是精确的漏检数。

用法：
    python tools/coverage_codeql_models.py
    python tools/coverage_codeql_models.py --top 30
"""
from __future__ import annotations

import argparse
import ast
import glob
import os
import re
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import srcctx as SC  # noqa: E402

# CodeQL 模型里声明的库名（用 `computed from .qll` 或现成缓存）
LIBS_CACHE = "/tmp/codeql_libs.txt"
PKG_HOME = os.path.expanduser("~/.codeql/packages/codeql/python-all")
SRC_GLOB = os.path.join(ROOT, "..", "_targets", "tp2x_src", "*")

# ★ 明显的非第三方名（相对导入 / 本地模块常与这些冲突时不必纠结；这里只排掉语义噪声）
NON_LIB = {"__future__"}


def codeql_libs() -> set[str]:
    """从 CodeQL 的模型文件里抽出它认识的库名（小写归一）。"""
    out: set[str] = set()
    if os.path.exists(LIBS_CACHE):
        out |= {x.strip() for x in open(LIBS_CACHE, encoding="utf-8") if x.strip()}
    # 再直接从 .qll / .model.yml 抓一遍（缓存可能是旧的）
    for pat in (os.path.join(PKG_HOME, "*", "semmle", "python", "frameworks", "*.qll"),
                os.path.join(PKG_HOME, "*", "semmle", "python", "frameworks", "*.model.yml")):
        for f in glob.glob(pat):
            try:
                t = open(f, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in re.finditer(r'moduleImport\("([^"]+)"', t):
                out.add(m.group(1))
            for m in re.finditer(r"^\s*- \['([A-Za-z_][A-Za-z0-9_.]*)'", t, re.M):
                out.add(m.group(1).split(".")[0])
    return {x.lower() for x in out if x and x not in NON_LIB}


def imports_of(path: str) -> set[str]:
    """一个 .py 文件的顶层导入包名。"""
    try:
        tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    except (SyntaxError, OSError):
        return set()
    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                out.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            if n.level == 0 and n.module:      # 相对导入（level>0）不算第三方
                out.add(n.module.split(".")[0])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=25)
    a = ap.parse_args()

    libs = codeql_libs()
    print("★ CodeQL 官方模型覆盖的库名 %d 个" % len(libs))
    dirs = sorted(d for d in glob.glob(SRC_GLOB) if os.path.isdir(d))
    if not dirs:
        print("[FATAL] 没找到靶目录：%s" % SRC_GLOB)
        return 2

    all_missing: Counter = Counter()
    print()
    print("%-34s %7s %7s %7s  %s" % ("靶", "导入数", "有模型", "无模型", "覆盖率"))
    print("-" * 78)
    tot = cov = 0
    for d in dirs:
        used: set[str] = set()
        for dp, dns, fns in os.walk(d):
            dns[:] = [x for x in dns if x not in SC._SKIP_DIRS]
            for fn in fns:
                if fn.endswith(".py"):
                    used |= imports_of(os.path.join(dp, fn))
        if not used:
            continue
        # ★★ 排除标准库再算 —— 否则 `time`/`typing`/`datetime` 这类**与污点无关**的模块
        #    会把覆盖率稀释掉（它们本就不需要模型）。用 `sys.stdlib_module_names`（3.10+）。
        used = {u for u in used if u not in sys.stdlib_module_names}
        if not used:
            continue
        have = {u for u in used if u.lower() in libs}
        miss = used - have
        for m in miss:
            all_missing[m] += 1
        tot += len(used)
        cov += len(have)
        print("%-34s %7d %7d %7d  %5.0f%%"
              % (os.path.basename(d)[:34], len(used), len(have), len(miss),
                 100.0 * len(have) / len(used)))
    print("-" * 78)
    print("%-34s %7d %7d %7d  %5.0f%%"
          % ("合计（按 靶×库 去重后）", tot, cov, tot - cov, 100.0 * cov / max(tot, 1)))
    print()
    print("★ 未被 CodeQL 模型覆盖的库（按被几个靶用到排序，前 %d）：" % a.top)
    for k, c in all_missing.most_common(a.top):
        print("   %-30s 被 %d 个靶用到" % (k, c))
    print()
    print("★ 提醒：这是**上限估计**（模型只保证「认识这个库」，不保证「认识那个函数」）；")
    print("  vendored 依赖若在源码树里，CodeQL 直接看得见实现，不吃这个缺口。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
