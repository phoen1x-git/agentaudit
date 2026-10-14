# -*- coding: utf-8 -*-
"""★ 量「PEP 695 类型别名没被认出来」到底影响多少端点。

背景：`_collect_auth_aliases` 的正则不认 `type X = Annotated[...Depends(...)]`
（PEP 695，Python 3.12 起官方写法）。别名收不到 → 用该别名的端点
全部被判成「无鉴权」→ 假阳性。

★★★ 这个脚本只做一件事：**同时按「现状正则」和「修好后的正则」跑两遍**，
统计有多少端点的 has_dep 会翻转。翻转数 = 这个缺陷的规模。

不修改 ast_criteria.py —— 先量清再决定改不改。
"""
import ast
import io
import json
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
from is_test_path import is_test_path  # noqa: E402

CD = os.path.join(HERE, "..", "data", "target_pool", "_src_cache")

# 现状正则（从 ast_criteria.py抄的，必须与线上一致）
_OLD = re.compile(
    r"^[ \t]*([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
    r"(?:Annotated\s*\[[^\]]{0,300}?Depends\s*\(|\s*Depends\s*\()",
    re.M)
# 修好后：加 `type ` 前缀 + 允许多行 Annotated
_NEW = re.compile(
    r"^[ \t]*(?:type\s+)?([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
    r"(?:Annotated\s*\[[^\]]{0,300}?Depends\s*\(|\s*Depends\s*\()",
    re.M)


def collect(src, rx):
    return set(m.group(1) for m in rx.finditer(src))


def endpoints(tree, route_from_dec):
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        rp = None
        for d in n.decorator_list:
            _m, p = route_from_dec(d)
            if p is not None:
                rp = p
                break
        if rp is None:
                continue
        try:
            sig = ast.unparse(ast.arguments(
                posonlyargs=n.args.posonlyargs, args=n.args.args,
                vararg=n.args.vararg, kwonlyargs=n.args.kwonlyargs,
                kw_defaults=n.args.kw_defaults, kwarg=n.args.kwarg,
                defaults=n.args.defaults))
        except Exception:
            continue
        yield n, rp, sig


def load_repo(repo, branch="main"):
    """★ 走 recheck.cache_files —— 复用它已固化的加载口径，别自己造。

    ★★ 为什么不能从缓存文件名反推路径：
      缓存名是 `f__<repo把/ 换成_>__<path把/ 换成_>.py.txt`，
      `/` 和 `_` 都被压成同一个字符 → **路径不可逆还原**。
      我第一版就是自己解的，结果 0 个文件、0 个端点，
      差点得出"这个缺陷没影响"的结论。
    """
    import recheck
    files, total_py, miss = recheck.cache_files(repo, branch)
    if not files:
        return None, total_py, len(miss)
    return files, total_py, len(miss)


def main():
    repos = sys.argv[1:] or ["ascending-llc/jarvis-registry"]
    for repo in repos:
        files, total_py, n_miss = load_repo(repo)
        if not files:
            print("!! %s 加载失败（tree 里py=%s）" % (repo, total_py))
            continue
        # 只拼生产文件（与analyze_files 的口径一致）
        prod = {p: t for p, t in sorted(files.items())
                if p.endswith(".py") and not is_test_path(p)}
        all_src = "\n".join(prod.values())
        old_al = collect(all_src, _OLD)
        new_al = collect(all_src, _NEW)
        only_new = sorted(new_al - old_al)

        flip = []
        n_ep = 0
        for p, t in prod.items():
            try:
                tree = ast.parse(t)
            except Exception:
                continue
            for n, rp, sig in endpoints(tree, A._route_from_decorator):
                n_ep += 1
                if "Depends" in sig:
                    continue          # 本来就认出来了，不算翻转
                if _is_exempt(rp):
                    continue
                hit_o = any(re.search(r"\b%s\b" % re.escape(a), sig)
                            for a in old_al)
                hit_n = any(re.search(r"\b%s\b" % re.escape(a), sig)
                            for a in new_al)
                if hit_o != hit_n:
                    flip.append((p, n.lineno, rp,
                                 sorted(set(re.findall(
                                     r"\b(?:type\s+)?[A-Z]\w*\b", sig)))))
        print("=" * 78)
        print("%s  (%d 生产文件 / %d 端点)" % (repo, len(prod), n_ep))
        print("  别名 现状=%d  修好后=%d  ★新增=%s"
              % (len(old_al), len(new_al), only_new or "(无)"))
        print("  ★ 判据结论会翻转的端点 = %d" % len(flip))
        for p, ln, rp, names in flip[:14]:
            print("      %s:%d%s  %s" % (p, ln, rp, names[:6]))
        if len(flip) > 14:
            print("      ... 还有 %d 个" % (len(flip) - 14))


def _is_exempt(path):
    return bool(A._is_exempt_path(path))


if __name__ == "__main__":
    main()
