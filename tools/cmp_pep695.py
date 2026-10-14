# -*- coding: utf-8 -*-
"""★★ 决定性实验：把 PEP 695 修好后重跑 inconsistent_auth，看集合差。

规则和 `cmp_criteria.py` 一样（**只跑一遍 AST，按口径分流**），
但这里分流的不是「文件」，而是「别名正则的版本」。

★ 判据（和测试文件那次同一个）：
  - 数字降 → 只说明少报了，**分不清修对了还是修过头**
  - ★ **「修好后多出来的 = 0」**才证明没吃掉任何该算的
  - 出现反向 → 新引入了不一致，是更严重的 bug
"""
import ast
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402

# 现状正则（与 ast_criteria._collect_auth_aliases 保持一致）
_OLD = re.compile(
    r"^[ \t]*([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
    r"(?:Annotated\s*\[[^\]]{0,300}?Depends\s*\(|\s*Depends\s*\()",
    re.M)


def routes_of(tree):
    """★ 复制判据里那段「找路由」逻辑 —— 不能自己简化，
    否则测的就不是线上那套了。"""
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        rp = None
        for d in n.decorator_list:
            _m, p = A._route_from_decorator(d)
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
        out.append((n, rp, sig))
    return out


def key_of(path, ln):
    return "%s:%d" % (path, ln)


def run(repo, branch="main"):
    files, _t, _m = recheck.cache_files(repo, branch)
    if not files:
        print("!! %s 加载失败" % repo)
        return
    prod = {p: t for p, t in sorted(files.items())
            if p.endswith(".py") and not is_test_path(p)}
    all_src = "\n".join(prod.values())

    variants = {
        "现状(不认 type X)": A._collect_auth_aliases(all_src),
        "修好(认 type X)": set(m.group(1) for m in _OLD.finditer(
            all_src)) | A._collect_auth_aliases(all_src),
    }
    # ★ 修好后的正则要真的能收 type X，直接替换模块内的收集器
    new_rx = re.compile(
        r"^[ \t]*(?:type\s+)?([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
        r"(?:Annotated\s*\[[^\]]{0,300}?Depends\s*\(|\s*Depends\s*\()",
        re.M)
    variants["修好(认 type X)"] = set(m.group(1)
                                      for m in new_rx.finditer(all_src))

    # 每文件算一次「哪些路由在同文件内不一致」
    per_file = {}
    for p, t in prod.items():
        try:
            tree = ast.parse(t)
        except Exception:
            continue
        rs = routes_of(tree)
        if not rs:
            continue
        per_file[p] = rs

    res = {}
    for name, aliases in variants.items():
        hits = set()
        for p, rs in per_file.items():
            flags = []
            for n, rp, sig in rs:
                dep = "Depends" in sig
                if not dep:
                    dep = any(re.search(r"\b%s\b" % re.escape(a), sig)
                              for a in aliases)
                if not dep:
                    try:
                        body = ast.unparse(n)
                        if A._has_auth_wordroot_call(body):
                            dep = True
                        elif A.AUTH_MIDDLEWARE.search(body) \
                                and A.AUTH_DENY.search(body):
                            dep = True
                        elif A._WRAPPER_CALL.search(body):
                            dep = A._wrapper_is_auth(all_src, body)
                    except Exception:
                        pass
                flags.append(dep)
            withd = [i for i, f in enumerate(flags) if f]
            without = [i for i, f in enumerate(flags) if not f]
            if not withd or not without:
                continue
            for i in without:
                n, rp, _sig = rs[i]
                if A._is_exempt_path(rp):
                    continue
                deco = ""
                for d in n.decorator_list:
                    try:
                        deco += ast.unparse(d) + " "
                    except Exception:
                        pass
                if A.AUTH_HINT.search(deco) or A.AUTH_EXEMPT_HINT.search(deco):
                    continue
                hits.add(key_of(p, n.lineno))
        res[name] = hits

    names = list(res)
    print("=" * 78)
    print("%s  (生产文件 %d)" % (repo, len(prod)))
    for nm in names:
        print("  %-20s inconsistent_auth = %d" % (nm, len(res[nm])))
    a, b = res[names[0]], res[names[1]]
    only_old = sorted(a - b)
    only_new = sorted(b - a)
    print()
    print("  ★ 集合差（关键）")
    print("      仅「现状」有= %d   仅「修好」有= %d" % (len(only_old),
                                                len(only_new)))
    for k in only_old[:12]:
        print("      - 消失: %s" % k)
    for k in only_new[:12]:
        print("      ★ 新增: %s" % k)
    if not only_new:
        print("      → 纯单向：修好只吃掉了误报，没吃掉任何「应该算的」")
    else:
        print("      → ★★ 出现反向！新引入了不一致，必须查")


if __name__ == "__main__":
    for r in (sys.argv[1:] or ["ascending-llc/jarvis-registry"]):
        run(r)
