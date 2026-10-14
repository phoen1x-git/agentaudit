# -*- coding: utf-8 -*-
"""决定性实验：第 9 种写法（router 级 dependencies）修好后的集合差。

和 cmp_criteria.py / cmp_pep695.py 同一个套路：
**只跑一遍 AST，再按「认不认 router 级依赖」两种口径分流**。

★ 判定标准（不变）：
  数字降 → 只说明少报了，**分不清修对了还是修过头**
  ★ 「修好后多出来的 = 0」才证明没吃掉任何该算的
  ★ 出现反向 → 新引入了不一致，是更严重的 bug
"""
import ast
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402


def flags_for(tree, module_src, aliases, use_router_deps):
    """★ 复制判据的鉴权判定，返回 {lineno: has_dep}。逻辑必须与线上一致。"""
    guards = A._collect_router_guards(tree) if use_router_deps else {}
    out = {}
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
        dep = "Depends" in sig
        if not dep and guards:
            for d in n.decorator_list:
                rv = A._router_var_of_deco(d)
                if rv and rv in guards:
                    dep = True
                    break
        if not dep and aliases:
            for a in aliases:
                if a in sig.split():        # 粗但够：token级
                    dep = True
                    break
        if not dep:
            try:
                body = ast.unparse(n)
                if A._has_auth_wordroot_call(body):
                    dep = True
                elif A.AUTH_MIDDLEWARE.search(body) and A.AUTH_DENY.search(body):
                    dep = True
                elif A._WRAPPER_CALL.search(body):
                    dep = A._wrapper_is_auth(module_src, body)
            except Exception:
                pass
        deco = ""
        for d in n.decorator_list:
            try:
                deco += ast.unparse(d) + " "
            except Exception:
                pass
        if A.AUTH_HINT.search(deco) or A.AUTH_EXEMPT_HINT.search(deco):
            dep = True
        out[n.lineno] = (rp, dep)
    return out


def run(repo, branch="main"):
    files, _t, _m = recheck.cache_files(repo, branch)
    if not files:
        print("!! %s 加载失败" % repo)
        return
    prod = {p: t for p, t in sorted(files.items())
            if p.endswith(".py") and not is_test_path(p)}
    module_src = "\n".join(prod.values())
    aliases = A._collect_auth_aliases(module_src)

    res = {}
    for tag, use_rd in (("现状(不认 router 级)", False),
                        ("修好(认 router 级)", True)):
        hits = set()
        for p, t in prod.items():
            try:
                tree = ast.parse(t)
            except Exception:
                continue
            fl = flags_for(tree, module_src, aliases, use_rd)
            withd = [k for k, v in fl.items() if v[1]]
            without = [k for k, v in fl.items() if not v[1]]
            if not withd or not without:
                continue
            for ln in without:
                rp = fl[ln][0]
                if A._is_exempt_path(rp):
                    continue
                hits.add("%s:%d" % (p, ln))
        res[tag] = hits

    a, b = res["现状(不认 router 级)"], res["修好(认 router 级)"]
    print("=" * 78)
    print("%s (%d 生产文件)" % (repo, len(prod)))
    for k, v in res.items():
        print("  %-22s inconsistent_auth = %d" % (k, len(v)))
    only_old = sorted(a - b)
    only_new = sorted(b - a)
    print()
    print("  ★ 集合差")
    print("      仅现状有= %d   仅修好后有= %d"
          % (len(only_old), len(only_new)))
    for k in only_old[:14]:
        print("      - 消失: %s" % k)
    if len(only_old) > 14:
        print("      ... 还有 %d个" % (len(only_old) - 14))
    for k in only_new[:14]:
        print("      ★ 新增: %s" % k)
    if not only_new:
        print("      → 纯单向：修好只吃掉了误报")


if __name__ == "__main__":
    for r in (sys.argv[1:] or ["rhesis-ai/rhesis"]):
        run(r)
