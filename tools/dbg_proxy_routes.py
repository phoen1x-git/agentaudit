# -*- coding: utf-8 -*-
"""诊断 proxy_routes.py 里 6 个端点各自的鉴权判定路径。

用途：定位 `clear_session_endpoint:527` 为什么被判成"无鉴权"，
而同文件另外 5 个用同样`CurrentUser` 的端点却被认出来了。
"""
import ast
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_criteria as A  # noqa: E402

P = ("../data/target_pool/_src_cache/"
     "f__ascending-llc_jarvis-registry__registry_src_registry_api_"
     "proxy_routes.py.txt")
src = open(P, encoding="utf-8", errors="replace").read()
tree = ast.parse(src)

print("=== _collect_auth_aliases 收了多少别名 ===")
al = A._collect_auth_aliases(src)
print("  total=%d  含 CurrentUser? %s" % (len(al), "CurrentUser" in al))
print("  前 20:", sorted(al)[:20])
print()

print("=== 6 个端点逐个诊断 ===")
for n in ast.walk(tree):
    if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        continue
    rp = None
    for d in n.decorator_list:
        _meth, p = A._route_from_decorator(d)
        if p is not None:
            rp = p
            break
    if rp is None:
        continue
    sig = ast.unparse(ast.arguments(
        posonlyargs=n.args.posonlyargs, args=n.args.args,
        vararg=n.args.vararg, kwonlyargs=n.args.kwonlyargs,
        kw_defaults=n.args.kw_defaults, kwarg=n.args.kwarg,
        defaults=n.args.defaults))
    dep = "Depends" in sig
    alias_hit = None
    if not dep:
        for a in al:
            if re.search(r"\b%s\b" % re.escape(a), sig):
                alias_hit = a
                dep = True
                break
    body = ast.unparse(n)
    wr = bool(A._WRAPPER_CALL.search(body))
    print("L%-5d %-44s Depends=%-6s alias=%-16s wrapper=%s"
          % (n.lineno, rp, dep, alias_hit, wr))
    if not dep and wr:
        print("        _wrapper_is_auth ->", A._wrapper_is_auth(src, body))
