# -*- coding: utf-8 -*-
"""定点诊断：travel_agent/app.py 里那个『1/6 有鉴权』到底是谁。"""
import ast, io, os, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_criteria as A
P = ("../data/target_pool/_src_cache/f__rhesis-ai_rhesis__agents_"
     "travel-agent_src_travel_agent_app.py.txt")
src = open(P, encoding="utf-8", errors="replace").read()
tree = ast.parse(src)
print("=== router 级 guards ===", A._collect_router_guards(tree))
print()
for n in ast.walk(tree):
    if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        continue
    rp = None
    for d in n.decorator_list:
        _m, p = A._route_from_decorator(d)
        if p is not None:
            rp = p; break
    if rp is None:
        continue
    sig = ast.unparse(ast.arguments(posonlyargs=n.args.posonlyargs,
        args=n.args.args, vararg=n.args.vararg, kwonlyargs=n.args.kwonlyargs,
        kw_defaults=n.args.kw_defaults, kwarg=n.args.kwarg,
        defaults=n.args.defaults))
    body = ast.unparse(n)
    w = bool(A._WRAPPER_CALL.search(body))
    print("L%-5d %-30s Depends=%-6s wordroot=%-6s wrapper=%s"
          % (n.lineno, rp, "Depends" in sig,
             A._has_auth_wordroot_call(body), w))
    if w:
        print("        _wrapper_is_auth ->", A._wrapper_is_auth(src, body))
