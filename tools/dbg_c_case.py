# -*- coding: utf-8 -*-
"""诊断 C 档：逐端点判定都对，但 analyze() 报 0。"""
import ast
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_criteria as A  # noqa: E402

SRC = (
    "from fastapi import FastAPI, Depends, HTTPException\n"
    "app = FastAPI()\n"
    "\n"
    "def _uid(request):\n"
    "    uid = getattr(request.state, 'user_id', None)\n"
    "    if not uid:\n"
    "        raise HTTPException(status_code=401, detail='need login')\n"
    "    return str(uid)\n"
    "\n"
    "@app.get('/a')\n"
    "async def a(request):\n"
    "    uid = _uid(request)\n"
    "    return {'uid': uid}\n"
    "\n"
    "@app.get('/b')\n"
    "async def b():\n"
    "    return {}\n"
)

lines = SRC.split("\n")
tree = ast.parse(SRC)
print("=== 装饰器 unparse 形态（判据 _find_unauth_endpoints 靠它匹配）===")
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for d in n.decorator_list:
            print("  L%-3d %r" % (n.lineno, ast.unparse(d)))
print()
print("=== _route_from_decorator 的返回 ===")
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for d in n.decorator_list:
            m, p = A._route_from_decorator(d)
            print("  L%-3d meth=%r path=%r" % (n.lineno, m, p))
print()
print("=== _find_inconsistent_auth 单跑 ===")
out = {k: {"label": k, "hits": [], "n_hits": 0, "hit_files": []}
       for k in ("inconsistent_auth",)}
A._find_inconsistent_auth(tree, lines, "r.py", out)
print("  n_hits =", out["inconsistent_auth"]["n_hits"])
for h in out["inconsistent_auth"]["hits"]:
    print("   ", h)
print()
print("=== analyze() 整体 ===")
res, _f = A.analyze(SRC, "r.py")
for k in ("inconsistent_auth", "unauth_endpoint"):
    print("  %-20s n=%d" % (k, res[k]["n_hits"]))
    for h in res[k]["hits"][:4]:
        print("      %s  %s" % (h.get("line"), (h.get("text") or "")[:50]))
