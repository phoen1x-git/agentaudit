# -*- coding: utf-8 -*-
"""诊断：反向档为什么没认出来（`/a` 调了真鉴权函数 `_uid(request)`）。"""
import ast
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_criteria as A  # noqa: E402

SRC = '''
from fastapi import FastAPI, HTTPException
app = FastAPI()

def _uid(request):
    uid = getattr(request.state, "user_id", None)
    if not uid:
        raise HTTPException(status_code=401, detail="need login")
    return str(uid)

@app.get("/a")
async def a(request):
    uid = _uid(request)
    return {"uid": uid}
'''

tree = ast.parse(SRC)
target = None
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
            and n.name == "a":
        target = n
        break
body = ast.unparse(target)
print("端点 a 的 unparse:")
print("   ", body.replace("\n", "\n    "))
print()
print("_wrapper_names(self_name='a') =", A._wrapper_names(body, self_name="a"))
print("_wrapper_is_auth              =",
      A._wrapper_is_auth(SRC, body, self_name="a"))
print()
print("=== _WRAPPER_CALL 在整个 SRC 上切到什么 ===")
for m in A._WRAPPER_CALL.finditer(SRC):
    print("   %-16s | %s" % (repr(m.group(1)), repr(m.group(2)[:45])))
print()
print("=== _wrapper_is_auth 里的 defs 切到了哪些函数 ===")
import re
for m in re.finditer(
        r"^[ \t]*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)[^:]*:"
        r"(.*?)(?=^[ \t]*(?:async\s+)?def\s+\w+\s*\(|"
        r"^[ \t]*@|^class\s|\Z)", SRC, re.M | re.S):
    print("   %s" % m.group(1))
