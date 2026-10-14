# -*- coding: utf-8 -*-
"""自测：`_wrapper_names` 把自己和异常构造误当鉴权调用（10-05 08:4x）。

★★ 完整案例（rhesis-ai/rhesis agents/travel-agent/src/travel_agent/app.py:248）：

    @app.post("/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest):                      ← 缺陷A：def 行被当成调用
        if not _startup_validated:
            raise HTTPException(503, "Travel Agent not initialised")
        try:
            return await chat_endpoint_traced(
                message=request.message,                        ← 缺陷B：detail 里有 request
                conversation_id=request.conversation_id)
        except Exception as exc:
            if "API_KEY" in str(exc):                          ← READ_ID 命中
                raise HTTPException(503, detail=str(exc))       ← DENY 命中
            ...
            raise HTTPException(500, "Error processing request")  ← ★ "request" 一词

    → `_wrapper_names` 收到 {'chat', 'chat_endpoint_traced', 'HTTPException'}
    → 追进 `chat`（**就是它自己**）→ READ_ID + DENY 都命中
    → ★★ 这个完全没鉴权的端点被判成"有鉴权"
    → 成了「同文件内 1/6 有鉴权」那个 **1** → 1 引爆 5 处假阳性

★ 这个 bug 的隐蔽性：它让判据**看起来在工作**
（确实找到了一个"鉴权函数"）， 但找到的是端点自己。
"""
import ast
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_criteria as A  # noqa: E402

BAD = 0


def chk(desc, got, want):
    global BAD
    ok = (got == want)
    if not ok:
        BAD += 1
    print("  %s %-54s 期望=%-22s 实际=%s"
          % ("OK  " if ok else "FAIL", desc, want, got))


print("=== A. _wrapper_names 排除自身与异常构造 ===")
CASES = [
    # (说明, 端点 unparse 结果, self_name, 期望 names)
    ("★缺陷A: def 行自己带 request 形参",
     "async def chat(request: ChatRequest):\n    pass",
     "chat", set()),
    ("★缺陷B: HTTPException 的 detail 含 'request'",
     "async def chat(request):\n"
     "    raise HTTPException(500, 'Error processing request')",
     "chat", set()),
    ("真包装函数仍要认出来（防「修过头」）",
     "async def f(request):\n    uid = _uid(request)\n    return uid",
     "f", {"_uid"}),
    ("★ 端点名字与包装函数同名之外的正常情形",
     "async def list_x(request):\n    return _identity(request)",
     "list_x", {"_identity"}),
    ("带点号的调用fastapi.HTTPException",
     "async def f(request):\n"
     "    raise fastapi.HTTPException(500, 'bad request')",
     "f", set()),
    ("JSONResponse 构造不算",
     "async def f(request):\n"
     "    return JSONResponse(content={'q': request})",
     "f", set()),
    ("★ 两个真实包装函数都要保留",
     "async def f(request):\n"
     "    a = _uid(request)\n    b = _tenant(request)\n    return a, b",
     "f", {"_uid", "_tenant"}),
    # ★ self_name=None（调用方没传）时，def 行那个假调用**仍会混进来** ——
    #   这正是我要的对照：证明 self_name 那一行是**真的在起作用**，
    #   不是「反正结果也一样」。真包装函数 _uid 两个版本都必须认出来。
    ("★ self_name=None 时真包装函数仍认得出（对照组）",
     "async def f(request):\n    return _uid(request)",
     None, {"f", "_uid"}),
]
for desc, src, sn, want in CASES:
    body = ast.unparse(ast.parse(src).body[0])
    got = A._wrapper_names(body, self_name=sn)
    chk(desc, got, want)

print()
print("=== B. 端到端：travel_agent 那个 /chat 端点不该被认成有鉴权 ===")
SRC = "\n".join([
    "from fastapi import FastAPI, HTTPException",
    "app = FastAPI(title='Travel Agent', version='0.2.0')",
    "",
    "@app.post('/chat')",
    "async def chat(request: ChatRequest):",
    "    if not _startup_validated:",
    "        raise HTTPException(status_code=503, detail='not initialised')",
    "    try:",
    "        return await chat_endpoint_traced(",
    "            message=request.message, conversation_id=request.conversation_id)",
    "    except Exception as exc:",
    "        if 'API_KEY' in str(exc):",
    "            raise HTTPException(status_code=503, detail=str(exc))",
    "        raise HTTPException(status_code=500, detail='Error processing request')",
    "",
    "@app.get('/conversations')",
    "async def list_conversations():",
    "    return []",
    "",
])
res, _ = A.analyze(SRC, "travel_agent/app.py")
n = res["inconsistent_auth"]["n_hits"]
chk("inconsistent_auth（应 0：/chat 没鉴权且不该引爆 /conversations）", n, 0)
if n:
    for h in res["inconsistent_auth"]["hits"]:
        print("       误报: %s:%s" % (h["file"], h["line"]))

print()
print("=== C. 反向档：真鉴权端点仍要被认出来（别修过头）===")
# ★ 用字符串拼接而不是三引号嵌套 —— 嵌套引号会被外层截断，
#   我第一版就是这么写的，结果 analyze() 报 0，误以为判据坏了。
SRC2 = "\n".join([
    "from fastapi import FastAPI, HTTPException",
    "app = FastAPI()",
    "",
    "def _uid(request):",
    "    uid = getattr(request.state, 'user_id', None)",
    "    if not uid:",
    "        raise HTTPException(status_code=401, detail='need login')",
    "    return str(uid)",
    "",
    "@app.get('/a')",
    "async def a(request):",
    "    uid = _uid(request)",
    "    return {'uid': uid}",
    "",
    "@app.get('/b')",
    "async def b():",
    "    return {}",
    "",
])
res2, _ = A.analyze(SRC2, "r.py")
h2 = res2["inconsistent_auth"]
print("  inconsistent_auth 命中 %d 处（期望 1，且是 /b）" % h2["n_hits"])
for hh in h2["hits"]:
    print("       %s:%s  %s" % (hh["file"], hh["line"], hh["text"]))
ok = (h2["n_hits"] == 1 and "b" in (h2["hits"][0]["text"] or ""))
if not ok:
    BAD += 1
print("  %s 反向档：真鉴权端点被认出来、无鉴权的那个被报出来"
      % ("OK  " if ok else "FAIL"))

print()
print("失败 %d" % BAD)
sys.exit(1 if BAD else 0)
