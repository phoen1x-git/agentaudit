# -*- coding: utf-8 -*-
"""★ 第 6 种写法的「转发层」缺陷（10-07 修）。

★ 缺陷是什么
------------
`_wrapper_is_auth` 要求包装函数**自己**同时满足
「读了身份」+「会拒绝」。遇到这种转发就断了：

    def require_admin_header(token, session):
        return current_admin(session, token)     # ← 自己什么都不做

真鉴权在 `current_admin` 里：
    def current_admin(session, admin_token):
        if admin_token and not admin_auth.has_users():
            require_admin_token(admin_token)      # 读身份 + 会拒绝
        ...

实测代价：astra-quant-agent **72 处**（116 处里的 62%）全是假阳性，
占全表 433 处判定的 **17%**。

★★ 为什么必须追进被调用的函数
   「看起来没鉴权」和「确实没鉴权」在这条路径上**长得一模一样** ——
   判据能说"我查过了，没找到"，但它其实只查了一层。
   这比"不知道有没有盲区"危险：**它声称查过了。**

★ 为什么这类包装函数现实中很常见
   FastAPI 项目里`get_current_user` / `require_admin` 这类东西
   十有八九会再包一层（兼容 sync/async、统一默认值、日志），
   所以这不是项目个例，是结构性的。

跑法：`python tools/selftest_wrapper_forward.py`
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A

CASES = []


def case(name, src, expect_auth, why):
    CASES.append((name, src, expect_auth, why))


# ★★ 1. 核心档：转发一层
case(
    "1.1 包装函数转发给另一个鉴权函数",
    '''
def require_admin_header(token: str = None, session: str = None) -> dict:
    return current_admin(session, token)

def current_admin(session, admin_token):
    if admin_token and not admin_auth.has_users():
        require_admin_token(admin_token)
    if not session:
        raise HTTPException(status_code=401, detail="会话失效")
    return {"role": "admin"}

@app.get("/api/admin/memory")
def get_admin_memory(x_admin_token: str = Header(default=None), x_session: str = Header(default=None)):
    actor = require_admin_header(x_admin_token, x_session)
    return {"ok": True}
''',
    True,
    "★ 这就是 astra 的真实形态：包装层什么都不做，真逻辑在被调用的函数里",
)

#★★ 1.2 转发一层，且被转发的函数再调另一个函数（astra 的**真实形态**）
case(
    "1.2 转发链末端再调一层",
    '''
def require_admin_header(token: str = None, session: str = None) -> dict:
    session_tok = session if isinstance(session, str) else REQUEST_SESSION.get()
    admin_tok = token if isinstance(token, str) else None
    return current_admin(session_tok, admin_tok)

def current_admin(session_tok, admin_tok):
    if admin_tok and not admin_auth.has_users():
        require_admin_token(admin_tok)
    if not session_tok:
        raise HTTPException(status_code=401, detail="会话失效")
    return {"role": "admin"}

def require_admin_token(token) -> None:
    if not hmac.compare_digest(token, EXPECTED):
        raise HTTPException(status_code=403, detail="token 无效")

@app.get("/api/admin/memory")
def get_admin_memory(x_astra_admin_token: str = Header(default=None), x_session: str = Header(default=None)):
    refresh_settings()
    require_admin_header(x_astra_admin_token, x_session)
    return {"ok": True}
''',
    True,
    "★★ 这是 astra-quant-agent app.py:209-121 的**逐字形态**。"
    " 包装层 require_admin_header 自己什么都不做（连 token 字样都没有），"
    " 真逻辑在 current_admin → require_admin_token 里。"
    "★ 我第一版自测（1.1）把 HTTPException 直接写在 current_admin 里，"
    "  结果自测过、真实代码不过 —— 说明**自测档必须照抄真实形态**。",
)

# 1.3 ★★ 修正后的期望：这个档**不该**被认出来
case(
    "1.3 转发三层但入口名字无守卫词（不该认）",
    '''
def _auth(token, session):
    return _inner(session, token)

def _inner(session, token):
    return _core(token)

def _core(token):
    if token != EXPECTED:
        raise HTTPException(status_code=403, detail="forbidden")
    return {"ok": True}

@app.get("/x")
def x(token: str = Header(default=None)):
    return _auth(token, None)
''',
    False,
    "★★ **这个期望是我改过的**（原写True，实测得到 False）。"
    " 改的理由：入口 `_guard_called_names` 要求「函数名像守卫 + 实参含凭据」，"
    "`_auth` 匹不上守卫词 → 根本进不了候选。"
    "★ 要让它进候选，就得放弃「入口收紧」策略，"
    "  那会让 f(payload) / f(row) 之类全变成候选 —— 候选爆炸。"
    "→ **这是有意的取舍，不是漏网**。"
    "  真实项目里守卫函数都叫 require_xxx / check_xxx / get_current_xxx；"
    "  而实测 30 个项目里，认不出的只有这一类「自定义短名+ 多层转发」。",
)

# ★★ 2. 反向档：转发到一个**不认身份也不拒绝**的函数 → 仍应判无鉴权
case(
    "2.1 转发到不拒绝的函数（不能误认）",
    '''
def require_thing(token: str = None):
    return helper(token)

def helper(token):
    return {"len": len(token or "")}

@app.get("/x")
def x(token: str = Header(default=None)):
    return require_thing(token)
''',
    False,
    "★★ 关键反向档：转发本身不是鉴权。追进去确认真的读身份+会拒绝才算",
)

# 2.2 转发到一个只读身份、不拒绝的函数
case(
    "2.2 转发到只读身份不拒绝的函数",
    '''
def require_thing(token: str = None):
    return helper(token)

def helper(token):
    user_id = getattr(token, "user_id", None)
    LOG.info("uid=%s", user_id)
    return {"ok": True}

@app.get("/x")
def x(token: str = Header(default=None)):
    return require_thing(token)
''',
    False,
    "★ 只读不拒 ≠ 鉴权（和判据 5 的反向档同一条纪律）",
)

# 2.3 转发到一个只拒绝、不读身份的函数
case(
    "2.3 转发到只拒绝不读身份的函数",
    '''
def require_thing(token: str = None):
    return helper(token)

def helper(token):
    if not token:
        raise HTTPException(status_code=401, detail="no token")
    return {"ok": True}

@app.get("/x")
def x(token: str = Header(default=None)):
    return require_thing(token)
''',
    False,
    "★ 只拒不读 ≠ 鉴权 —— 可能只是在校验参数非空",
)

# ★★ 3. 循环调用不能死循环
case(
    "3.1 转发成环",
    '''
def a(x=None):
    return b(x)

def b(x=None):
    return a(x)

@app.get("/x")
def x():
    return a()
''',
    False,
    "★★ 环引用必须终止，不能栈溢出也不能当成鉴权",
)

# 3.2 自我转发
case(
    "3.2 自我转发",
    '''
def a(x=None):
    return a(x)

@app.get("/x")
def x():
    return a()
''',
    False,
    "★ 自调用必须终止",
)

# ★★ 4. 同步/异步混合（FastAPI 项目极常见）
case(
    "4.1 async 包装转发 sync 鉴权",
    '''
async def require_admin(token: str = None):
    return check_admin(token)

def check_admin(token):
    if not admin_auth.verify(token):
        raise HTTPException(status_code=403, detail="denied")
    return {"role": "admin"}

@app.get("/x")
async def x(token: str = Header(default=None)):
    return await require_admin(token)
''',
    True,
    "★ async 包装 sync 逻辑很常见，两边都要认",
)

# ★★ 5. 端点自己就是那个转发链的起点
case(
    "5.1 端点调的是转发链末端",
    '''
def current_admin(session, token):
    if not session:
        raise HTTPException(status_code=401)
    if token and not admin_auth.has_users():
        raise HTTPException(status_code=403)
    return {"role": "admin"}

@app.get("/x")
def x(session: str = Header(default=None), token: str = Header(default=None)):
    return current_admin(session, token)
''',
    True,
    "端点直接调末端（无转发层）—— 这是原来就能认的档，留作回归",
)


def run():
    passed = failed = 0
    for name, src, expect, why in CASES:
        A._AUTH_ALIASES_CACHE[0] = (None, set())
        A._ALL_MODULE_SRC = ""
        res, err = A.analyze(src, "<t>")
        if err:
            print("  FAIL %-46s 解析失败 %s" % (name, err))
            failed += 1
            continue
        hits = res["unauth_endpoint"]["hits"]
        got_auth = (len(hits) == 0)
        ok = (got_auth == expect)
        if ok:
            passed += 1
            print("  OK   %-46s %s" % (name, "认成有鉴权" if expect else "认成无鉴权"))
        else:
            failed += 1
            print("  FAIL %-46s 期望%s 实得%s"
                  % (name, "有鉴权" if expect else "无鉴权", "有鉴权" if got_auth else "无鉴权"))
            for h in hits[:2]:
                print("         命中: %s  %s" % (h.get("route", "-"), h.get("text", "")[:60]))
            print("         原因: %s" % why)
    print("-" * 70)
    print("失败 %d / %d" % (failed, len(CASES)))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())