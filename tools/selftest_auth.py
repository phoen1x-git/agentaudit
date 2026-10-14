# -*- coding: utf-8 -*-
"""
inconsistent_auth 判据的 7 档标准答案 —— 改判据后必须跑这个。

★ 为什么要「双向」验证：
  只测「该报的报了」不够 —— 判据也可能因为收得太紧，
  把**该报的也一起压下去**，而数字看起来是「误报减少了」。
  必须同时包含反向档（state 但无 401→ 不算鉴权），
  才能发现「修过头」。

★ 我在这栽过：补第 4 种鉴权写法（中间件注入型）时，
  第一版正则写成request[.]state[.](\\w+)，
  而 ast.unparse 输出的是 getattr(request.state, 'user_id', None)
  —— **属性名是字符串字面量，后面跟逗号不是点**，匹配不到。
  而反向档同时也不过了（该报的没报），
  是双向验证同时暴露了「过松」和「过紧」两个方向。

★★ 补第 6 种写法时（10-05 上午）又栽了一次，这次栽在**标准答案本身**：
  我写的第 9 档是「a 和 b 都调 _fmt(request)」，期望报 1。
  但 a、b 都被判成无鉴权 → 「全都不一致」不成立 → 判据不报，
  **判据是对的，档位是错的**。
  → 教训：**反向档自己必须构成「不一致」**。
    一个「全部同样」的样本测不出修没修过头 ——
    判据把所有人都判成有鉴权、或都判成没鉴权，都能让它「通过」。
"""
import ast
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_criteria as A

CASES = [
    ("1 Depends 注入", '''
from fastapi import Depends, APIRouter
from auth import get_current_user
r = APIRouter()
@r.get("/a")
async def a(u=Depends(get_current_user)): return 1
@r.get("/b")
async def b(): return 1
''', 1, "b 漏挂 → 报 1 处"),

    ("2 函数体内调鉴权", '''
from fastapi import APIRouter
r = APIRouter()
@r.get("/a")
async def a(t): return verify_token(t)
@r.get("/b")
async def b(): return 1
''', 1, "a 有鉴权 → b 报 1 处"),

    ("3 中间件注入型 getattr（新增）", '''
from fastapi import APIRouter, Request, HTTPException
r = APIRouter()
@r.get("/a")
async def a(request: Request):
    uid = getattr(request.state, "user_id", None)
    if not uid: raise HTTPException(401, "x")
    return 1
@r.get("/b")
async def b(): return 1
''', 1, "★ 实测 hunter-community 的实际写法"),

    ("4 全部端点都有鉴权", '''
from fastapi import APIRouter, Depends
from auth import get_current_user
r = APIRouter()
@r.get("/a")
async def a(u=Depends(get_current_user)): return 1
@r.get("/b")
async def b(u=Depends(get_current_user)): return 1
''', 0, "一致 → 不该报"),

    ("5 ★反向档：state 但无 401", '''
from fastapi import APIRouter, Request, Depends
from auth import get_current_user
r = APIRouter()
@r.get("/a")
async def a(u=Depends(get_current_user)): return 1
@r.get("/b")
async def b(request: Request):
    sid = request.state.session_id
    return 1
''', 1, "★ 没 401 说明不是鉴权 → b 该报（防修过头）"),

    ("6 中间件直接属性访问", '''
from fastapi import APIRouter, Request, HTTPException
r = APIRouter()
@r.get("/a")
async def a(request: Request):
    if not request.state.uid: raise HTTPException(403, "no")
    return 1
@r.get("/b")
async def b(): return 1
''', 1, "403 也算拒绝"),

    ("7 真阳性对照：普通漏挂", '''
from fastapi import Depends, APIRouter
from auth import get_current_user
r = APIRouter()
@r.get("/a")
async def a(u=Depends(get_current_user)): return 1
@r.get("/b")
async def b(): return 1
''', 1, "防改动把真阳性一起修掉"),

    #★ 下面 3 档是 10-05 上午补的，起因见下面「★ 第 6 种盲区」那段注释
    ("8 ★自定义鉴权包装 _uid", '''
from fastapi import APIRouter, Request, HTTPException
r = APIRouter()
def _uid(request: Request) -> str:
    uid = getattr(request.state, "user_id", None)
    if not uid: raise HTTPException(401, "需要登录")
    return str(uid)
@r.get("/a")
async def a(request: Request):
    uid = _uid(request)
    return {"user_id": uid}
@r.get("/b")
async def b(): return 1
''', 1, "★ 端点体里只有 _uid(request)，两个正则都匹配不到 → 修好后 b 仍该报 1"),

    ("9 包装函数无鉴权语义（反向档）", '''
from fastapi import APIRouter, Request, Depends
from auth import get_current_user
r = APIRouter()
def _fmt(request: Request) -> str:
    return request.headers.get("x-trace-id", "")
@r.get("/a")
async def a(request: Request, u=Depends(get_current_user)):
    tid = _fmt(request)
    return {"trace": tid}
@r.get("/b")
async def b(request: Request):
    tid = _fmt(request)
    return {"trace": tid}
''', 1, "★ _fmt 只是取 trace-id，不算鉴权 → b 该报（防修过头）"),

    ("10 全端点都用同一包装 → 一致", '''
from fastapi import APIRouter, Request, HTTPException
r = APIRouter()
def _uid(request: Request) -> str:
    uid = getattr(request.state, "user_id", None)
    if not uid: raise HTTPException(401, "x")
    return str(uid)
@r.get("/a")
async def a(request: Request): return {"u": _uid(request)}
@r.get("/b")
async def b(request: Request): return {"u": _uid(request)}
''', 0, "★ hunter-community 的真实形态：全都有 → 不该报"),

    # ★★★ 11~13 是 10-05 上午那次误判的产物。
    #  起因：新加了第 6 种写法后某项目从2 涨到 14，我第一反应是"修对了"。
    #   追下去发现方向反了 —— 新写法让「同文件内有鉴权的端点数」从 1 变 4，
    #   于是**没鉴权的那些全成了"不一致"**。根因是看不见中间件层。
    #   这三档测的是「别把中间件兜底的项目当成漏洞」这个方向。
    ("11 ★参数不在第一位 + 名字不叫 request", '''
from fastapi import APIRouter, Request, HTTPException
r = APIRouter()
def _authorize_thing(thing_id: str, http_request: Request) -> str:
    owner = getattr(http_request.state, "owner", None)
    if owner != thing_id:
        raise HTTPException(403, "not yours")
    return owner
@r.get("/a")
async def a(thing_id: str, http_request: Request):
    return {"o": _authorize_thing(thing_id, http_request)}
@r.get("/b")
async def b(): return 1
''', 1, "★ 实测 _authorize_run_mutation(run_id, http_request) 的形态："
        "request 排第2 且叫 http_request → 修好后 a 认得出有鉴权，b 仍该报 1"),

    ("12 ★包装函数只做参数校验（反向档·防修过头）", '''
from fastapi import APIRouter, Request, HTTPException
r = APIRouter()
def _check_quota(http_request: Request) -> int:
    if http_request.headers.get("x-quota") is None:
        raise HTTPException(402, "quota")
    return 100
@r.get("/a")
async def a(request: Request, u=Depends(get_current_user)):
    return {"q": _check_quota(request)}
@r.get("/b")
async def b(request: Request):
    return {"q": _check_quota(request)}
''', 1, "★ 402 是计费不是鉴权（判据只认 401/403）→ b 该报，"
        "防把「任何 raise HTTPException」都当成鉴权"),

    ("13 ★包装函数读身份但从不拒绝（反向档）", '''
from fastapi import APIRouter, Request
r = APIRouter()
def _maybe_owner(request: Request) -> str:
    return getattr(request.state, "owner", None) or "anonymous"
@r.get("/a")
async def a(request: Request, u=Depends(get_current_user)):
    return {"o": _maybe_owner(request)}
@r.get("/b")
async def b(request: Request):
    return {"o": _maybe_owner(request)}
''', 1, "★ 读了 request.state 但没有拒绝分支 → 不是鉴权 → b 该报"),

    # ★★★★★ 第 14 档（10-05 06:55 补）：第 7 种写法「类型别名注入」
    #  这一档**需要第二个文件**—— 别名定义在 dependencies 里，路由文件只 import。
    #  实测 abilityai/trinity：整个 client_portal/router.py 因此全被判成"无鉴权"，
    #  而"同文件内 1/5 有鉴权"那个 1 引爆点带出 4 处误报。
    #  ★ 也正因为它是跨文件的，我第一版实现写成了单文件扫 → 等于没修。
    #    所以这一档专门用来卡住"必须跨文件"这个性质。
    ("14 ★类型别名注入（跨文件·第7种写法）", '''
from fastapi import APIRouter
from typing import Annotated
from backend.dependencies import OwnedAgentByName, CurrentUser
r = APIRouter()
@r.get("/a")
async def a(agent_name: OwnedAgentByName, current_user: CurrentUser): return 1
@r.get("/b")
async def b(): return 1
''', 1, "★ 别名在另一个文件里定义为 Annotated[..., Depends(...)]；"
        "签名里没有 Depends 字样 → 修好后 a 认得出，b 仍该报 1",
     # ★ 第二个文件：别名定义处
     '''
from typing import Annotated
from fastapi import Depends
def get_owned_agent_by_name(name: str): return name
def get_current_user(): return "u"
OwnedAgentByName = Annotated[str, Depends(get_owned_agent_by_name)]
CurrentUser       = Annotated[str, Depends(get_current_user)]
'''),
]

# ★ 声明「同一个源串被拆成多文件」的档位下标 → 需要走 analyze_files 的两趟逻辑
MULTI_FILE_CASES = {len(CASES) - 1}


def main():
    print("=" * 66)
    print("inconsistent_auth 判据 ·%d 档标准答案" % len(CASES))
    print("=" * 66)
    ok = True
    for idx, case in enumerate(CASES):
        name, src, exp, why = case[0], case[1], case[2], case[3]
        extra = case[4] if len(case) > 4 else None
        out = {"inconsistent_auth": {"hits": [], "n_hits": 0, "hit_files": []}}
        try:
            if extra is not None:
                # ★ 走真实入口，让 analyze_files 的第 1 趟真的跑起来。
                #   直接调 _find_inconsistent_auth 会绕过别名收集 → 测不到跨文件性质。
                A._ALL_MODULE_SRC = src + "\n" + extra
                A._find_inconsistent_auth(ast.parse(src), src.splitlines(),
                                         "t.py", out)
                A._ALL_MODULE_SRC = ""
            else:
                A._ALL_MODULE_SRC = ""
                A._find_inconsistent_auth(ast.parse(src), src.splitlines(),
                                         "t.py", out)
            got = out["inconsistent_auth"]["n_hits"]
        except Exception as e:
            got = "异常 %s: %s" % (type(e).__name__, e)
        good = (got == exp)
        if not good:
            ok = False
        print("  %s %-32s 期望 %d 实得 %s" %
              ("OK  " if good else "FAIL", name, exp, got))
        print("       %s" % why)
    print()
    print("=" * 66)
    if ok:
        print("全部 %d 档通过 ✓  可以出结论了" % len(CASES))
        return 0
    print("★ 有失败 —— 不要据此出结论，先修判据")
    return 1


if __name__ == "__main__":
    sys.exit(main())
