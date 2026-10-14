# -*- coding: utf-8 -*-
"""★ unauth_endpoint 必须认得**跨文件类型别名**（10 档）。

背景
----
第 7 种写法（`别名 = Annotated[..., Depends(...)]`）的机制早就有了 ——
`_find_inconsistent_auth` 一直在用。但**`unauth_endpoint` 没接**，
于是同一个别名在一条判据里被认得出来、在另一条里认不出 → 自相矛盾。

实测代价（`measure_crossfile_alias.py` 量29 个项目）：
  · trinity 16 处（占它 64 处基数的 25%）
  · jarvis-registry 7 处（`type CurrentUser = ...`，PEP 695 语法）
  rhesis 7 处大驼峰别名，0 处用到 → 那边无需动。

真实形态（trinity / jarvis）
----------------------------
    # src/backend/dependencies.py
    AuthorizedAgentByName = Annotated[str, Depends(get_authorized_agent_by_name)]
    type CurrentUser = Annotated[UserContextDict, Depends(get_current_user)]

    # src/backend/routers/agents.py —— 签名里一个 Depends 字都没有
    @router.get("/{agent_name}/terminal")
    async def terminal(agent_name: AuthorizedAgentByName, ...): ...

★★ 防线：两条判据必须同步。少接一条就制造自相矛盾，
   而自相矛盾意味着**两个数字都不能信**。
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ast_criteria as ac  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  [%s] %s%s" % ("OK" if cond else "FAIL", name,
                           ("  <- " + detail) if (detail and not cond) else ""))


DEPS = (
    "from typing import Annotated\n"
    "from fastapi import Depends\n"
    "\n"
    "def get_current_user():\n"
    "    return None\n"
    "\n"
    "def get_authorized_agent_by_name(agent_name: str):\n"
    "    return agent_name\n"
    "\n"
    "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
    "AuthorizedAgentByName = Annotated[str, Depends(get_authorized_agent_by_name)]\n"
)

DEP695 = (
    "from typing import Annotated\n"
    "from fastapi import Depends\n"
    "\n"
    "def get_current_user():\n"
    "    return None\n"
    "\n"
    "type CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
)

ROUTES = (
    "from fastapi import APIRouter\n"
    "from dependencies import CurrentUser, AuthorizedAgentByName\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/secure')\n"
    "async def secure(u: CurrentUser):\n"
    "    return u\n"
    "\n"
    "@router.get('/term/{agent_name}')\n"
    "async def term(agent_name: AuthorizedAgentByName):\n"
    "    return agent_name\n"
    "\n"
    "@router.get('/open')\n"
    "async def open_ep():\n"
    "    return 1\n"
)


def run(files):
    res, failed = ac.analyze_files(files, skip_tests=True)
    return res


def routes_hit(res):
    return {h.get("route") for h in res["unauth_endpoint"]["hits"]}


# ---------------------------------------------------------------- 1
print("\n=== 1. 经典 Annotated 别名（trinity 形态）===")
res = run({"dependencies.py": DEPS, "routers/agents.py": ROUTES})
got = routes_hit(res)
check("1.1 用 CurrentUser 的 /secure 不报", "/secure" not in got, "报了")
check("1.2 用 AuthorizedAgentByName 的 /term/{agent_name} 不报",
      "/term/{agent_name}" not in got, "报了")
check("1.3 没用到别名的 /open 仍然要报（别修过头）",
      "/open" in got, "漏报了")
check("1.4 只报1 处", res["unauth_endpoint"]["n_hits"] == 1,
      "报了 %d 处" % res["unauth_endpoint"]["n_hits"])

# ---------------------------------------------------------------- 2
print("\n=== 2. PEP 695 `type X = ...`（jarvis 形态）===")
res2 = run({"auth/dependencies.py": DEP695,
            "api/routes.py": ROUTES.replace("from dependencies import",
                                             "from auth.dependencies import")})
got2 = routes_hit(res2)
check("2.1 用 type别名的 /secure 不报", "/secure" not in got2, "报了")
check("2.2 /term 也不报，但**原因是词根不是别名**："
      "AuthorizedAgentByName 里含「Authoriz」，AUTH_HINT 直接认了它",
      "/term/{agent_name}" not in got2, "报了")
check("2.3 /open 报", "/open" in got2, "漏报了")

# 2.4：换一个**不含鉴权词根**的别名名，验证确实靠别名机制认出来
ROUTES2 = (
    "from fastapi import APIRouter\n"
    "from auth.dependencies import SessionCtx, AuthorizedAgentByName\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/secure')\n"
    "async def secure(ctx: SessionCtx):\n"
    "    return ctx\n"
)
res2b = run({"auth/dependencies.py":
             "from typing import Annotated\n"
             "from fastapi import Depends\n"
             "def get_session():\n    return None\n"
             "SessionCtx = Annotated[dict, Depends(get_session)]\n",
             "api/routes.py": ROUTES2})
check("2.4 不含鉴权词根的别名 SessionCtx 也能认出来（真靠别名机制）",
      "/secure" not in routes_hit(res2b),
      "报了 → 说明只靠 AUTH_HINT 认 Alias 名字里的词根")

# ---------------------------------------------------------------- 3
print("\n=== 3. ★ 两条判据必须同步（不自相矛盾）===")
# 同一个项目里：别名端点 + 无别名端点
res3 = run({"dependencies.py": DEPS, "routers/agents.py": ROUTES})
ua = res3["unauth_endpoint"]["n_hits"]
ia = res3["inconsistent_auth"]["n_hits"]
check("3.1 unauth_endpoint 只报 /open（1 处）", ua == 1, "实际 %d" % ua)
# inconsistent_auth 认得别名 → 同文件里已有「有鉴权」的端点
# → 剩下无鉴权的 /open 应该被它报成不一致
check("3.2 inconsistent_auth 能认出别名端点（不把它们全当无鉴权）",
      ia >= 1, "inconsistent_auth=%d，一处都没报反而可疑" % ia)

# ---------------------------------------------------------------- 4
print("\n=== 4. 反向：不能因为接了别名而吃掉真阳性 ===")
# 别名名出现在**函数体或无关处**，签名里没有 → 仍应报
res4 = run({
    "dependencies.py": DEPS,
    "routers/x.py":
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/nope')\n"
        "async def nope():\n"
        "    note = 'CurrentUser'# 只是提到这个名字\n"
        "    return note\n",
})
check("4.1 签名里没用别名、只在函数体提到 → 仍然要报",
      "/nope" in routes_hit(res4), "被误当成有鉴权")

# ---------------------------------------------------------------- 5
print("\n=== 5. 反向：普通变量不能被当成别名 ===")
res5 = run({
    "dependencies.py": DEPS,
    "routers/y.py":
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "signer = None\n"
        "\n"
        "@router.get('/z')\n"
        "async def z():\n"
        "    return signer\n",
})
check("5.1 小写普通变量不算别名（CurrentUser 这类大驼峰才算）",
      "/z" in routes_hit(res5), "被误当成有鉴权")

# ---------------------------------------------------------------- 汇总
print("\n" + "=" * 70)
print("通过 %d / %d" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("失败：")
    for f in FAIL:
        print("  - " + f)
    sys.exit(1)
print("全部通过 ✓")