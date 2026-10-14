# -*- coding: utf-8 -*-
"""★ evidence 的 file 字段必须是**文件路径**，不是路由路径（11 档）。

★★★★★★ 这个 bug 藏了不知道多久，而且是**记录层**的bug ——
   判据结论本身是对的，但证据记错了地方，导致：
     ① 核实的时候看到 `"file": "/chat"` ，根本不知道命中在哪个文件；
     ② files_top 里 27 处命中被压成 9 个「路由路径」桶，
        数据源分布完全失真 —— 而 files_top 恰恰是
        「先看数据源有没有被污染」的那一步。

起因：`_find_unauth_endpoints(tree, lines, path, out)` 的入参 `path`
是文件路径，函数体里却两处写了 `path = m.group(3)`（路由路径），
**把入参覆盖了**。Python 不会报错，覆盖后一切照常运行。

**判据本身没错，错的只是「把结论记到哪儿」。**
这类 bug 比误判更阴险：误判会被自测抓到，记错地方不会。

自测要点：
  1. evidence 里的 "file" == 我传进去的文件路径
  2. 路由路径另存到 "route"，不丢
  3. hit_files 里的也是文件路径（决定 files_top 对不对）
  4. 一个文件里多个不同路由 → 都归到同一个 file
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ast_criteria as ac  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  [%s] %s%s" % ("OK" if cond else "FAIL", name,
                           ("  <- " + detail) if (detail and not cond) else ""))


def hits_of(src, route):
    """跑一遍判据，返回 unauth_endpoint 里 route 匹配的那些 hit。"""
    files = {"app/api/routes.py": src}
    res, failed = ac.analyze_files(files, skip_tests=True)
    got = res["unauth_endpoint"]["hits"]
    return res, [h for h in got if h.get("route") == route], got


# ---------------------------------------------------------------- 1~3
print("\n=== 1~3. file 必须是文件路径 / route 另存 / hit_files 对 ===")

# 故意用「路由名和文件名不一样」的组合，否则测不出来
res, mine, got = hits_of(
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/alpha')\n"
    "async def alpha():\n"
    "    return {'ok': 1}\n"
    "\n"
    "@router.get('/beta')\n"
    "async def beta():\n"
    "    return {'ok': 2}\n",
    "/alpha")

check("1.1 路由 /alpha 被检出", len(mine) == 1, "检出 %d 处" % len(mine))
check("1.2 hit['file'] 是文件路径 app/api/routes.py",
      bool(mine) and mine[0].get("file") == "app/api/routes.py",
      "实际=%r" % (mine[0].get("file") if mine else None))
check("1.3 hit['route'] 单独存了路由 /alpha",
      bool(mine) and mine[0].get("route") == "/alpha",
      "实际=%r" % (mine[0].get("route") if mine else None))
check("1.4 hit 里不再出现 route==file 的混淆（file 不等于 /alpha）",
      bool(mine) and mine[0].get("file") != "/alpha")
check("1.5 hit_files 里是文件路径",
      "app/api/routes.py" in res["unauth_endpoint"]["hit_files"],
      "实际=%r" % (res["unauth_endpoint"]["hit_files"],))

# 两个路由同文件 → hit_files 只该有 1 个文件（不能按路由拆桶）
res2, _, got2 = hits_of(
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/x')\n"
    "async def x():\n"
    "    return 1\n"
    "\n"
    "@router.post('/y')\n"
    "async def y():\n"
    "    return 2\n"
    "\n"
    "@router.delete('/z')\n"
    "async def z():\n"
    "    return 3\n",
    "/x")
hf = res2["unauth_endpoint"]["hit_files"]
check("1.6 三个路由同文件 → hit_files 只有 1 项（files_top 不会被拆成 3 桶）",
      len(hf) == 1 and hf[0] == "app/api/routes.py",
      "实际=%r" % (hf,))

# ---------------------------------------------------------------- 4
print("\n=== 4. 每个命中的 file 都等于传进去的路径（多文件批）===")

two = {
    "pkg/svc/alpha_api.py":
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/a1')\n"
        "async def a1():\n"
        "    return 1\n",
    "pkg/svc/beta_api.py":
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/b1')\n"
        "async def b1():\n"
        "    return 1\n",
}
res3, failed3 = ac.analyze_files(two, skip_tests=True)
hits3 = res3["unauth_endpoint"]["hits"]
check("4.1 两个文件各 1 处，合计 2 处", len(hits3) == 2, "实际 %d" % len(hits3))
check("4.2 两条的 file 分别是各自的文件路径（没串台）",
      sorted(h.get("file") for h in hits3)
      == ["pkg/svc/alpha_api.py", "pkg/svc/beta_api.py"],
      "实际=%r" % sorted(h.get("file") for h in hits3))
check("4.3 hit_files 两个文件都在",
      sorted(res3["unauth_endpoint"]["hit_files"])
      == ["pkg/svc/alpha_api.py", "pkg/svc/beta_api.py"],
      "实际=%r" % sorted(res3["unauth_endpoint"]["hit_files"]))

# ---------------------------------------------------------------- 5
print("\n=== 5. 形式二（裸调用 app.post('/x', handler)）**必须保持关闭** ===")
#★★★★★★ 10-05 的教训：这条分支原来匹配不到东西（死分支），
#   我把它改活之后跑全量 29 项目，114 处业务命中**全是字典取键**
#   （blueprint.get('topology') / server.get('name') / route.get('target')）。
#   载体名都在 ROUTE_BASES 里，第一个参数都是字面量字符串 → 语法上无法区分。
#   加「≥2 个参数」后还剩 26 处，逐条看**仍然全是字典取键**。
#   → 已回滚。这几档现在锁的是「**别再把它打开**」。
res4, mine4, got4 = hits_of(
    "from fastapi import FastAPI\n"
    "app = FastAPI()\n"
    "\n"
    "def handler():\n"
    "    return 1\n"
    "\n"
    "app.post('/direct', handler)\n",
    "/direct")
check("5.1 裸调用式路由**不被报**（形式二已关闭，避免误报字典取键）",
      len(mine4) == 0, "误报 %d 处" % len(mine4))
check("5.2 同理：web.get('title') 这种两参数取键也不报",
      len(hits_of("x = {'a': 1}\nweb = x\n"
                  "t = web.get('title', None)\n", "/none")[1]) == 0)

# ---------------------------------------------------------------- 6
print("\n=== 6. 反向：不能因为修了记录层而多报/少报 ===")
# 有鉴权 → 一处都不该报
res5, mine5, got5 = hits_of(
    "from fastapi import APIRouter, Depends\n"
    "from auth import get_current_user\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/secure')\n"
    "async def secure(u=Depends(get_current_user)):\n"
    "    return u\n"
    "\n"
    "@router.get('/open')\n"
    "async def open_ep():\n"
    "    return 1\n",
    "/secure")
check("6.1 有 Depends 的 /secure 不报", len(mine5) == 0, "误报 %d 处" % len(mine5))
res6, mine6, got6 = hits_of(
    "from fastapi import APIRouter, Depends\n"
    "from auth import get_current_user\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/secure')\n"
    "async def secure(u=Depends(get_current_user)):\n"
    "    return u\n"
    "\n"
    "@router.get('/open')\n"
    "async def open_ep():\n"
    "    return 1\n",
    "/open")
check("6.2 同一个文件里没鉴权的 /open 仍然要报（别修过头）",
      len(mine6) == 1, "检出 %d 处" % len(mine6))

# ---------------------------------------------------------------- 汇总
print("\n" + "=" * 70)
print("通过 %d / %d" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("失败：")
    for f in FAIL:
        print("  - " + f)
    sys.exit(1)
print("全部通过 ✓")