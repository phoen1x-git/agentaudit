# -*- coding: utf-8 -*-
"""自测：第 9 种鉴权写法 —— **router 级 dependencies**。

★★ 这个盲区为什么最危险（sample-org/sample-api 实测）：
    router = ApiRouter(prefix="/services",
                          dependencies=[Depends(require_current_user_or_token)])
    @router.get("/github/contents")
    def get_github_contents(repo_url: str): ...
  → 规则只看「端点自己」，会把这个文件里**每一个**端点都判成"无鉴权"。
  → 实测 sampleagent 11 处、sample 2 处，全是 100% 假阳性。

★ 为什么漏了这么久：第 8 种写法（类型别名）的注释里我写了
  "签名里一个 Depends 字都没有" → 我以为已覆盖"Depends 不在签名里"，
  **没想到 Depends 还能挂在 router 上、连签名都不参与。**
"""
import ast
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ast_criteria import (  # noqa: E402
    _collect_router_guards, _router_var_of_deco)

BAD = 0


def chk(desc, got, want):
    global BAD
    ok = (got == want)
    if not ok:
        BAD += 1
    print("  %s %-56s 期望=%-5s 实际=%s"
          % ("OK  " if ok else "FAIL", desc, want, got))


print("=== A. _collect_router_guards ===")
CASES = [
    ("APIRouter + dependencies",
     "from fastapi import APIRouter, Depends\n"
     "router = APIRouter(dependencies=[Depends(auth)])\n",
     {"router"}),
    ("★★ 自定义子类 ApiRouter（真实形态）",
     "router = ApiRouter(prefix='/s', "
     "dependencies=[Depends(require_current_user_or_token)])\n",
     {"router"}),
    ("带 prefix 和 tags 也算",
     "router = APIRouter(prefix='/a', tags=['x'], "
     "dependencies=[Depends(f)])\n",
     {"router"}),
    ("★★ dependencies=[] 不算（显式声明不挂）",
     "router = APIRouter(prefix='/a', dependencies=[])\n",
     set()),
    ("没有 dependencies 不算",
     "router = APIRouter(prefix='/a')\n", set()),
    ("类里定义 router（缩进 4 空格）",
     "class M:\n    router = APIRouter(dependencies=[Depends(g)])\n",
     {"router"}),
    ("★ 多个依赖",
     "router = APIRouter(dependencies=[Depends(a), Depends(b)])\n",
     {"router"}),
    ("★ 变量名带类型注解",
     "router: APIRouter = APIRouter(dependencies=[Depends(h)])\n",
     {"router"}),
    ("★ 非 Router 类（服务容器）不该收",
     "registry = Container(dependencies=[Depends(x)])\n", set()),
    ("★ 没有 dependencies 的自定义 Router 不该收",
     "router = MyRouter(prefix='/x')\n", set()),
]
for desc, src, want in CASES:
    try:
        got = set(_collect_router_guards(ast.parse(src)))
    except Exception as e:
        got = "parse-error:%s" % e
    chk(desc, got, want)

print()
print("=== B. _router_var_of_deco（从装饰器反查 router 变量）===")
DECO = [
    ("@router.get('/x')", "router"),
    ("@self.app.get('/x')", "app"),          # ★ 取最后一段
    ("@api_router.post('/x')", "api_router"),
    ("@router.get('/x', dependencies=[Depends(a)])", "router"),
]
for code, want in DECO:
    d = ast.parse(code + "\ndef f(): pass").body[0].decorator_list[0]
    chk(code, _router_var_of_deco(d), want)

print()
print("=== C. 端到端：真实形态不应被报成「无鉴权」===")
import ast_criteria as A  # noqa: E402

SRC = '''
from fastapi import APIRouter, Depends
from auth import require_current_user_or_token

router = APIRouter(prefix="/services",
                   dependencies=[Depends(require_current_user_or_token)])

@router.get("/github/contents")
def get_github_contents(repo_url: str):
    return read(repo_url)

@router.get("/exchange-rates")
async def get_exchange_rates(current_user: User = Depends(require_current_user_or_token)):
    return {}
'''
tree = ast.parse(SRC)
res, _ = A.analyze(SRC, "routers/services.py")
n_inc = res["inconsistent_auth"]["n_hits"]
n_un = res["unauth_endpoint"]["n_hits"]
chk("inconsistent_auth（router 级鉴权后应全有 → 0）", n_inc, 0)
chk("unauth_endpoint（同上）", n_un, 0)
print("     规则标签:", res["inconsistent_auth"]["label"])
print("     规则标签:", res["unauth_endpoint"]["label"])

print()
print("失败 %d" % BAD)
sys.exit(1 if BAD else 0)
