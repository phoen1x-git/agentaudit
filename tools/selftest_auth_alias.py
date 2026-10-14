# -*- coding: utf-8 -*-
"""★ 验`_collect_auth_aliases` 的两种失败形态。

背景（jarvis-registry 实测）：
    # registry/src/registry/auth/dependencies.py:40
    type CurrentUser = Annotated[UserContextDict, Depends(get_current_user)]
    # registry/src/registry/api/proxy_routes.py:527
    async def clear_session_endpoint(..., user_context: CurrentUser): ...
  → 别名一个都没收到 → 端点被判成"无鉴权" → 假阳性。
"""
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ast_criteria import _collect_auth_aliases  # noqa: E402

CD = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                  "..", "data", "target_pool", "_src_cache")
DEP = os.path.join(CD, "f__ascending-llc_jarvis-registry__registry_src_"
                        "registry_auth_dependencies.py.txt")

CASES = [
    # (说明, 源码, 期望是否收得到)
    ("经典赋值 X = Annotated[...Depends(...)]",
     "CurrentUser = Annotated[User, Depends(get_current_user)]\n", True),
    ("★ PEP695: type X = Annotated[...Depends(...)]",
     "type CurrentUser = Annotated[User, Depends(get_current_user)]\n", True),
    ("FastAPI 官方写法 X = Depends(...)",
     "CurrentUser = Depends(get_current_user)\n", True),
    ("★ PEP695 简写: type X = Depends(...)",
     "type CurrentUser = Depends(get_current_user)\n", True),
    ("带类型注解的赋值 X: T = Annotated[...Depends(...)]",
     "CurrentUser: tp.Alias = Annotated[User, Depends(get_current_user)]\n",
     True),
    ("多行 Annotated（Depends 在下一行）",
     "type CurrentUser = Annotated[\n    User,\n    Depends(get_current_user),\n]\n",
     True),
    ("★ 小写别名不该收（避免把普通变量当别名）",
     "helper = Depends(get_current_user)\n", False),
    ("无关赋值不该收",
     "MAX_SIZE = 1024\n", False),
]

print("=== _collect_auth_aliases 自测 ===")
bad = 0
for desc, src, want in CASES:
    got = bool(_collect_auth_aliases(src))
    ok = (got == want)
    bad += (not ok)
    print("  %s %-52s 期望=%-5s 实际=%-5s收=%s"
          % ("OK  " if ok else "FAIL", desc, want, got,
             sorted(_collect_auth_aliases(src))))

print()
print("=== 真实文件（jarvis dependencies.py）===")
real = open(DEP, encoding="utf-8", errors="replace").read()
al = _collect_auth_aliases(real)
print("  收得别名:", sorted(al) or "(空)")
print("  含CurrentUser:", "CurrentUser" in al)
print()
print("  第 40 行原文:", repr(real.split("\n")[39]))

print()
print("=== 单行正则 vs 加 type 前缀 ===")
LINE = r"^[ \t]*([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
LINE_T = r"^[ \t]*(?:type\s+)?([A-Z]\w*|_\w+)\s*(?::[^=\n]+)?=\s*"
for name, pat in (("现状", LINE), ("加 type 前缀", LINE_T)):
    got = re.findall(pat + r"Annotated\s*\[", real, re.M)
    print("  %-12s -> %s" % (name, got))

print()
print("失败 %d / %d" % (bad, len(CASES)))
sys.exit(1 if bad else 0)
