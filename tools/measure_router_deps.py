# -*- coding: utf-8 -*-
"""★★★ 量「router 级 dependencies」这个鉴权盲区有多大。

发现途径（10-05 08:3x，rhesis-ai/rhesis 核实第 5 处时）：
    apps/backend/src/rhesis/backend/app/routers/services.py:146
        @router.get("/github/contents")
        def get_github_contents(repo_url: str):        ← 判据说"无鉴权"
    但同文件 63 行：
        router = RhesisRouter(
            prefix="/services",
            dependencies=[Depends(require_current_user_or_token)],  ★★ 这里
        )
    → **这个文件里所有端点都有鉴权**，判据完全看不见 router 级这一层。

★ 判据只认 3 种位置：
    1) 端点签名里的 `x: User = Depends(...)`
    2) 端点签名里的类型别名（`x: CurrentUser`，PEP695 那种）
    3) 装饰器（`@require_auth`）
  **漏掉的第 4 种：router / app 构造时的 `dependencies=[...]`。**

输出：每个项目里有多少个 router/app 带dependencies，以及
      这些 router 下的端点被误判成"无鉴权"的规模。
"""
import ast
import io
import os
import re
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402


def router_guards(tree):
    """★ 找出所有 `X = <Router>(...)` 且带 dependencies=[...] 的 router 变量名。"""
    out = {}
    for n in ast.walk(tree):
        if not isinstance(n, (ast.Assign, ast.AnnAssign)):
            continue
        targets = ([n.target] if isinstance(n, ast.AnnAssign)
                   else n.targets)
        if not (isinstance(n.value, ast.Call)):
            continue
        fn = n.value.func
        cname = getattr(fn, "id", None) or \
            getattr(getattr(fn, "attr", None), "__str__", lambda: "")()
        if not isinstance(cname, str) or "Router" not in cname:
            continue
        for kw in n.value.keywords:
            if kw.arg != "dependencies":
                continue
            try:
                src = ast.unparse(kw.value)
            except Exception:
                src = "<unparse failed>"
            if src.strip() in ("[]", ""):
                continue
            for t in targets:
                if isinstance(t, ast.Name):
                    out[t.id] = src
    return out


def main():
    repos = sys.argv[1:] or ["rhesis-ai/rhesis"]
    for repo in repos:
        files, _t, _m = recheck.cache_files(repo, "main")
        if not files:
            print("!! %s 加载失败" % repo)
            continue
        prod = {p: t for p, t in sorted(files.items())
                if p.endswith(".py") and not is_test_path(p)}

        n_guard_routers = 0
        guarded_files = 0
        guarded_endpoints = 0
        misjudged = []
        for p, t in prod.items():
            try:
                tree = ast.parse(t)
            except Exception:
                continue
            guards = router_guards(tree)
            if not guards:
                continue
            n_guard_routers += len(guards)
            guarded_files += 1
            for n in ast.walk(tree):
                if not isinstance(n, (ast.FunctionDef,
                                      ast.AsyncFunctionDef)):
                    continue
                for d in n.decorator_list:
                    try:
                        dec = ast.unparse(d)
                    except Exception:
                        continue
                    m = re.match(r"^([\w\.]+)\.(get|post|put|delete|"
                                 r"patch|head|options)\s*\(", dec)
                    if not m:
                        continue
                    var = m.group(1).split(".")[-1]
                    if var not in guards:
                        continue
                    guarded_endpoints += 1
                    # ★ 这就是被误判的：router 有 dependencies，
                    #   但端点自己没挂任何鉴权
                    try:
                        sig = ast.unparse(ast.arguments(
                            posonlyargs=n.args.posonlyargs,
                            args=n.args.args, vararg=n.args.vararg,
                            kwonlyargs=n.args.kwonlyargs,
                            kw_defaults=n.args.kw_defaults,
                            kwarg=n.args.kwarg,
                            defaults=n.args.defaults))
                    except Exception:
                        continue
                    if "Depends" in sig:
                        continue        # 端点自己也挂了，不算误判
                    try:
                        body = ast.unparse(n)
                        if A._has_auth_wordroot_call(body):
                            continue
                    except Exception:
                        pass
                    misjudged.append((p, n.lineno, dec[:40],
                                      guards[var][:40]))
        print("=" * 78)
        print("%s (%d 生产文件)" % (repo, len(prod)))
        print("  带 dependencies 的 router  = %d （分布在 %d 个文件）"
              % (n_guard_routers, guarded_files))
        print("  这些 router 下的端点= %d" % guarded_endpoints)
        print("  ★ 其中端点自身无鉴权痕迹 = %d" % len(misjudged))
        for p, ln, dec, g in misjudged[:12]:
            print("      %s:%d%s   deps=%s" % (p, ln, dec, g))
        if len(misjudged) > 12:
            print("      ... 还有 %d 个" % (len(misjudged) - 12))


if __name__ == "__main__":
    main()
