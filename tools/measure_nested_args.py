# -*- coding: utf-8 -*-
"""★★★ 量「嵌套实参假阴性」的真实规模。

问题（第 6 种鉴权写法的盲区）：
    _auth(get_identity(request), scope)
判据靠正则切括号去提取被调函数的实参列表，
只会匹配到**内层** `get_identity(`，认不出真正的 `_auth`。

★ 这就是 `docs/46` 第六节那条教训的正面用法：
  **发现一个判据边界问题后，先量它在真实数据里的规模，再决定改不改。**
  量完可能会发现"边界情况没错，真实错的是别的地方"。

输出：
  1) 全库有多少处「实参里含嵌套调用」
  2) 其中多少处**同时**实参含 request 对象（这才可能漏判）
  3) 漏判后会发生什么 —— 是少认一个鉴权（假阴性）还是别的
"""
import ast
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A  # noqa: E402
import recheck  # noqa: E402
from is_test_path import is_test_path  # noqa: E402

# 判据里认的包装函数命名
WRAP = re.compile(r"\b_\w+\s*\(")
REQ_TOK = re.compile(
    r"^(?:request|http_request|http_req|req|request_obj|request_object|"
    r"req_obj|raw_request|scoped_request|starlette_request|"
    r"fastapi_request)$", re.I)


def has_req_tok(arglist):
    if not arglist:
        return False
    for t in re.split(r"[^A-Za-z0-9_]+", arglist):
        if t and REQ_TOK.match(t):
            return True
    return False


def main():
    repos = sys.argv[1:] or ["ascending-llc/jarvis-registry"]
    for repo in repos:
        files, _t, _m = recheck.cache_files(repo, "main")
        if not files:
            print("!! %s加载失败" % repo)
            continue
        prod = {p: t for p, t in sorted(files.items())
                if p.endswith(".py") and not is_test_path(p)}
        all_src = "\n".join(prod.values())
        aliases = A._collect_auth_aliases(all_src)

        n_call = 0          # 包装函数调用总数
        n_nested = 0        # 实参里含嵌套调用
        n_nested_req = 0    # ★ 实参含嵌套调用 且 实参含 request 对象
        samples = []
        for p, t in prod.items():
            try:
                tree = ast.parse(t)
            except Exception:
                continue
            for n in ast.walk(tree):
                if not isinstance(n, ast.Call):
                    continue
                fn = n.func
                name = getattr(fn, "id", None) or \
                    getattr(getattr(fn, "attr", None), "__str__", lambda: "")()
                if not (isinstance(name, str) and name.startswith("_")):
                    continue
                n_call += 1
                arg_src = ""
                for a in list(n.args) + [k.value for k in n.keywords]:
                    try:
                        arg_src += ast.unparse(a) + ","
                    except Exception:
                        pass
                has_nested = any(isinstance(a, (ast.Call, ast.Await))
                                 for a in list(n.args))
                if not has_nested:
                    continue
                n_nested += 1
                if has_req_tok(arg_src):
                    n_nested_req += 1
                    if len(samples) < 12:
                        samples.append((p, n.lineno, name, arg_src[:110]))
        print("=" * 78)
        print("%s (%d 生产文件)" % (repo, len(prod)))
        print("  包装函数调用总数         = %d" % n_call)
        print("  其中实参含嵌套调用       = %d" % n_nested)
        print("  ★ 且实参含 request 对象  = %d" % n_nested_req)
        for p, ln, nm, a in samples:
            print("      %s:%d  %s(%s)" % (p, ln, nm, a))


if __name__ == "__main__":
    main()
