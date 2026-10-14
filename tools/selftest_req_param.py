# -*- coding: utf-8 -*-
r"""★ `_has_req_param` 的标准答案集 —— 15 档，改 `_REQ_PARAM` 后必须全过。

为什么这一档特别重要
--------------------
`_REQ_PARAM` 从通配 `\b\w*request\w*` 收紧成精确白名单
`^(?:request|http_request|...)$` 时，我踩了一个**假阴性**坑：

    旧用法：_REQ_PARAM.search(arglist)      arglist = "run_id, http_request"
    新正则：^request$                        → 永远匹配不上整段文本！

→ 所有端点都被认成"无鉴权" → **真洞被藏起来**，
  而且**看起来一切正常**（有数字、有覆盖率、有证据）。

所以第 1 档 `_authorize_run_mutation(run_id, http_request)` 是**专门防这个坑的**。
★ 它对应10-05 上午在 `another-sample-agent/api/main.py`
  真实遇到过的形态（第 1131 行）。

跑法：
    python tools/selftest_req_param.py
"""
import os
import sys

CASES = [
    # (实参列表文本, 期望, 为什么)
    ("run_id, http_request", True,
     "★★ 收紧过头的坑就挂在这：整段文本里含 http_request，但 ^...$ 匹不了整段"),
    ("request", True, "最标准"),
    ("request_obj", True, "后缀型"),
    ("request_object", True, "后缀型全拼"),
    ("req", True, "短名（starlette/req 库习惯）"),
    ("request, scope", True, "第 1 位 + 后面还有别的"),
    ("ctx.state, request=request", True, "★ 关键字实参"),
    # ---- 以下是必须认不出来的（它们不是「一个 HTTP 请求对象」）----
    ("requested_path", False, "★★ 路径参数（FastAPI 最常见）"),
    ("request_id", False, "★★ 业务 ID"),
    ("agent_request_id", False, "业务 ID（另一项目）"),
    ("request_timeout_seconds", False, "超时配置"),
    ("request_may_have_spent", False, "★★ 计费额度（商业化项目）"),
    ("credits_per_request", False, "★ 计费（前后都接字符）"),
    ("requests", False,
     "★★★ HTTP 客户端库名 —— 出站调用，与鉴权毫无关系"),
    ("chat_request", False, "Pydantic 模型"),
    ("resume_requested", False, "过去式"),
    ("run_id", False, "完全无关"),
    ("", False, "空串"),
]


def main():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ast_criteria import _has_req_param

    bad = []
    for arglist, exp, why in CASES:
        got = _has_req_param(arglist)
        ok = (got == exp)
        if not ok:
            bad.append((arglist, exp, got, why))
        print("%s %-32r exp=%-5s got=%-5s  %s"
              % ("OK  " if ok else "FAIL", arglist, exp, got, why))
    print()
    if bad:
        print("★ %d / %d 档不通过 —— ★ 别拿去改规则：收紧过头会造成**假阴性**"
              % (len(bad), len(CASES)))
        print("  假阴性 = 真洞被藏起来，比假阳性危险得多。")
        return 1
    print("全部 %d 档通过 ✓（含 1 档专门防「收紧过头」）" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
