# -*- coding: utf-8 -*-
"""`tools/guard_filler.py` 的自测 —— 钉住「哪种形状判成什么」。

为什么要这么细：这一栏的 verdict 直接决定「这条候选是真洞还是假阳」，
判错一个方向，下游就把真洞当假阳扔掉（或者反过来）。所以每条规则配一个夹具，
**包括「判不出来时必须说不知道」那一条** —— 那是防止工具变成瞎猜的最后一道。

    python tools/selftest_guard_filler.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import guard_filler as G  # noqa: E402

OK = 0
BAD = 0


def rec(name: str, cond: bool, detail: str = "") -> None:
    global OK, BAD
    if cond:
        OK += 1
        print(f"  OK   {name}")
    else:
        BAD += 1
        print(f"  FAIL {name}" + (f"  ← {detail}" if detail else ""))


# --------------------------------------------------------------------------
# 夹具：一个文件里造出所有要考的形状，每条候选指向其中一个 sink
# --------------------------------------------------------------------------
FIXTURE = '''\
import os
import re


def identity_str(payload):
    x = str(payload)
    return eval(x)                          # sink @8


def real_float(payload):
    n = float(payload)
    return eval(n)                          # sink @13


def exist_only(path, base):
    p = os.path.join(base, path)
    if os.path.isfile(p):
        return open(p).read()               # sink @20


def whitelist(payload):
    if payload not in ("safe", "slow"):
        return None
    return eval(payload)                    # sink @27


def unknown_func(payload):
    x = mystery_transform(payload)
    return eval(x)                          # sink @32


def sink_self(payload):
    payload = eval(payload)                 # sink @37 —— 本行自身是 sink，不许当自己的守卫
    return payload


def alias_chain(payload):
    a = payload
    b = a
    c = str(b)
    return eval(c)                          # sink @45


def unknown_if(payload):
    if re.match(SOME_VAR, payload):
        return eval(payload)                # sink @51
    return None


def real_isinstance(payload):
    if not isinstance(payload, str):
        return None
    return eval(payload)                    # sink @58


def no_guard(payload):
    return eval(payload)                    # sink @62
'''


def sink_line_of(path: Path, func: str) -> int:
    """在夹具里按函数名找 sink 行（那个函数里 eval/open 调用的行）。

    ★ 不手写行号：第一版我在注释里手标 `# sink @8`，结果夹具一改就全错位，
      13 条全 FAIL 而根因不在被测代码上。**测试自己也要被怀疑**。
    """
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    name = G._call_name(sub)
                    if name in ("eval", "open"):
                        return sub.lineno
    raise AssertionError(f"the fixture has no sink for {func}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gf_selftest_"))
    fix = tmp / "m.py"
    fix.write_text(FIXTURE, encoding="utf-8")

    def rows(func: str):
        r = G.fill(tmp, "m.py", sink_line_of(fix, func))
        return r["guards_relevant"], r, sink_line_of(fix, func)

    def at(sl: int, up: int = 0) -> str:
        """距 sink 往上 up 行的 location 字符串。"""
        return f"m.py:{sl - up}"

    def verdicts(rows_):
        return str([(x["location"], x["kind"], x["verdict"]) for x in rows_])

    print("[1] an identity transform is bogus")
    got, _, sl = rows("identity_str")
    hit = [x for x in got if x["location"] == at(sl, 1)]
    rec("str(payload) 判 bogus", bool(hit) and hit[0]["verdict"] == "bogus", verdicts(got))
    rec("str 的 why 里点名「对字符串是恒等」", bool(hit) and "恒等" in hit[0]["why"],
        hit[0]["why"][:60] if hit else "")

    print("[2] a real sanitizer is real, and why must say that throwing can itself be a DoS")
    got, _, sl = rows("real_float")
    hit = [x for x in got if x["location"] == at(sl, 1)]
    rec("float(payload) 判 real", bool(hit) and hit[0]["verdict"] == "real", verdicts(got))
    rec("real 的 why 不许让下游读成「安全」", bool(hit) and "DoS" in hit[0]["why"],
        hit[0]["why"][:70] if hit else "")

    print("[3] an existence check is not a guard")
    got, _, sl = rows("exist_only")
    hit = [x for x in got if x["location"] == at(sl, 1)]
    rec("os.path.isfile 判 bogus", bool(hit) and hit[0]["verdict"] == "bogus", verdicts(got))
    rec("isfile 的 why 说清「穿越出来的路径只要存在就通过」",
        bool(hit) and "穿越" in hit[0]["why"], hit[0]["why"][:70] if hit else "")
    rec("同时抓到了上游的 os.path.join", any(x["location"] == at(sl, 2) for x in got),
        str([x["location"] for x in got]))

    print("[4] a literal allowlist is real")
    got, _, sl = rows("whitelist")
    # 夹具里 `if` 与 sink 之间隔着 `return None`，所以是往上第 2 行。
    # ★ 这条断言我改错过两次 —— 手写行偏移很容易错位，测试自己也该被怀疑。
    hit = [x for x in got if x["location"] == at(sl, 2)]
    rec("`x not in (...)` 判 real", bool(hit) and hit[0]["verdict"] == "real", verdicts(got))

    print("[5] an unknown function stays unknown; do not guess")
    got, _, sl = rows("unknown_func")
    hit = [x for x in got if x["location"] == at(sl, 1)]
    rec("mystery_transform 判 unknown", bool(hit) and hit[0]["verdict"] == "unknown", verdicts(got))
    rec("unknown 的 why 写明「无法判断」而不是沉默", bool(hit) and "无法判断" in hit[0]["why"],
        hit[0]["why"][:70] if hit else "")

    print("[6] the sink's own line is not its guard")
    got, r, sl = rows("sink_self")
    rec("`payload = eval(payload)` 没被报成 transform",
        not any(x["location"] == at(sl) for x in got), str([x["location"] for x in got]))
    rec("结果里如实记了「同行嵌套转换未纳入」",
        any("同一行内" in u for u in r["unresolved"]), str(r["unresolved"])[:80])

    print("[7] an alias chain carries through three levels")
    got, _, sl = rows("alias_chain")
    hit = [x for x in got if x["location"] == at(sl, 1)]
    rec("a→b→c 的末端 str() 被找到", bool(hit), verdicts(got))
    rec("constrains_value 是末端变量 c 而不是 payload",
        bool(hit) and hit[0]["constrains_value"] == "c", hit[0]["constrains_value"] if hit else "")

    print("[8] a variable pattern is unknown: you cannot call it an allowlist if you cannot see it")
    got, _, sl = rows("unknown_if")
    hit = [x for x in got if x["location"] == at(sl, 1)]
    rec("re.match(SOME_VAR, ...) 判 unknown", bool(hit) and hit[0]["verdict"] == "unknown", verdicts(got))

    print("[9] a real type constraint is real, and the bool trap is named")
    got, _, sl = rows("real_isinstance")
    # 夹具里 `if` 与 sink 之间还隔了一行 `return None`，所以是往上第 2 行
    hit = [x for x in got if x["location"] == at(sl, 2)]
    rec("isinstance 判 real", bool(hit) and hit[0]["verdict"] == "real", verdicts(got))
    rec("real 的 why 提 isinstance(True, int)", bool(hit) and "True" in hit[0]["why"],
        hit[0]["why"][:70] if hit else "")

    print("[10] with no guard found, say so: that does not mean there is none")
    got, r, sl = rows("no_guard")
    rec("没有相关语句时 guards_relevant 为空", got == [], str(got))
    rec("why_empty 提醒可能是来源在调用方", "不等于" in (r.get("why_empty") or ""),
        (r.get("why_empty") or "")[:80])

    print("[11] another function's guard must not leak in")
    got, _, sl = rows("identity_str")
    others = {at(rows("real_float")[2], 0), at(rows("exist_only")[2], 1), at(rows("whitelist")[2], 1)}
    rec("结果里不含其它函数的行", not any(x["location"] in others for x in got),
        str([x["location"] for x in got]))
    rec("条数不超过 MAX_ROWS", len(got) <= G.MAX_ROWS, str(len(got)))

    print("[12] to_case_shape drops the two fields the schema rejects")
    _, r, _ = rows("real_float")
    case = G.to_case_shape(r)
    allowed = {"location", "kind", "constrains_value", "verdict", "why"}
    bad = [k for row in case["guards_relevant"] for k in row if k not in allowed]
    rec("输出字段全在 schema 白名单内", not bad, str(bad))
    rec("direction 被剔掉了", all("direction" not in row for row in case["guards_relevant"]))
    rec("方向改由 why 的前缀承载",
        all(row["why"].startswith("[上游]") or row["why"].startswith("[下游]")
            for row in case["guards_relevant"]),
        str([row["why"][:6] for row in case["guards_relevant"]]))

    print("[13] a missing file or a syntax error is an error, not an empty result")
    r = G.fill(tmp, "nope.py", 1)
    rec("文件不存在时报 error", bool(r.get("error")), str(r.get("error")))
    (tmp / "broken.py").write_text("def f(:\n  pass\n", encoding="utf-8")
    r2 = G.fill(tmp, "broken.py", 1)
    rec("语法错时报 error 并带行号", bool(r2.get("error")) and "行" in r2["error"], str(r2.get("error")))

    print()
    print(f"passed {OK}, failed {BAD}")
    print("all passed" if BAD == 0 else "there are failures")
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
