# -*- coding: utf-8 -*-
"""立卷门槛：把「哪些候选值得变成一个案子」写成可执行的判据。

★★ 为什么要有这个文件
   第二步（反推形状）的产出里有一条 `立卷标准.md`，写的是三条门槛：有进攻面、有外部可达的
   入口、追证至少能取到一个上游。但**它当时只是一段话**——没有实现、没有在任何真实候选集上
   跑过。计划里那句「2747 条候选不是都要变成案子，不设门槛，工作台就变成 2747 个空文件夹」
   就一直停在纸面上。
   这个文件把那三条变成谓词，然后在真实候选集上跑一遍，得到「该立几条」。

★ 判据只用**已经落盘的数据**（`Finding` 的字段），不重新扫、不调模型、不猜。
  取不到的字段一律按「不知道」处理，**不许因为拿不到就默认通过或默认拒绝**。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 危险动作：这些函数的实参一旦外部可控，性质就变了。其余（读文件、发请求）降一档看。
DANGEROUS = {
    "exec", "eval", "compile", "__import__", "execfile",
    "system", "popen", "call", "run", "Popen", "check_output", "check_call",
    "spawn", "spawnSync", "execSync", "execFile", "fork",
    "execute", "executemany", "raw", "extra",
    "open", "write_text", "write_bytes", "dump", "dumps",
    "loads", "load", "yaml_load", "pickle_load",
    "render_template_string", "Markup", "from_string",
}

# ★ 按**全名**匹配的（末段比对会误伤）：`os.path.join` 是路径拼接、能造穿越；
#   但 `str.join` / `"".join` 完全无害，只按末段 `join` 匹配就会把它也算成进攻面。
DANGEROUS_FULL = {
    "os.path.join", "posixpath.join", "ntpath.join",
    "os.path.abspath", "os.path.realpath", "os.path.normpath",
    "shutil.copy", "shutil.copyfile", "shutil.move", "shutil.rmtree",
    "os.remove", "os.unlink", "os.rename", "os.makedirs", "os.mkdir",
    "send_file", "send_from_directory", "FileResponse", "StreamingResponse",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pickle.loads", "marshal.loads", "yaml.load", "yaml.unsafe_load",
    "sqlite3.connect", "cursor.execute", "conn.execute",
}

# 测试文件不立案：它们本来就在拿假数据跑，报出去没有意义
TEST_HINTS = ("/test_", "/tests/", "_test.py", "conftest.py", "/spec/", ".spec.", ".test.")


def _is_test(rel: str) -> bool:
    p = "/" + (rel or "").replace("\\", "/").lower()
    return any(h in p for h in TEST_HINTS)


def _sources(fd) -> list[dict]:
    return [a for a in (getattr(fd, "arg_sources", None) or []) if isinstance(a, dict)]


def _sink_matches(sink: str, snippet: str = "") -> bool:
    """`subprocess.run` / `os.system` / `cursor.execute` 都要能对上清单。

    ★ 第一版只比对完整字符串，于是 `subprocess.run` 一条都匹配不上、853 条被误挡。
      取末段是必须的：静态前端给的是**点号全名**，清单记的是**函数名**。
    ★ 但末段比对会误伤：`os.path.join` 要算进攻面，`str.join` 不能。所以两条路：
      先查全名清单，再查末段清单。
    ★★ 第三档（真数据第三次打脸）：静态前端有时给的是 `Attribute.join`
      —— **接收者整个丢了**（`core/ql/call/call.qll` 的 `sinkName` 用
      `getObject().getNode().toString()`，对复合对象返回节点类型名 `Attribute` 而不是
      `os.path`）。于是 `os.path.join` 变成 `Attribute.join`，前两档都匹配不上。
      实测代价：CASE-0001 那条**已实跑 8/8 读到 win.ini** 的真洞，
      在 50 条候选里被第①条判成"进攻面弱"。**门槛把唯一一条已知真洞挡了。**
      修法不去动 QL（改 `sinkName` 会改 `sink_func` → 改 fingerprint → 断历史追溯链），
      改在门槛这一侧：接收者丢了，就用 `snippet`（sink 那一行的源码）把全名找回来。
      `os.path.join(` 出现在源码里才算；`"".join(` 不会误伤。
    """
    if not sink:
        return False
    if sink in DANGEROUS_FULL:
        return True
    tail = sink.rsplit(".", 1)[-1]
    if sink.startswith("Attribute."):
        # ★ 接收者已丢 ⇒ **不许**只凭末段放行：`Attribute.exec` 可能是正则的 `TYPED_ID.exec`
        #   （第 6 步在 JS 侧压掉过同一个误报），`Attribute.join` 可能是 `"".join`。
        #   只认源码行里出现的全名。
        if snippet:
            for full in DANGEROUS_FULL:
                if full.rsplit(".", 1)[-1] == tail and (full + "(") in snippet:
                    return True
        return False
    return tail in DANGEROUS


def gate(fd) -> dict:
    """三条门槛，各自独立判，结果逐条给理由。

    返回 {"pass": bool, "checks": {名字: bool|None}, "reasons": [str]}
    `None` = 这条判不了（缺数据），**不算通过也不算拒绝**，最终按不通过处理但单独计数。
    """
    profile = getattr(fd, "entry_profile", None) or {}
    kind = (profile.get("kind") or "unknown").lower()
    exposure = (profile.get("exposure") or "unknown").lower()
    srcs = _sources(fd)
    traced = [a for a in srcs if str(a.get("kind") or "") not in ("", "local")]

    checks: dict[str, bool | None] = {}
    reasons: list[str] = []

    # ① 有进攻面：危险动作 + 不是测试文件
    sink = str(getattr(fd, "sink_func", "") or "")
    if _is_test(getattr(fd, "sink_uri", "") or ""):
        checks["attack_surface"] = False
        reasons.append("候选在测试文件里，不立案")
    elif not sink:
        checks["attack_surface"] = None
        reasons.append("拿不到 sink 函数名，进攻面判不了")
    else:
        checks["attack_surface"] = _sink_matches(sink, str(getattr(fd, "snippet", "") or ""))
        if not checks["attack_surface"]:
            reasons.append(f"`{sink}` 不在危险动作清单里，进攻面弱")

    # ② 有外部可达的入口
    if kind == "unknown":
        checks["external_reach"] = None
        # ★ 说清「为什么不知道」，别让读者以为"这个文件没有入口"
        if not getattr(fd, "src_root", ""):
            reasons.append("src_root 为空 ⇒ 无法判入口形态（老轮次没存这个字段）")
        else:
            reasons.append("入口形态判不出来（unknown），可达性未知")
    elif kind in ("http", "mcp"):
        checks["external_reach"] = exposure in ("high", "medium", "unknown")
        if exposure == "low":
            reasons.append(f"{kind} 但形态判为 low（疑似只监听回环）")
    elif kind == "cli":
        # 本机执行者能碰到 = 有人能触发；但"操作者自己给的参数"不算不可信，
        # 所以 CLI 立案的必要条件是**上游把值送进来**，由第③条兜。
        checks["external_reach"] = True
    else:  # library
        # 库模块本身没有入口，只有被调用方 import 才算可达。
        checks["external_reach"] = bool(traced)
        if not traced:
            reasons.append("库模块且没有任何上游来源证据 ⇒ 没有可达入口")

    # ③ 追证至少取到一个上游
    # ★★ 这一条对 http / mcp 形态**系统性失效**（实测 19 条 http 全挂在这里，
    #    含 CASE-0001 那条已实跑读到 win.ini 的真洞）。原因不在候选：
    #    web 入口的输入是框架从 HTTP 请求里取的（`@app.get("/{path:path}")` +
    #    `async def serve_spa(path: str)`），而 CodeQL 的实参来源查询只认函数参数与数据流，
    #    **不认框架注入** → 那条链永远标成 `local`。
    #    诚实处置：这两种形态下第③条记为 `None`（判不了），
    #    **不算通过、也不当成"确实没有上游"** —— 后者会让统计把"缺数据"读成"没洞"。
    if not srcs:
        if kind in ("http", "mcp"):
            checks["upstream_traced"] = None
            reasons.append("没有实参来源数据；%s 入口的值由框架注入，静态数据流追不到" % kind)
        else:
            checks["upstream_traced"] = False
            reasons.append("没有实参来源数据（arg_sources 为空），追不到上游")
    elif traced:
        checks["upstream_traced"] = True
    elif kind in ("http", "mcp"):
        checks["upstream_traced"] = None
        reasons.append("实参来源全标成 local，但 %s 入口的值来自请求、不是函数参数 ⇒ 这一档判不了" % kind)
    else:
        checks["upstream_traced"] = False
        reasons.append("实参来源全是 local（追不到源头）")

    ok = all(v is True for v in checks.values())
    return {"pass": ok, "checks": checks, "reasons": reasons,
            "kind": kind, "exposure": exposure}


def report(rows: list, on_log=print) -> dict:
    """对一批 Finding 跑门槛，给分布。

    ★★ `False`（判否）与 `None`（判不了）必须**分开计数**。
      以前两者都并进 `by_check`，于是"缺数据"被读成"这条不满足"——
      实测某一轮 50 条里，`upstream_traced` 那栏 46 条其实一大半是"追不到"，
      不是"确实没有上游"。合并计数会把判据的假阴性藏起来。
    """
    from collections import Counter
    out = {"n": 0, "pass": 0, "by_check": Counter(), "by_unknown": Counter(),
           "by_kind": Counter(), "kind_pass": Counter(), "rows": []}
    for fd in rows:
        g = gate(fd)
        out["n"] += 1
        out["by_kind"][g["kind"]] += 1
        if g["pass"]:
            out["pass"] += 1
            out["kind_pass"][g["kind"]] += 1
        for name, v in g["checks"].items():
            if v is False:
                out["by_check"][name] += 1        # 判否：确实不满足
            elif v is None:
                out["by_unknown"][name] += 1      # 判不了：缺数据，不许当判否
        out["rows"].append({"project": getattr(fd, "project", ""),
                            "file": getattr(fd, "sink_uri", ""),
                            "line": getattr(fd, "sink_line", 0),
                            "kind": g["kind"], "pass": g["pass"],
                            "failed": [k for k, v in g["checks"].items() if v is False],
                            "unknown": [k for k, v in g["checks"].items() if v is None],
                            "reasons": g["reasons"]})
    on_log("%d candidates -> %d clear the gate (%.0f%%)" % (
        out["n"], out["pass"], 100.0 * out["pass"] / max(1, out["n"])))
    on_log("entry kinds: " + str(dict(out["by_kind"])))
    on_log("kinds that clear the gate: " + str(dict(out["kind_pass"])))
    on_log("counted as no (genuinely fails): " + str(dict(out["by_check"])))
    on_log("★ cannot tell (missing data, which is not a no): "
               + str(dict(out["by_unknown"])))
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="按立卷门槛筛候选")
    ap.add_argument("--round",
                    help="round directory, or a path to findings.json")
    ap.add_argument("--out", help="write the result as JSON")
    a = ap.parse_args()
    if not a.round:
        ap.print_help()
        return 2
    p = Path(a.round)
    if p.is_dir():
        p = p / "findings.json"
    import csv
    from core import round as R
    findings = R.read_findings_json(p)
    res = report(findings)
    if a.out:
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------
# 窗口档（window trace_level）的门槛，扩语言时用
# ---------------------------------------------------------------------------
# ★ 为什么不复用上面的 `gate()`：那个函数已经被 15 条真实 Python 候选验证过，
#   它的第三条门槛读 `arg_sources`（CodeQL 的跨函数实参来源）。而 JS 那边是 window 档，
#   **没有 arg_sources**，读它必然为空 ⇒ 永远不通过。那不是候选的问题，是门槛和档位耦合了。
#
#   窗口档能拿到的等价证据是「危险位置的实参是不是字面量」（`tools/js_arg_origin.py`）：
#     · 全是字面量      ⇒ **reject**：参数写死在代码里，没必要立案
#     · 有裸变量/表达式 ⇒ **hold**：能立案，但要人看一眼那个变量被赋了什么
#   注意 **window 档给不出 `pass`** —— 它看不到变量的赋值，而"不是字面量"不等于"外部可控"。

WINDOW_VERDICTS = ("all_literal", "has_varref", "has_expr", "no_args")


def gate_window(fd, arg_verdict: str, arg_why: str = "") -> dict:
    """窗口档的立卷判定。`arg_verdict` 来自 `tools/js_arg_origin.py`。

    返回 `{"decision": pass|hold|reject, "checks": {...}, "reasons": [...]}`。
    ★ `decision` 三态而不是布尔：window 档的"够格立案"只能是 hold（待查），
      写成 pass 会把"我没看到赋值"伪装成"我确认了来源"。
    """
    profile = getattr(fd, "entry_profile", None) or {}
    kind = (profile.get("kind") or "unknown").lower()
    exposure = (profile.get("exposure") or "unknown").lower()
    sink = str(getattr(fd, "sink_func", "") or "")

    checks: dict[str, bool | None] = {}
    reasons: list[str] = []

    # ① 进攻面：和 Python 侧同一张清单
    if _is_test(getattr(fd, "sink_uri", "") or ""):
        checks["attack_surface"] = False
        reasons.append("候选在测试文件里，不立案")
    elif not sink:
        checks["attack_surface"] = None
        reasons.append("拿不到 sink 函数名，进攻面判不了")
    else:
        checks["attack_surface"] = _sink_matches(sink, str(getattr(fd, "snippet", "") or ""))
        if not checks["attack_surface"]:
            reasons.append(f"`{sink}` 不在危险动作清单里，进攻面弱")

    # ② 可达入口：和 Python 侧同一套判据
    if kind == "unknown":
        checks["external_reach"] = None
        reasons.append("入口形态判不出来（unknown），可达性未知")
    elif kind in ("http", "mcp"):
        checks["external_reach"] = exposure in ("high", "medium", "unknown")
        if exposure == "low":
            reasons.append(f"{kind} 但形态判为 low（疑似只监听回环）")
    elif kind == "cli":
        checks["external_reach"] = True
    else:
        # 库模块：窗口档看不到谁 import 它 ⇒ 不知道，不算拒绝
        checks["external_reach"] = None
        reasons.append("库模块：窗口档看不到调用方，可达性未知（不等于不可达）")

    # ③ 窗口档的等价物：危险位置的实参不是死值
    if arg_verdict == "all_literal":
        checks["danger_arg_live"] = False
        reasons.append("危险位置的实参全是字面量 —— 参数写死在代码里")
    elif arg_verdict == "no_args":
        checks["danger_arg_live"] = None
        reasons.append("拿不到危险位置的实参（no_args）")
    elif arg_verdict in ("has_varref", "has_expr"):
        checks["danger_arg_live"] = True
        reasons.append(f"{arg_verdict}：{arg_why or '危险位置的实参不是字面量'}")
    else:
        checks["danger_arg_live"] = None
        reasons.append(f"实参判定的取值不认识：{arg_verdict!r}")

    if any(v is False for v in checks.values()):
        decision = "reject"
    elif all(v is True for v in checks.values()):
        # 三项都为真也只到 hold：窗口档看不到赋值，不能宣称来源已确认
        decision = "hold"
        reasons.append("★ 窗口档看不到变量赋值，最多到 hold（待查），给不出 pass")
    else:
        decision = "hold"
    return {"decision": decision, "checks": checks, "reasons": reasons,
            "kind": kind, "exposure": exposure, "trace_level": "window"}
