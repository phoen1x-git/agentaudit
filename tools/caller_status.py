# -*- coding: utf-8 -*-
"""`callers.status` —— 零调用方时，到底是死代码、公开 API，还是动态派发。

    python tools/caller_status.py --root <src> --file <rel> --line <行号>
    python tools/caller_status.py --root <src> --file <rel> --line <行号> --out x.json

★★★ 为什么要有这个文件
   第四步（真走一遍）的失败信号就是这一格。用 trulens 从头走的那一轮，六个动作里第 4 步卡住，
   工具的原话是「可能是公开 API、死代码或动态派发，**工具分不出来**」——
   而这一步**决定结论方向**：
       死代码   ⇒ 直接丢弃，不用立案
       公开 API ⇒ `arg_source=local`，多半 `no_go`（值由开发者自己传）
       动态派发 ⇒ 继续追注册表，**可能翻成 vuln**
   形状里没有一栏装这个区分，`CASE-0004`（trulens）与 `CASE-0002`（metagpt）缺的是同一个东西。
   所以把它做成工具，而不是继续写在 `why` 的散文里。

★ 设计纪律（和 `triage_gate` 一致）：
   1. 四态之外还有 `unknown`。**判不出来就写 `unknown`**，并写清"缺哪一样证据"。
   2. 每个态都要有**能指到的证据**（文件:行号），不许只给标签。
   3. 判据顺序写死：先看有没有调用方；没有才依次看 动态派发 → 公开 API → 死代码。
      顺序不能换 —— 动态派发排第一，因为它能把 `no_go` 翻成 `vuln`，漏了代价最大。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import trace_note as TN                      # noqa: E402

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "build", "dist", ".mypy_cache"}
TEST_HINTS = ("/tests/", "/test/", "/test_", "_test.py", "conftest.py")


def _is_test(rel: str) -> bool:
    p = "/" + rel.replace("\\", "/").lower()
    return any(h in p for h in TEST_HINTS)


def _iter_py(root: Path):
    for p in root.rglob("*.py"):
        parts = set(p.parts)
        if parts & SKIP_DIRS:
            continue
        yield p


def _rel(p: Path, root: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def _scan_string_use(root: Path, name: str, home: str, limit: int = 6) -> list[dict]:
    """函数名以**字符串**出现在别处 ⇒ 可能是 `getattr` / 注册表 / 插件表 / entry points。

    ★ 只认字符串字面量，不认普通调用：普通调用由 `trace_note` 的 callers 负责。
    ★ 排除定义处所在文件 —— 它自己写 `def name` 时不会带引号，但同文件里可能有
      `logger.info("name ...")` 这种噪声，不排除会把每个函数都判成动态派发。
    """
    pat = re.compile(r"""["']%s["']""" % re.escape(name))
    hits = []
    for p in _iter_py(root):
        rel = _rel(p, root)
        if rel == home or _is_test(rel):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if name not in text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                # ★ 自测抓到：`__all__ = ["name"]` 与 `from x import name`
                #   里的字符串**语义与动态派发相反** —— 前者是"对外导出"，后者是"静态引入"。
                #   不排掉的话，一个正常导出的公开函数会被判成 dynamic_dispatch，
                #   把 `no_go` 翻成"继续追注册表"，正好是最贵的那类错。
                if "__all__" in line or re.match(r"^\s*(from|import)\s", line):
                    continue
                hits.append({"file": rel, "line": i, "text": line.strip()[:120]})
                if len(hits) >= limit:
                    return hits
    return hits


def _scan_export(root: Path, name: str, home: str, limit: int = 6) -> list[dict]:
    """名字被再导出 / 列进 `__all__` / 被别的模块 `from ... import name`。

    这是"公开 API"的直接证据 —— 比自己判断"看起来像公开"可靠。
    """
    imp = re.compile(r"^\s*from\s+\S+\s+import\s+(?:\(|[^#]*\b)%s\b" % re.escape(name))
    dunder = re.compile(r"__all__")
    quoted = re.compile(r"""["']%s["']""" % re.escape(name))
    hits = []
    for p in _iter_py(root):
        rel = _rel(p, root)
        if rel == home or _is_test(rel):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if name not in text:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if imp.match(line):
                hits.append({"file": rel, "line": i, "text": line.strip()[:120], "how": "from-import"})
            elif dunder.search(line) and quoted.search(line):
                hits.append({"file": rel, "line": i, "text": line.strip()[:120], "how": "__all__"})
            if len(hits) >= limit:
                return hits
    return hits


ROUTE_DEC = re.compile(
    r"\.(get|post|put|delete|patch|route|head|options|tool|websocket)\s*\(")


def _has_route_decorator(decs) -> bool:
    return any(ROUTE_DEC.search(str(d)) for d in (decs or []))


def classify(root, rel: str, line: int, note: dict | None = None,
             on_log=None, entry_kind: str | None = None) -> dict:
    """返回 {status, why, evidence[], calls_checked}。

    status ∈ has_callers / dynamic_dispatch / framework_callback /
             no_callers_public_api / no_callers_dead / unknown

    ★★ 第五态 `framework_callback` 是跑真数据才发现的：
      某一轮那 8 条 http 候选**全部**零调用方，被原四态判成 `no_callers_public_api`。
       `server.py:1609` 就是 `serve_spa` —— 它由 FastAPI 的 `@app.get("/{path:path}")` 调度，
       **本来就不该有 Python 调用方**。把它判成"对外 API"是语义错的：
       前者的值是开发者传的（⇒ no_go），后者的值是**网络上任何人**传的（⇒ 可能是真洞）。
       这一态的判据是**路由装饰器**，不是形态标签 —— 形态只用来限定"该不该往这上面想"。
    """
    root_p = Path(root)
    note = note or TN.build_note(root, rel, line)
    enc = note.get("enclosing") or {}
    out = {"status": "unknown", "why": "", "evidence": [],
           "name": enc.get("name") or (enc.get("qual") or "").rsplit(".", 1)[-1],
           "qual": enc.get("qual"),
           "callers_total": (note.get("callers") or {}).get("total", 0),
           "note_status": note.get("status")}

    if note.get("status") != "ok":
        out["why"] = "trace_note 没跑成（status=%s），调用方一个都没查" % note.get("status")
        return out
    # ★ `trace_note` 的 enclosing 不一定带 `name`（实测 trulens 那条只有 `qual`），
    #   从 qual 末段取，别让"字段名对不上"变成"判不了"。
    name = enc.get("name") or (enc.get("qual") or "").rsplit(".", 1)[-1]
    if not name:
        out["why"] = "连所在函数都没解析出来，四态都判不了"
        return out

    callers = note.get("callers") or {}
    strong = int(callers.get("strong") or 0)
    medium = int(callers.get("medium") or 0)
    if strong or medium:
        out["status"] = "has_callers"
        out["why"] = "有 %d 个可信调用方（strong=%d/medium=%d），不需要判零调用方的情形" % (
            strong + medium, strong, medium)
        for c in (callers.get("strong_calls") or []) + (callers.get("medium_calls") or []):
            out["evidence"].append({"file": c.get("file"), "line": c.get("line"),
                                    "text": str(c.get("call_expression") or "")[:120],
                                    "how": "caller"})
            if len(out["evidence"]) >= 3:
                break
        return out

    # ---- 以下都是「零可信调用方」----
    dyn = _scan_string_use(root_p, name, rel)
    if dyn:
        out["status"] = "dynamic_dispatch"
        out["why"] = ("仓库内没有直接调用，但函数名以字符串出现在 %d 处 ⇒ 可能走 getattr/注册表/插件表，"
                      "这条能继续追，不能按 no_go 收" % len(dyn))
        out["evidence"] = [{**d, "how": "string-ref"} for d in dyn]
        return out

    exports = _scan_export(root_p, name, rel)
    is_private = name.startswith("_") and not (name.startswith("__") and name.endswith("__"))

    decs = enc.get("decorators") or []
    if _has_route_decorator(decs) and (entry_kind in (None, "http", "mcp", "unknown")):
        out["status"] = "framework_callback"
        out["why"] = ("零调用方，但函数带路由/工具装饰器（%s）⇒ 由框架调度，"
                      "不是死代码、也不是「开发者调用」的公开 API。**值来自请求/模型调用方**。"
                      % "; ".join(str(d) for d in decs[:2]))
        out["evidence"] = [{"file": rel, "line": int(enc.get("line") or 0),
                            "text": str(decs[0])[:120], "how": "decorator"}]
        return out

    if is_private:
        out["status"] = "no_callers_dead"
        out["why"] = ("零调用方 + 名字以下划线开头（私有）+ 无字符串注册 ⇒ 按死代码处理。"
                      "★ 这是判据结论，不是证明：动态派发若用拼接名字（`getattr(x, 'a'+'b')`）扫不到。")
        out["evidence"] = []
        return out
    if exports:
        out["status"] = "no_callers_public_api"
        out["why"] = ("零调用方 + 名字公开 + 被再导出/列进 __all__（%d 处）⇒ 对外 API，"
                      "值由使用它的开发者提供" % len(exports))
        out["evidence"] = exports
        return out

    # 公开名但仓库内既无调用也无导出迹象
    out["status"] = "no_callers_public_api"
    out["why"] = ("零调用方 + 名字公开（不以 _ 开头）+ 无字符串注册 ⇒ 判为对外 API。"
                  "★ 弱判据：仓库内没找到 __all__/再导出，也可能只是没人用的公开函数；"
                  "要定死这一条，得看文档/README 或发布侧的 API 列表。")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="判零调用方的四态（死代码/公开 API/动态派发/有调用方）")
    ap.add_argument("--root", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--line", type=int, required=True)
    ap.add_argument("--entry-kind", default="",
                    help="http/mcp/cli/library; it decides the framework-callback state")
    ap.add_argument("--out", help="write the result as JSON")
    a = ap.parse_args()
    r = classify(a.root, a.file, a.line, on_log=print, entry_kind=(a.entry_kind or None))
    text = json.dumps(r, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
        print("wrote %s" % a.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
