# -*- coding: utf-8 -*-
"""`trace_entry_path` 自测：这一轮踩过的四个坑，每个一条断言。

跑法：python tools/selftest_trace_entry_path.py

★ 为什么自测要专门盯「不该发生的事」：
  这个工具的每一个 bug 都是**看起来很正常**的那种 ——
  装饰器认不出 → 结论变成"调用方都不是入口"（像"没有入口"）；
  方法 self 错位 → 链在第 1 层就断（像"追不到参数"）；
  同名撞车 → 链条绕回自己（像"追到底了"）；
  把表达式读成常量 → 结论"枪里没子弹"（像"假阳被排除了"）。
  **四个 bug 全都长得像正确答案。** 所以断言必须写成"必须是 X"，而不是"不能崩"。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from tools import trace_entry_path as T  # noqa: E402

npass = nfail = 0


def rec(name: str, cond: bool, detail: str = "") -> None:
    global npass, nfail
    if cond:
        npass += 1
        print("  [PASS] %s" % name)
    else:
        nfail += 1
        print("  [FAIL] %s   %s" % (name, detail))


def build(root: Path) -> None:
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "impl.py").write_text(
        "import os, tempfile\n\n"
        "def impl(v):\n"
        "    return eval(v)\n\n"
        "def impl2(v):\n"
        "    return os.system(v)\n\n"
        "def impl_const(v):\n"
        "    return os.system(v)\n\n"
        "def orphan(v):\n"
        "    return os.system(v)\n\n"
        "def uses_literal():\n"
        "    return impl_const('fixed string')\n\n"
        "def uses_factory():\n"
        "    d = tempfile.mkdtemp()\n"
        "    for i in range(3):\n"
        "        os.makedirs(os.path.join(d, str(i)))\n"
        "    return d\n",
        encoding="utf-8")
    (root / "pkg" / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "from .impl import impl, impl2\n\n"
        "app = FastMCP('demo')\n\n"
        "@app.tool(annotations={'x': 1})\n"
        "def tool_a(name: str) -> str:\n"
        "    return impl(name)\n\n"
        "def helper(v):\n"
        "    return impl2(v)\n\n"
        "@app.post('/run')\n"
        "def route_b(payload: str):\n"
        "    return helper(payload)\n",
        encoding="utf-8")
    (root / "pkg" / "cls.py").write_text(
        "import os\n\n"
        "class K:\n"
        "    def m(self, v):\n"
        "        return os.system(v)\n\n"
        "    def use(self, x):\n"
        "        return self.m(x)\n",
        encoding="utf-8")
    (root / "pkg" / "noise.py").write_text(
        "import os\n\n"
        "def unrelated(fd, mode):\n"
        "    return os.open(fd, mode)\n",
        encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text(
        "from pkg.impl import orphan\n\n"
        "def test_it():\n"
        "    assert orphan('tmp') is not None\n",
        encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        build(root)

        print("=== 1. one hop to the entry point (@mcp.tool, with arguments)===")
        r = T.trace(root, "pkg/impl.py", 4)
        print("    impl  -> %s  %s" % (r["verdict"], r.get("why", "")[:60]))
        rec("impl：追到 mcp 入口", r["verdict"] == "external", str(r.get("paths"))[:200])
        rec("impl：入口是 tool_a、kind=mcp",
            any(p.get("entry_kind") == "mcp" and p["caller"]["function"] == "tool_a"
                for p in r.get("paths") or []), str(r.get("paths"))[:200])

        print("=== 2. two hops to the entry point (tool -> helper -> sink)===")
        r = T.trace(root, "pkg/impl.py", 7)
        print("    impl2 -> %s  depth %s" % (r["verdict"], r.get("layers")))
        rec("impl2：两层后仍能追到入口", r["verdict"] == "external", str(r.get("paths"))[:200])
        rec("impl2：经过 helper 这一层",
            any(p.get("caller", {}).get("function") == "helper" for p in r.get("paths") or []),
            str([p.get("caller", {}).get("function") for p in r.get("paths") or []]))

        print("=== 3. called only with constants, so not external ===")
        r = T.trace(root, "pkg/impl.py", 10)
        print("    impl_const -> %s" % r["verdict"])
        rec("impl_const：不许判成 external", r["verdict"] != "external", r["verdict"])

        print("=== 4. no callers (calls from tests do not count)===")
        r = T.trace(root, "pkg/impl.py", 13)
        print("    orphan -> %s  skipped %s call(s) from tests"
              % (r["verdict"], r.get("skipped_test_calls", 0)))
        rec("orphan：判 no_caller（测试调用被跳过）",
            r["verdict"] == "no_caller" and r.get("skipped_test_calls") == 1,
            "%s / skipped=%s" % (r["verdict"], r.get("skipped_test_calls")))

        print("=== 5. ★ self in a method call does not take an argument slot ===")
        r = T.trace(root, "pkg/cls.py", 5)
        print("    K.m -> %s  tainted %s" % (r["verdict"], r.get("tainted_params")))
        rec("K.m：能回溯到 v（不是被 self 顶掉）", r.get("tainted_params") == ["v"],
            str(r.get("tainted_params")))
        rec("K.m：能追到 use 这一层",
            any(p.get("caller", {}).get("function") == "use" for p in r.get("paths") or []),
            str(r.get("paths"))[:200])

        print("=== 6. ★ same name must not leak across (os.open is neither method m nor builtin open)===")
        r = T.trace(root, "pkg/impl.py", 4)
        files = {p.get("caller", {}).get("file") for p in r.get("paths") or []}
        rec("impl 的路径里没有 noise.py", "pkg/noise.py" not in files, str(files))

        print("=== 7. ★ an expression is not a constant ===")
        r = T.trace(root, "pkg/impl.py", 21)
        print("    uses_factory -> %s" % r["verdict"])
        rec("内部工厂生成的值 → internal_generated",
            r["verdict"] == "internal_generated", r["verdict"])

        print("=== 8. when the depth runs out, say 'not finished', never 'unreachable'===")
        r = T.trace(root, "pkg/impl.py", 7, max_depth=1)
        print("    impl2 max_depth=1 -> %s" % r["verdict"])
        rec("层数用完 → exhausted（不是 constant / internal）",
            r["verdict"] == "exhausted", r["verdict"])

        print("\nresult: %d passed / %d failed" % (npass, nfail))
        return 0 if nfail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
