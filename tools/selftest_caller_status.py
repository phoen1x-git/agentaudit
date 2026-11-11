# -*- coding: utf-8 -*-
"""`tools/caller_status.py` 的自测：四态各来一个能构造的样例，外加两条"不许误判"。

★ 为什么必须自测：四态的每一种都会直接改结论方向（死代码丢弃 / 公开 API 判 no_go /
  动态派发继续追）。判错不会报错，只会安静地把一条洞丢掉或者把一条死代码立案。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import caller_status as CS     # noqa: E402

n_pass = n_fail = 0


def rec(name: str, ok: bool, detail: str = "") -> None:
    global n_pass, n_fail
    if ok:
        n_pass += 1
        print("  OK   %s" % name)
    else:
        n_fail += 1
        print("  FAIL %s   %s" % (name, detail))


def build(root: Path) -> None:
    (root / "pkg").mkdir(parents=True, exist_ok=True)
    # ① 有调用方
    (root / "pkg" / "called.py").write_text(
        "def used(x):\n    return eval(x)\n\n\ndef go(v):\n    return used(v)\n", encoding="utf-8")
    # ② 公开名、零调用、有再导出 → public_api（强证据）
    (root / "pkg" / "exported.py").write_text(
        "def re_exported(x):\n    return eval(x)\n", encoding="utf-8")
    (root / "pkg" / "__init__.py").write_text(
        "from .exported import re_exported\n\n__all__ = [\"re_exported\"]\n", encoding="utf-8")
    # ③ 私有名、零调用 → dead
    (root / "pkg" / "priv.py").write_text(
        "def _hidden(x):\n    return eval(x)\n", encoding="utf-8")
    # ④ 名字以字符串出现在注册表 → dynamic_dispatch
    (root / "pkg" / "reg.py").write_text(
        "def dynamic_one(x):\n    return eval(x)\n", encoding="utf-8")
    (root / "pkg" / "table.py").write_text(
        "REGISTRY = {}\n\n\ndef register(name, fn):\n    REGISTRY[name] = fn\n\n\nregister(\"dynamic_one\", None)\n",
        encoding="utf-8")
    # ⑤ 公开名但什么都没 → public_api（弱判据，必须写明是弱判据）
    (root / "pkg" / "lonely.py").write_text(
        "def lonely_public(x):\n    return eval(x)\n", encoding="utf-8")
    # ⑥ http handler：零调用方，但带路由装饰器 → framework_callback
    (root / "pkg" / "route.py").write_text(
        "def deco(p):\n    return lambda f: f\n\n\n@deco.get('/x')\n"
        "def handler(x):\n    return eval(x)\n", encoding="utf-8")


print("caller_status 自测")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    build(root)

    r = CS.classify(root, "pkg/called.py", 2)
    rec("有调用方 → has_callers", r["status"] == "has_callers", str(r))
    rec("has_callers 带得出调用点", bool(r.get("evidence")), str(r.get("evidence")))

    r = CS.classify(root, "pkg/exported.py", 2)
    rec("零调用 + __all__ 再导出 → public_api", r["status"] == "no_callers_public_api", str(r))
    rec("public_api 的证据能指到 __init__.py",
        any("__init__.py" in (e.get("file") or "") for e in r.get("evidence") or []),
        str(r.get("evidence")))

    r = CS.classify(root, "pkg/priv.py", 2)
    rec("零调用 + 下划线私有 → 死代码", r["status"] == "no_callers_dead", str(r))

    r = CS.classify(root, "pkg/reg.py", 2)
    rec("名字以字符串进注册表 → dynamic_dispatch", r["status"] == "dynamic_dispatch", str(r))
    rec("dynamic_dispatch 的证据指向注册处",
        any("table.py" in (e.get("file") or "") for e in r.get("evidence") or []),
        str(r.get("evidence")))

    r = CS.classify(root, "pkg/lonely.py", 2)
    rec("零调用 + 公开名 + 无导出 → public_api（并在 why 里注明是弱判据）",
        r["status"] == "no_callers_public_api" and "弱判据" in r["why"], str(r))

    # ⑥ 文件不存在 → 必须报 unknown，不许猜
    r = CS.classify(root, "pkg/nope.py", 2)
    rec("文件不存在 → unknown（不猜）", r["status"] == "unknown", str(r))

    # ⑦ 带路由装饰器的零调用方函数 → framework_callback（不是 public_api）
    r = CS.classify(root, "pkg/route.py", 7, entry_kind="http")
    rec("http handler（带路由装饰器）→ framework_callback",
        r["status"] == "framework_callback", str(r))
    rec("framework_callback 的证据指向装饰器",
        any(e.get("how") == "decorator" for e in r.get("evidence") or []), str(r.get("evidence")))

    # ⑧ 反例：库形态下同样的装饰器形状，不该被当成框架回调
    r = CS.classify(root, "pkg/route.py", 7, entry_kind="library")
    rec("library 形态下不判 framework_callback",
        r["status"] != "framework_callback", str(r))

print("-" * 60)
print("结果：%d 通过 / %d 失败" % (n_pass, n_fail))
sys.exit(1 if n_fail else 0)
