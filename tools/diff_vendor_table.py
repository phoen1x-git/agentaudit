# -*- coding: utf-8 -*-
"""比对 TaintP2X 的 source/sink 表 ↔ 我们的 sinks.yml / sources.yml。

★ 用途（docs/131 §七 优先级 1）：TaintP2X（Apache 2.0）公开了 LLM provider 的
  **精确调用路径**与 5 大类 sink 定义；我们自己的 source 只是"方法名近似"。
  本工具**只做差异报告、不改行为** —— 真正的合并是一次单变量改动（要同报稳定性+刻度）。

    python tools/diff_vendor_table.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "data" / "vendor_taintp2x"
_DEF = re.compile(r"^\s*def\s+([A-Za-z_][\w.]*)\s*\(", re.M)
_TAG = re.compile(r"Taint(Sink|Source)\[\s*(\w+)\s*\]")


def parse_pysa(p: Path):
    """→ [(dotted, kind, tag)]，kind ∈ {sink, source}。"""
    txt = p.read_text(encoding="utf-8", errors="replace")
    tag = _TAG.search(txt)
    kind = "source" if p.name == "llms_sources.pysa" else "sink"
    out = []
    for m in _DEF.finditer(txt):
        out.append((m.group(1), kind, tag.group(2) if tag else ""))
    return out


def vendor_calls():
    sink, source = [], []
    for p in sorted(VENDOR.glob("*.pysa")):
        for dotted, kind, tag in parse_pysa(p):
            (source if kind == "source" else sink).append((dotted, tag, p.name))
    return sink, source


def ours():
    sk = yaml.safe_load((ROOT / "core" / "config" / "sinks.yml").read_text(encoding="utf-8"))
    so = yaml.safe_load((ROOT / "core" / "config" / "sources.yml").read_text(encoding="utf-8"))
    sink_names, sink_objs = set(), set()
    for s in sk["sinks"]:
        if s.get("func"):
            sink_names.add(str(s["func"]).lower())
        if s.get("name"):
            sink_names.add(str(s["name"]).lower())
        for k in ("obj", "obj_suffix"):
            if s.get(k):
                sink_objs.add(str(s[k]).lower())
    src_names, src_objs = set(), set()
    for s in so["sources"]:
        for n in (s.get("names") or []):
            src_names.add(str(n).lower())
        for k in ("obj", "obj_suffix"):
            if s.get(k):
                src_objs.add(str(s[k]).lower())
    return sink_names, sink_objs, src_names, src_objs


def main() -> int:
    sink, source = vendor_calls()
    s_names, s_objs, src_names, src_objs = ours()

    print(f"vendor：sink 定义 {len(sink)} 条 / source 定义 {len(source)} 条")
    print(f"ours  ：sink 名 {sorted(s_names)} / obj {sorted(s_objs)}")
    print(f"        source 名 {sorted(src_names)}")

    print("\n=== sink：vendor 有、我们**没有**的功能名（按 tag 归类）===")
    miss: dict[str, set] = {}
    for dotted, tag, f in sink:
        func = dotted.split(".")[-1]
        if func.lower() not in s_names:
            miss.setdefault(tag, set()).add(dotted)
    for tag, items in sorted(miss.items(), key=lambda kv: -len(kv[1])):
        print(f"\n[{tag}] 缺 {len(items)} 条：")
        for x in sorted(items)[:60]:
            print("   ", x)

    print("\n=== source：vendor 的 provider 模块（我们按方法名近似，未按模块区分）===")
    mods = sorted({d.split(".")[0] for d, _, _ in source})
    print("   模块:", mods)
    meths = sorted({d.split(".")[-1] for d, _, _ in source})
    print("   方法:", meths)
    print("   ★ 我们没有的 provider 模块:", [m for m in mods
                                              if m.lower() not in src_objs])

    out = ROOT / "data" / "target_pool" / "_vendor_diff.json"
    out.write_text(__import__("json").dumps(
        {"sink_total": len(sink), "source_total": len(source),
         "missing_sink_by_tag": {k: sorted(v) for k, v in miss.items()},
         "source_modules": mods, "source_methods": meths},
        ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n→ {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
