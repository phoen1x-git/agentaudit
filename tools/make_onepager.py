"""Render a one-page evidence pack for a single finding (docs/123 + docs/128 format).

Usage:
  python tools/make_onepager.py out/round-batch3 --pick "file.py:123"
  python tools/make_onepager.py out/round-batch3 --verdict vuln
  python tools/make_onepager.py out/round-batch3 --top 5
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(rd: Path):
    f = rd / "findings.json"
    if not f.exists():
        return []
    d = json.load(open(f, encoding="utf-8"))
    return d if isinstance(d, list) else list(d.values())


def _src_window(rd: Path, row: dict) -> str:
    """Pull a few lines around the sink from the cached source, if present."""
    proj = row.get("project") or ""
    rel = row.get("file") or ""
    line = row.get("line")
    if not (proj and rel and line):
        return ""
    for base in (ROOT.parent / "_targets" / "a1src", ROOT.parent / "_targets"):
        for p in base.glob(f"*{proj}*"):
            f = p / rel
            if f.exists():
                try:
                    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
                except Exception:
                    continue
                lo = max(0, int(line) - 12)
                hi = min(len(lines), int(line) + 8)
                out = []
                for i in range(lo, hi):
                    mark = "→" if i + 1 == int(line) else " "
                    out.append(f"{mark}{i+1:5}  {lines[i]}")
                return "\n".join(out)
    return ""


def render(rd: Path, row: dict) -> str:
    loc = f"{row.get('file')}:{row.get('line')}"
    L = []
    L.append(f"# 一页纸 · {row.get('project')} · `{loc}`")
    L.append("")
    L.append("## 0. 档案标记")
    L.append(f"- **结论**：`{row.get('ai_verdict')}`（AI 置信度 {row.get('conf')}）")
    L.append(f"- **Go / Maybe**：（待我填）")
    L.append(f"- **sink**：`{row.get('sink')}` ｜ **入口函数**：`{row.get('entry')}` ｜ **调用链深度** {row.get('depth')}")
    L.append(f"- **字段**：by_design=`{row.get('by_design')}` scope_exceeds=`{row.get('scope_exceeds')}` "
             f"guards_real=`{row.get('guards_real')}` arg_source=`{row.get('arg_source')}`")
    L.append("")
    L.append("## 1. 一句话：这条是什么")
    L.append("（待填：大白话，不从术语开始）")
    L.append("")
    L.append("## 2. 为什么我认为是真的")
    L.append(f"**AI 判定理由**：{row.get('ai_reason')}")
    L.append("")
    L.append("```")
    L.append(_src_window(rd, row) or (row.get("snippet") or ""))
    L.append("```")
    L.append("")
    L.append(f"**调用链**：`{row.get('chain')}`")
    L.append("")
    L.append("## 3. 你要核对的 3 件事")
    L.append("1. （待填）")
    L.append("2. （待填）")
    L.append("3. （待填）")
    L.append("")
    L.append("## 4. 这次要学的一件事")
    L.append("- **这类缺陷是什么**：")
    L.append("- **为什么这个参数危险**：")
    L.append("- **守卫长什么样**（正例对照）：")
    L.append("- **下次你自己怎么快速判断**：")
    L.append("")
    L.append("## 5. 证据附录")
    gl = row.get("guards_list")
    if isinstance(gl, str):
        try:
            gl = json.loads(gl)
        except Exception:
            pass
    L.append(f"- **守卫行（{row.get('guards')} 条）**：")
    for g in (gl or [])[:6]:
        L.append(f"  - `{g}`")
    L.append(f"- **实参来源**：`{row.get('arg_source')}`")
    L.append(f"- **fingerprint**：`{row.get('fingerprint')}`")
    L.append("")
    L.append("## 6. 英文报告草稿")
    L.append("（待填）")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("round_dir")
    ap.add_argument("--pick", default="", help="file:line")
    ap.add_argument("--verdict", default="")
    ap.add_argument("--top", type=int, default=0)
    a = ap.parse_args()
    rd = Path(a.round_dir)
    rows = load(rd)
    if not rows:
        print(f"no findings.json in {rd}")
        return 1
    sel = rows
    if a.pick:
        sel = [r for r in sel if f"{r.get('file')}:{r.get('line')}" == a.pick]
    if a.verdict:
        sel = [r for r in sel if r.get("ai_verdict") == a.verdict]
    if a.top:
        sel = sel[: a.top]
    if not sel:
        print("no match")
        return 1
    for r in sel:
        print(render(rd, r))
        print("\n" + "=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
