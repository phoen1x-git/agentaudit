"""对「存疑」档候选：**静态往上找调用方**，看能不能追出真正的入口。

★★ 为什么需要（这是 `docs/236` 第 1 条「把存疑 259 条变小」的零成本实现）：

  `tools/reachability_triage.py` 把 330 条分成「可达 / 存疑 / 不可达」，其中
  **259 条「存疑」** —— 它的判词是 `why`：「没看到 @tool / get_tools / HTTP 装饰器 / 微服务注册」。
  ★ **但这不等于"外面调不到"** —— sink 所在函数可能被**另一个挂了装饰器的函数**调用。

  ⇒ 本工具就做**那一跳**：在同一仓库的源码树里找「谁调用了这个函数」，
    再看**调用方自己有没有暴露标记**。追得到的，才值得送判定层（那要花钱）。

★ 成本：**0**（纯 AST，不调 LLM）。
★ 复用：`tools/resolve_needs_human_callers.py` 的 `find_callers`（不重造）。

用法：
    python tools/find_entries_for_suspects.py --project samplecomps
    python tools/find_entries_for_suspects.py --project samplecomps --tier vuln
    python tools/find_entries_for_suspects.py --all
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import resolve_needs_human_callers as R  # noqa: E402  复用 find_callers

TRIAGE = os.path.join(ROOT, "data", "target_pool", "reachability_triage.json")
OUT = os.path.join(ROOT, "data", "target_pool", "suspect_entry_probe.md")

# ★ 靶源码根目录（与 prepare_tp2x_targets 的落盘位置一致；找不到就跳过并如实报出来）
SRC_ROOTS = [
    os.path.join(ROOT, "..", "_targets", "tp2x_src"),
    os.path.join(ROOT, "..", "_targets", "a1src"),
]

# ★★ 测试代码识别（2026-10-14 加）—— 起因：实测发现 `find_callers` 找出来的"调用方"
#    经常是 `def test_handle_message(self)` 这种**单元测试**，而测试函数**永远不会有**产品入口标记
#    （`@tool` / `@app.route`）⇒ 会把"有调用方"这一档灌满噪声。
#    ★ 排除它们之后，"有调用方但没暴露"这一档才真的表示"**产品代码调用了它，但那个调用者没暴露**"。
TEST_PATH_PAT = re.compile(r"(^|/)(tests?|test_|__tests__|testing)/|(^|/)test_[^/]*\.py$|_test\.py$", re.I)
TEST_NAME_PAT = re.compile(r"^test_|^Test|_test$|Test$", re.I)


def is_test_code(rel: str, qual: str) -> bool:
    return bool(TEST_PATH_PAT.search(rel or "") or TEST_NAME_PAT.search(qual or ""))


# ★ "暴露标记"：调用方出现这些，就认为**它是一个入口**
EXPOSE_PAT = re.compile(
    r"@tool\b|@app\.(route|get|post|put|delete)|@router\.(get|post|put|delete)|"
    r"get_tools\s*\(|@register_microservice|@register_statistics|"
    r"FastAPI\s*\(|Flask\s*\(|@mcp\.|@server\.|def\s+(main|__init__)\s*\(|if\s+__name__\s*==",
    re.I,
)


def find_src_root(project: str):
    """在 SRC_ROOTS 里按项目短名模糊找源码根。"""
    key = re.sub(r"[^a-z0-9]", "", project.lower())
    for base in SRC_ROOTS:
        if not os.path.isdir(base):
            continue
        for d in os.listdir(base):
            dn = re.sub(r"[^a-z0-9]", "", d.lower())
            if key and (key in dn or dn.endswith(key)):
                p = os.path.join(base, d)
                if os.path.isdir(p):
                    return p
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default="", help="限定项目短名")
    ap.add_argument("--tier", default="all", choices=["all", "vuln", "needs_human"],
                    help="只看某一档的判定结果（默认全部）")
    ap.add_argument("--all", action="store_true", help="全部项目")
    ap.add_argument("--limit", type=int, default=0, help="每个项目最多看几条（0=不限）")
    a = ap.parse_args()

    tri = json.load(open(TRIAGE, encoding="utf-8"))
    sus = [r for r in tri if r["verdict"].startswith("?存疑")]
    if a.project and not a.all:
        sus = [r for r in sus if r["project"] == a.project]
    if a.tier != "all":
        sus = [r for r in sus if str(r.get("llm")) == a.tier]

    by_proj = collections.defaultdict(list)
    for r in sus:
        by_proj[r["project"]].append(r)

    L = ["# 「存疑」档：静态追入口的探测结果\n",
         "> ★ 零成本（纯 AST）。**只回答一个问题**：sink 所在函数**有没有调用方**，",
         "> 以及**那个调用方自己挂没挂暴露标记**。",
         "> ★ 追得到 ⇒ 这一条**值得送判定层**（那一步才花钱）；追不到 ⇒ 大概率真的调不到。\n"]

    tot = collections.Counter()
    for proj, rows in sorted(by_proj.items(), key=lambda kv: -len(kv[1])):
        root = find_src_root(proj)
        L.append(f"## {proj}（{len(rows)} 条）" + ("" if root else "  ⚠️ **找不到源码根，跳过**"))
        if not root:
            tot["no_src"] += len(rows)
            L.append("")
            continue
        hit_entry, hit_call, miss = [], [], []
        for r in (rows[:a.limit] if a.limit else rows):
            entry = (r.get("fn") or r.get("chain") or "").split("<")[0].strip()
            if not entry:
                miss.append((r, "没有函数名"))
                continue
            try:
                callers = R.find_callers(root, entry, r.get("file") or "", limit=6)
            except Exception as e:
                miss.append((r, f"find_callers 异常 {type(e).__name__}"))
                continue
            if not callers:
                miss.append((r, "找不到调用方"))
                continue
            # ★★★ 2026-10-14 修 bug：`find_callers` 返回的源码字段叫 **`body`**，
            #   我原先写成 `c.get("src")` ⇒ 取到 None ⇒ **暴露标记永远匹配不到**，
            #   于是"调用方直接有暴露标记 = 0"这个结论**是被 bug 造出来的**。
            #   ★ 教训：跨模块复用别人返回的 dict 时，**字段名要用打印/断言核一遍**，别按印象写。
            # ★★ 先剔除**测试代码**（否则"有调用方"这一档全是 `def test_xxx` 的噪声 —— 实测踩到）
            prod = [c for c in callers
                    if not is_test_code(c.get("file") or "", c.get("qual") or "")]
            if not prod:
                miss.append((r, "★ 只有测试代码调用它（= 没有产品入口）"))
                tot["only_test"] += 1
                continue
            exposed = [c for c in prod if EXPOSE_PAT.search(c.get("body") or "")]
            (hit_entry if exposed else hit_call).append((r, prod, exposed))
            tot["entry" if exposed else "caller"] += 1
        tot["miss"] += len(miss)
        tot["total"] += len(rows)
        L.append(f"- ★ **调用方本身就挂暴露标记**（⇒ 强候选）：**{len(hit_entry)}**")
        L.append(f"- 有**产品**调用方、但调用方也没暴露标记（⇒ 要再往上一层）：**{len(hit_call)}**")
        L.append(f"- 找不到调用方 / 只有测试代码调它（⇒ 大概率真调不到）：**{len(miss)}**")
        L.append("")
        for r, callers, exposed in hit_entry[:10]:
            L.append(f"  - ★ `{r['fp']}`  sink={r['sink']}  entry=`{r.get('fn')}`")
            L.append(f"    调用方：`{exposed[0].get('qual') or exposed[0].get('rel') or '?'}`")
        L.append("")

    L.append("## 合计\n")
    L.append(f"- 总计看过：**{tot['total']}** 条")
    L.append(f"- ★ **调用方直接有暴露标记**：**{tot['entry']}** 条 ← **这些最值得送判定层**")
    L.append(f"- 有调用方但没暴露标记：**{tot['caller']}** 条（要再往上追一层）")
    L.append(f"- 找不到调用方 / 只有测试代码调它：**{tot['miss']}** 条（大概率确实调不到）")
    if tot["only_test"]:
        L.append(f"  ★ 其中 **{tot['only_test']}** 条是「**只有测试代码调用它**」"
                 "（★ 这是最强的一类排除：测试不等于入口）")
    if tot["no_src"]:
        L.append(f"- ⚠️ 因找不到源码根而跳过：**{tot['no_src']}** 条")
    L.append("")
    L.append("★ 口径提醒：**「找不到调用方」不等于「不可达」** —— "
             "它只说明**按名字匹配**的 AST 追不到（跨文件 / 动态调用 / 同名会漏）。")

    md = "\n".join(L) + "\n"
    open(OUT, "w", encoding="utf-8").write(md)
    print(md)
    print("写出:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
