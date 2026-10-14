# -*- coding: utf-8 -*-
"""生成 `tools/INDEX.md` —— 183 个工具的一页索引。

★ 为什么要它：工具数已经到 183，**"我记得有个脚本能…"是找不到的**。
  这个索引回答两件事：
    ① **我该用哪个？** → 顶部的「常用入口」（人工维护，按任务场景列）
    ② **这个文件是干什么的？** → 下面的自动表（标题 + CLI 参数 + 行数 + 日期）

★ 自动化程度（刻意）：**标题和参数自动抓**（从 docstring / argparse），
  但「常用入口」那一段是**手写的** —— 因为"什么时候该用它"这件事，代码里读不出来。

用法：
    python tools/make_tool_index.py            # 生成 tools/INDEX.md
    python tools/make_tool_index.py --check    # 只报"和现有 INDEX 差多少"，不写文件
"""
from __future__ import annotations

import argparse
import ast
import glob
import os
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
OUT = TOOLS / "INDEX.md"

# ★ 手写：按**任务场景**列常用入口（这才是"该用哪个"的答案）
PRIMARY = [
    ("app/run_all.py", "★ 一键入口：prepare → scan → report → 账本（支持断点续跑）"),
    ("app/run_round.py", "单轮：静态候选 + LLM 判定 + 两个台账（`--tag` / `--only` / `--targets-file`）"),
    ("app/make_report.py", "把某轮的 `findings.tsv` 出成 `report_draft.md`"),
    ("app/prepare_targets.py", "下载源码 + 建 CodeQL 库，并写目标表 yml"),
    ("tools/target_audit.py", "★ 选靶体检：`--axis recent`(HOT/WARM/COLD) / `--axis all`(干净/已审)"),
    ("core/candidate_ledger.py", "★ 候选台账：`list --status todo` / `show <指纹>` / `mark` / `stats`"),
    ("tools/rejudge_rows.py", "三关①：对指定行复判（★ 每轮换 `--tag` 防缓存假稳定）"),
    ("tools/resolve_needs_human_callers.py", "三关①的加强版（路B）：补调用方上下文再复判"),
    ("tools/check_candidate_alive.py", "三关③：查靶存活（归档/停维护）"),
    ("core/gh.py", "三关②：GitHub 查询封装（带 token）"),
    ("tools/check_disclosures.py", "★ 披露跟踪：已报 issue 状态 + 邮件渠道表"),
    ("tools/eval_gt_linehit.py", "语料真值核检出（`--neg` 同时核假阳）"),
    ("tools/gt_attribution.py", "六类归因：HIT / BLOCKED / STALE / MISS / ABSENT"),
    ("tools/make_onepager.py", "一页纸（★ 只读 findings 字段；含实跑/上游核查的要手写）"),
    ("tools/ab_sources_probe.py", "source 表 / 属性传播的 A/B 探针（四臂）"),
    ("tools/ab_sources_selftest.py", "★ A/B 的**正向自检**：造「按定义一定该命中」的样本"),
    ("tools/verify_*.py", "★ 实跑复现脚本（每个候选一个，例：verify_samplewebapp_traversal.py）"),
    ("tools/coverage_codeql_models.py", "CodeQL 内置模型对靶的覆盖率（找「框架中介」缺口）"),
    ("tools/watchdog_check.py", "夜班第 0 步：判 A(有人在跑)/B(断链)/C(卡住)"),
    ("tools/make_tool_index.py", "★ 生成本文件"),
]


def first_line(p: Path) -> str:
    """取 docstring 的第一个非空行当标题（去掉 `#`/`★` 前缀噪声）。"""
    try:
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        doc = ast.get_docstring(tree) or ""
    except (SyntaxError, OSError):
        doc = ""
    for ln in doc.splitlines():
        t = re.sub(r"^[\s#*★·\-]+", "", ln).strip()
        if t:
            return t[:120]
    # 退化：找第一行真注释
    try:
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()[:12]:
            t = ln.strip()
            if t.startswith("#") and len(t) > 3 and "coding" not in t:
                return re.sub(r"^#+\s*", "", t)[:120]
    except OSError:
        pass
    return ""


def flags(p: Path) -> str:
    try:
        src = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    fs = re.findall(r'add_argument\(\s*"(--[A-Za-z0-9_.\-]+)"', src)
    seen, out = set(), []
    for f in fs:
        if f not in seen:
            seen.add(f)
            out.append(f)
    if not out:
        return ""
    s = " ".join(out[:6])
    return s + (" …" if len(out) > 6 else "")


def row(p: Path) -> str:
    try:
        lines = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
    except OSError:
        lines = 0
    d = datetime.fromtimestamp(p.stat().st_mtime).strftime("%m-%d")
    return (f"| `{p.name}` | {first_line(p) or '（无说明）'} | "
            f"{('`' + flags(p) + '`') if flags(p) else ''} | {lines} | {d} |")


def build() -> str:
    files = sorted(TOOLS.glob("*.py"), key=lambda p: p.name)
    dep = sorted((TOOLS / "_deprecated").glob("*.py")) if (TOOLS / "_deprecated").is_dir() else []
    L: list[str] = []
    L.append("# tools/INDEX.md —— 工具索引（自动生成，别手改）")
    L.append("")
    L.append(f"> 生成：{datetime.now().strftime('%Y-%m-%d %H:%M')} ｜ "
             f"`tools/*.py` **{len(files)}** 个 ｜ 生成器：`tools/make_tool_index.py`")
    L.append(">")
    L.append("> ★ 本文件由脚本生成：**改内容请改工具自己的 docstring**，然后重跑 "
             "`python tools/make_tool_index.py`。")
    L.append("")
    L.append("## 一、常用入口（★ 手写，按任务场景 —— 先在这里找）")
    L.append("")
    L.append("| 脚本 | 什么时候用它 |")
    L.append("|---|---|")
    for name, why in PRIMARY:
        L.append(f"| `{name}` | {why} |")
    L.append("")
    L.append("★ 没在本表里的，往下看第二节按文件名找。")
    L.append("")
    L.append(f"## 二、全部工具（{len(files)} 个，按文件名）")
    L.append("")
    L.append("| 文件 | 说明（docstring 首行） | 主要参数 | 行数 | 改于 |")
    L.append("|---|---|---|---|---|")
    for p in files:
        L.append(row(p))
    if dep:
        L.append("")
        L.append(f"## 三、已退役（`tools/_deprecated/`，{len(dep)} 个，只搬不删）")
        L.append("")
        L.append("| 文件 | 说明 | 行数 |")
        L.append("|---|---|---|")
        for p in dep:
            n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
            L.append(f"| `{p.name}` | {first_line(p) or '（无说明）'} | {n} |")
        L.append("")
        L.append("★ 规矩见 `tools/_deprecated/README.md`。")
    L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只报差异，不写文件")
    a = ap.parse_args()
    new = build()
    old = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
    if a.check:
        nl, ol = new.count("\n"), old.count("\n")
        print(f"现有 {ol} 行 ｜ 新生成 {nl} 行 ｜ 差异 {abs(nl - ol)} 行"
              f" ｜ {'一致' if new == old else '★ 不一致（重跑不带 --check 即可更新）'}")
        return 0
    OUT.write_text(new, encoding="utf-8")
    print(f"已写入 {OUT}（{new.count(chr(10)) + 1} 行）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
