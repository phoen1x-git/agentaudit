# -*- coding: utf-8 -*-
"""★ 已合并（2026-10-13 · P4 技术债）—— 本文件只是**兼容入口**，不实现任何逻辑。

真正的实现搬到 `tools/target_audit.py`，用 `--axis` 选口径：
  · `--axis recent`  = **本文件原来的行为**（近 N 天 + 批量审计特征 → HOT/WARM/COLD）
  · `--axis all`     = 另一个轴（全时间 `in:title security` → 干净/已审）

★ 为什么合并：两个近同名工具**问的不是同一个问题**，谁该跑容易搞混。
  ★ 注意：合并前我一度在 `docs/220/221` 写它们"功能重叠" —— **那句是错的**，
  它们是**同一工具的两个轴**（查询口径不同），现已更正。

旧命令照旧可用（参数原样转发）：
    python tools/target_audit_scan.py --yml core/config/targets_tp2x.yml --days 90
等价于：
    python tools/target_audit.py --axis recent --yml core/config/targets_tp2x.yml --days 90
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "tools" / "target_audit.py"

arg = sys.argv[1] if len(sys.argv) > 1 else ""
if arg in ("-h", "--help"):
    # help 走合并版自己的帮助（信息更全）
    sys.exit(subprocess.call([sys.executable, str(TARGET), "--help"]))

print("★ [已合并] tools/target_audit_scan.py → tools/target_audit.py --axis recent", file=sys.stderr)
rest = sys.argv[1:]
if "--axis" not in rest:
    rest = ["--axis", "recent"] + rest
sys.exit(subprocess.call([sys.executable, str(TARGET)] + rest))
