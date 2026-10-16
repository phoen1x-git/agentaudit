"""Kernel: config loading and path filtering.

The path filter replaces the baseline's plain substring blacklist with three layers:
path segments, filename regexes, and substrings. Set AF_NO_FILTER=1 to switch it off
for an A/B comparison.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

_CFG_DIR = Path(__file__).resolve().parent / "config"


def load_yaml(name: str) -> dict:
    p = _CFG_DIR / name
    with open(p, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_filters() -> dict:
    return load_yaml("filters.yml")


def load_sinks() -> dict:
    return load_yaml("sinks.yml")



def path_is_filtered(rel_path: str, filters: dict) -> bool:
    """rel_path 用 / 分隔。命中任一规则 → True（这条结果不交给人看）。"""
    if os.environ.get("AF_NO_FILTER", "0") == "1":
        return False                      # ★ for A/B：关掉 path-filter
    if not rel_path:
        return False
    low = rel_path.lower().replace("\\", "/")
    segs = [s for s in low.split("/") if s]
    # ① 路径段精确匹配
    black_segs = {s.lower() for s in filters.get("path_segments", [])}
    if any(s in black_segs for s in segs):
        return True
    # ② 文件名正则
    base = segs[-1] if segs else ""
    for pat in filters.get("filename_re", []):
        if re.match(pat, base):
            return True
    # ③ AgentFuzz baseline的子串兜底
    for sub in filters.get("substrings", []):
        if sub.lower() in low:
            return True
    return False
