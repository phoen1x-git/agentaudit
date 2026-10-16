"""『目标短名 → 目标源码根目录』的映射 + 把 findings 里的相对路径解析成真实路径。

★★ 为什么单独抽出来（而不是散在各工具里）：
   原来这段逻辑住在 `an early script`，而那个文件**写死了我们自己的目标**，
   所以**不能随包发布**。但 `judge_round` / `rejudge_rows` / `resolve_needs_human_callers`
   都要用它 ⇒ 抽成一个**通用、可配置**的小模块。

★ 配置方式（都不进版本库）：
   1. `core/config/targets*.yml` —— 权威来源，形如：
          targets:
            <你给目标起的短名>:
              repo: owner/name
              src: ../_targets/owner__name
   2. 环境变量 `AF_TARGET_MAP=/path/to/map.json` —— 形如 `{"短名": "源码根绝对路径"}`

★ 本模块**不内置任何具体目标**。
"""
from __future__ import annotations

import glob
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _from_yml() -> dict[str, str]:
    """从 `core/config/targets*.yml` 读『短名 → 源码根』。"""
    m: dict[str, str] = {}
    for y in glob.glob(os.path.join(ROOT, "core", "config", "targets*.yml")):
        try:
            txt = open(y, encoding="utf-8").read().splitlines()
        except Exception:
            continue
        cur = None
        for ln in txt:
            mo = re.match(r"^  ([A-Za-z_.\-]+):\s*$", ln)
            if mo:
                cur = mo.group(1)
                continue
            ms = re.match(r"^\s+src:\s*(\S+)\s*$", ln)
            if ms and cur:
                p = ms.group(1).replace("/", os.sep)
                if not os.path.isabs(p):
                    p = os.path.normpath(os.path.join(ROOT, p))
                m.setdefault(cur, p)
                cur = None
    return m


def _from_json_env() -> dict[str, str]:
    p = os.environ.get("AF_TARGET_MAP", "")
    if not p or not os.path.exists(p):
        return {}
    try:
        d = json.load(open(p, encoding="utf-8"))
        return {str(k): str(v) for k, v in d.items()} if isinstance(d, dict) else {}
    except Exception:
        return {}


def load_src_map() -> dict[str, str]:
    m = _from_yml()
    m.update(_from_json_env())          # 环境变量优先
    return m


_SRC_MAP: dict[str, str] = load_src_map()


def _resolve_src(r: dict) -> str | None:
    """把 findings 里的相对 `file` 解析成目标源码真实路径。

    ① 直接命中 → ② 去版本后缀（`x-1_2_3` → `x`）→ ③ 前缀模糊；
    都失败则按 basename 在候选根里搜。
    ★ 没有任何候选根时返回 `None`（调用方应自己处理）。
    """
    rel = (r.get("file") or "").replace("\\", "/")
    if not rel:
        return None
    proj = (r.get("project") or "").strip().lower()

    roots: list[str] = []
    if proj in _SRC_MAP:
        roots.append(_SRC_MAP[proj])
    base = re.split(r"[-_]\d", proj)[0]
    if base and base in _SRC_MAP and _SRC_MAP[base] not in roots:
        roots.append(_SRC_MAP[base])
    for k, v in _SRC_MAP.items():
        if v in roots:
            continue
        if proj and (proj.startswith(k) or k.startswith(base or proj)):
            roots.append(v)

    for root in roots:
        p = os.path.join(root, rel)
        if os.path.exists(p):
            return p
    base_name = os.path.basename(rel)
    for root in roots:
        for dp, _dn, fn in os.walk(root):
            if base_name in fn:
                return os.path.join(dp, base_name)
    return None
