#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""判据版本锁：防止「改了判据，却拿旧代码跑出来的数字出结论」。

★ 这条纪律是被逼出来的（2026-10-05 06:46）
----------------------------------------------------
06:40 启动 4 个重核分片 → 06:42 我在核实 trinity 时发现两个新问题，
当场改了 tools/ast_criteria.py（第 7 种写法 + ensure 词根修正）
→ 06:46 发现已经跑出来的 3 条记录**是旧代码的结果**。

★ 危险的地方在于它**看起来完全正常**：
  数字有、覆盖率有、证据有 —— 只是判据版本不对。
  如果不查，报告里就会出现"用旧判据跑出的新数字"。

用法：
    # 1) 批处理开始前打戳（recheck.py 会自动调）
    python tools/criteria_ver.py stamp

    # 2) 随时查当前代码 vs 各批次产出
    python tools/criteria_ver.py check

    # 3) 改了判据之后
    python tools/criteria_ver.py status
"""
import hashlib
import json
import os
import sys
import glob
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
POOL = os.path.join(ROOT, "data", "target_pool")
CRITERIA = os.path.join(HERE, "ast_criteria.py")
LOCK = os.path.join(POOL, "criteria_version.json")


def criteria_hash():
    """★ 只对 ast_criteria.py 的**内容**取哈希，不含 mtime。

    ★ 为什么不用 mtime：编辑器保存一次可能只改一行，
    用 mtime 会让"没改内容"也判定为"变了" → 全部批次作废 → 白重跑。
    """
    with open(CRITERIA, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def stamp():
    h = criteria_hash()
    os.makedirs(POOL, exist_ok=True)
    old = read_lock()
    data = {
        "hash": h,
        "stamped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "prev_hash": (old or {}).get("hash"),
    }
    with open(LOCK, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print("判据版本已记录: %s  (%s)" % (h, data["stamped_at"]))
    if data["prev_hash"] and data["prev_hash"] != h:
        print("  ★ 判据已改动 %s → %s" % (data["prev_hash"], h))
        print("  ★ **之前用旧判据跑出来的批次全部作废，需重跑**")
    return h


def read_lock():
    if not os.path.exists(LOCK):
        return None
    try:
        return json.load(open(LOCK, encoding="utf-8"))
    except Exception:
        return None


def _batches():
    """列出所有重核产出文件及其 mtime。"""
    out = []
    for pat in ("rc_v*_partial.jsonl", "rc_v*.json", "rc_rest*.jsonl"):
        for p in glob.glob(os.path.join(POOL, pat)):
            out.append((os.path.basename(p), os.path.getmtime(p)))
    return sorted(out)


def check():
    cur = criteria_hash()
    lock = read_lock()
    print("当前 ast_criteria.py 哈希: %s" % cur)
    if not lock:
        print("★ 没有版本记录（还没 stamp 过）—— 无法判断批次是否失效")
        return 2
    print("记录时的哈希          : %s  (%s)" % (lock.get("hash"), lock.get("stamped_at")))
    if lock.get("hash") == cur:
        print("→ 一致。批次产出可用。")
        return 0
    print("→ ★★ 不一致：判据在 stamp 之后被改过。")
    print("   下面这些批次是**旧判据**跑的，不能用来出结论：")
    for name, mt in _batches():
        print("     %-28s %s" % (name, time.strftime("%m-%d %H:%M", time.localtime(mt))))
    return 1


def status():
    """给recheck.py 用的轻量接口：返回当前哈希。"""
    print(criteria_hash())
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    fn = {"stamp": stamp, "check": check, "status": status}.get(cmd)
    if not fn:
        print(__doc__)
        sys.exit(2)
    sys.exit(fn() or 0)
