# -*- coding: utf-8 -*-
"""重建 core/config/targets_a1.yml：扫 `_targets/a1db/*-db` + 从所有 `a1_batch*.json` 反查 repo。

★ 与 `app/prepare_targets.py` 末尾的生成逻辑**同规则**，但**不下载、不建库** ——
  用于 prepare 被中断后把目标表补全。

    python tools/rebuild_targets_yml.py [--out core/config/targets_a1.yml]
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
POOL = ROOT / "data" / "target_pool"
DB_ROOT = ROOT.parent / "_targets" / "a1db"
SRC_ROOT = ROOT.parent / "_targets" / "a1src"


def safe(repo: str) -> str:
    # ★ 与 prepare_targets 的实际落盘规则一致：**全小写**，"/" → "__"，其余（含 "-"）保留。
    #   例：ANative-Lab/SampleAgentX → anative-lab__sampleagentx
    return repo.lower().replace("/", "__")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="core/config/targets_a1.yml")
    a = ap.parse_args()

    repo_of: dict[str, str] = {}
    for bp in sorted(POOL.glob("a1_batch*.json")):
        try:
            for b in json.load(open(bp, encoding="utf-8")).get("batch", []):
                if b.get("repo"):
                    repo_of[safe(b["repo"])] = b["repo"]
        except Exception:
            continue

    tgt = {"version": 1, "updated": datetime.now().strftime("%Y-%m-%d"),
           "note": "A1 目标表（tools/rebuild_targets_yml.py 生成，含所有已建好的库）",
           "targets": {}}
    miss = []
    for d in sorted(DB_ROOT.glob("*-db")):
        if not (d / "codeql-database.yml").exists():
            continue
        s = d.name[:-3]
        repo = repo_of.get(s)
        if not repo:
            miss.append(s)
            continue
        src = SRC_ROOT / s
        name = repo.split("/")[-1].lower().replace("-", "_").replace(".", "_")
        tgt["targets"][name] = {
            "repo": repo,
            "db": Path(os.path.relpath(d, ROOT)).as_posix(),
            "src": Path(os.path.relpath(src, ROOT)).as_posix(),
        }
    out = ROOT / a.out
    out.write_text(yaml.safe_dump(tgt, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"目标表 {len(tgt['targets'])} 个 → {out}")
    print("  目标:", list(tgt["targets"]))
    if miss:
        print("  ★ 有库但批次文件里查不到 repo（未入表）:", miss)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
