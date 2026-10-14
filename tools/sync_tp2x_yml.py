"""同步 `core/config/targets_tp2x.yml`：扫 `_targets/tp2x_db` + 从语料/报告反查 repo。

★ 为什么需要：`tools/rebuild_targets_yml.py` 只扫 `_targets/a1db/*-db`（a1 池），
  而 TaintP2X 语料的靶建在 `_targets/tp2x_db/`。★ 建完库不写进 yml → `run_round` 根本看不到这些靶
  （`run_round` 只从 yml 读目标）→ **建了库却扫不了**，白建。

★ 短名规则（要稳定，不能每次跑都不一样）：
  1. 现有 yml 里已有的 repo → **沿用现有短名**（不许改，改了下游按短名引用的地方全崩）；
  2. 新 repo → 取 repo 名（`owner/repo` 的 `repo` 部分），小写、非 [a-z0-9] 换成 `_`；
  3. 撞名 → 追加 `_2` / `_3`。

用法：
    python tools/sync_tp2x_yml.py                 # 预览（不写）
    python tools/sync_tp2x_yml.py --write         # 真的写
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
YML = ROOT / "core" / "config" / "targets_tp2x.yml"
DB = ROOT.parent / "_targets" / "tp2x_db"
SRC = ROOT.parent / "_targets" / "tp2x_src"
REPORT = ROOT / "data" / "target_pool" / "tp2x_prepare_report.json"
CORPUS = ROOT / "data" / "target_pool" / "taintp2x_benchmark.json"


def slug_of(short: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", short.lower()).strip("_")


def build_repo_index() -> dict:
    """从 prepare 报告 + 语料反查：db 目录名 → owner/repo。"""
    idx: dict[str, str] = {}
    if REPORT.exists():
        try:
            d = json.loads(REPORT.read_text(encoding="utf-8"))
            for r in (d.get("results") or []):
                db = r.get("db")
                rp = r.get("repo")
                if db and rp:
                    idx[os.path.basename(db)] = rp
        except Exception:
            pass
    # 语料兜底（目录名有两种写法：`owner__repo` 与 `owner_repo`）
    if CORPUS.exists():
        try:
            c = json.loads(CORPUS.read_text(encoding="utf-8"))
            for r in (c.get("positive") or []) + (c.get("negative") or []):
                rp = r.get("repo")
                if not rp:
                    continue
                # ★ 两种 slug 都要生成，且**两个方向**都建 key ——
                #   prepare 脚本落的目录名可能是 `owner__repo-db`，也可能是 `owner_repo-db`
                #   （`docs/189` 的"两套拼法"教训：漏一个方向就静默反查不到）。
                variants = set()
                if "__" in rp:
                    variants.add(rp.replace("__", "/"))
                    variants.add(rp.replace("__", "_"))
                elif "_" in rp:
                    variants.add(rp.replace("_", "/", 1))
                for v in variants:
                    for slug in (rp, v.replace("/", "__"), v.replace("/", "_")):
                        idx.setdefault(f"{slug}-db", rp.replace("__", "/"))
        except Exception:
            pass
    return idx


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()

    if not YML.exists():
        print(f"✗ 找不到 {YML}")
        return 1
    doc = yaml.safe_load(YML.read_text(encoding="utf-8")) or {}
    targets: dict = doc.get("targets") or {}

    # 现有短名 ↔ repo 双向表
    repo2short = {v.get("repo"): k for k, v in targets.items() if isinstance(v, dict)}
    used = set(targets)

    repo_idx = build_repo_index()
    added, skipped = [], []
    if not DB.exists():
        print(f"✗ 找不到 {DB}")
        return 1

    for d in sorted(DB.iterdir()):
        if not d.is_dir() or not d.name.endswith("-db"):
            continue
        if not (d / "codeql-database.yml").exists():
            skipped.append((d.name, "无 codeql-database.yml（建库没完成）"))
            continue
        repo = repo_idx.get(d.name) or repo_idx.get(f"{d.name}-db")
        if not repo:
            skipped.append((d.name, "反查不到 repo（不在报告/语料里）"))
            continue
        if repo in repo2short:
            continue                                   # 已在 yml，不动
        # 生成短名
        base = slug_of(repo.split("/")[-1])
        short, n = base, 1
        while short in used:
            n += 1
            short = f"{base}_{n}"
        used.add(short)
        repo2short[repo] = short
        # src 目录：优先按 prepare 的命名（owner_repo），回退 owner__repo
        cand = [SRC / f"{d.name[:-3]}", SRC / f"{d.name[:-3].replace('__', '_')}"]
        src_dir = next((c for c in cand if c.exists()), None)
        rel = lambda p: "../" + str(p.relative_to(ROOT.parent)).replace("\\", "/")  # noqa: E731
        targets[short] = {
            "repo": repo,
            "db": rel(d),
            "src": rel(src_dir) if src_dir else "",
        }
        added.append((short, repo, d.name))

    print(f"现有 yml 条目 {len(targets) - len(added)} 个 ｜ ★ 本次新增 {len(added)} 个")
    for s, rp, dn in added:
        print(f"   + {s:<22} {rp:<44} ({dn})")
    if skipped:
        print(f"\n⚠️ 跳过 {len(skipped)} 个：")
        for dn, why in skipped:
            print(f"   - {dn:<46} {why}")

    if not a.write:
        print("\n（预览模式；加 --write 才写盘）")
        return 0
    doc["targets"] = targets
    doc["updated"] = datetime.now().strftime("%Y-%m-%d")
    YML.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False,
                                  default_flow_style=False, width=100), encoding="utf-8")
    print(f"\n★ 已写入 {YML}（共 {len(targets)} 个条目）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
