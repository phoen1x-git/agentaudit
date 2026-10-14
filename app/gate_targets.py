"""Screen a target pool with the health gate.

    python app/gate_targets.py data/target_pool/projects_profile.json [--mode alive|detect]

Input: a pool shaped like {repo: {...}} or [repo, ...].
Output: `data/target_pool/pool_<date>.json`, keeping only the targets that pass, together
with the reason each rejected target was rejected.

Keeping the reasons matters: a target pool decays quietly (repos get archived, authors
walk away) and without the reasons you cannot see it happening.

--mode:
    alive  (default) reporting to maintainers -> skip archived / unmaintained repos
    detect           measuring detection power -> do not skip archived repos
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import gate as G  # noqa: E402


def _parse_argv() -> tuple[Path | None, str]:
    """★ 这个脚本用 sys.argv 而不是 argparse，所以要手动跳过 `--mode X` 的取值，
    否则 `detect` 会被当成池子文件路径（踩过）。"""
    argv = sys.argv[1:]
    mode, pos, i = "", [], 0
    while i < len(argv):
        if argv[i] == "--mode" and i + 1 < len(argv):
            mode = argv[i + 1]
            i += 2
            continue
        pos.append(argv[i])
        i += 1
    return (Path(pos[0]) if pos else None), mode


def _repos_from(path: Path) -> list[str]:
    d = json.load(open(path, encoding="utf-8"))
    if isinstance(d, dict):
        if "repos" in d and isinstance(d["repos"], dict):        # screener 的 pool.json
            return [k for k in d["repos"]]
        if "passed" in d:                                        # 我们自己产出的 pool_*.json
            return [x["repo"] for x in d["passed"]]
        return [k for k in d if not k.startswith("_")]
    if isinstance(d, list):
        return [x if isinstance(x, str) else x.get("repo") for x in d]
    return []


def main() -> int:
    src_arg, mode = _parse_argv()
    src = src_arg or (ROOT / "data" / "target_pool" / "projects_profile.json")
    if not src.exists():
        print(f"找不到池子文件：{src}")
        return 1
    repos = _repos_from(src)
    cfg = G.load_cfg()
    print(f"池子 {src.name}：{len(repos)} 个候选，逐个体检"
          f"（模式 {mode or cfg.get('mode')}，带 {cfg.get('ttl_days')} 天缓存）…\n")

    passed, skipped, unknown = [], [], []
    for r in repos:
        res = G.check(r, cfg, mode=(mode or None))
        line = f"{r:45} {G.summary(res)}"
        print(("  ✓ " if res["verdict"] == "PASS" else "  ✗ ") + line)
        (passed if res["verdict"] == "PASS" else unknown if res["verdict"] == "UNKNOWN" else skipped).append(res)
        time.sleep(0.2)

    out = {
        "_meta": {
            "source": str(src),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "gate_cfg": cfg,
            "n_in": len(repos), "n_pass": len(passed),
            "n_skip": len(skipped), "n_unknown": len(unknown),
        },
        "passed": [{"repo": r["repo"], "stars": r.get("stars"),
                    "pushed_at": r.get("pushed_at"), "months_since_push": r.get("months_since_push"),
                    "default_branch": r.get("default_branch")} for r in passed],
        "skipped": [{"repo": r["repo"], "reasons": r["reasons"]} for r in skipped],
        "unknown": [{"repo": r["repo"], "reasons": r["reasons"]} for r in unknown],
    }
    dst = ROOT / "data" / "target_pool" / f"pool_{datetime.now().strftime('%Y%m%d')}.json"
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"\n== 入场 {len(repos)} → 过门 {len(passed)}，筛掉 {len(skipped)}，未知 {len(unknown)}")
    print(f"   → {dst}")
    if skipped:
        print("   筛掉的原因：")
        for r in skipped:
            print(f"     {r['repo']:45} {'；'.join(r['reasons'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
