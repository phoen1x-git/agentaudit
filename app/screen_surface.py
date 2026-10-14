"""A1 入口 · 攻击面预检：把"值不值得建库扫"变成可执行判断。

    python app/screen_surface.py --top 60 --n 12

流水线位置：`gate_targets.py`（过健康门）→ **本步（攻击面预检）** → `prepare_targets.py`（下源码+建库）

★ 为什么要有这一步（docs/56 + A1 第一批的教训）：
  A1 第一批 12 个目标是按"描述里像带 Web 服务层的应用"挑的，
  结果好几个本质是"工具脚本集合" —— 扫出来 0 条 vuln，**不是判据漏了，是攻击面不存在**。
  本步不再看描述，而是**读仓库的文件树和依赖**，只留同时具备
  「有执行原语」+「真的在调 LLM」的目标。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import surface as SU          # noqa: E402
from core import gh                     # noqa: E402
import importlib.util                   # noqa: E402

POOL = ROOT / "data" / "target_pool"
SURFACE_CACHE = POOL / "surface_cache.json"


def _already_prepared() -> set[str]:
    """★ 已经下过源码/建过库的目标不能再选（否则重扫一遍，纯浪费）。

    来源：`core/config/targets_a1.yml`（已就绪的目标表）+ `a1_batch1.json`（上一批）。
    """
    out: set[str] = set()
    try:
        import yaml
        d = yaml.safe_load((ROOT / "core" / "config" / "targets_a1.yml").read_text(encoding="utf-8"))
        for t in (d.get("targets") or {}).values():
            if t.get("repo"):
                out.add(t["repo"].lower())
    except Exception:
        pass
    for fn in ("a1_batch1.json",):
        p = POOL / fn
        if p.exists():
            try:
                for b in json.load(open(p, encoding="utf-8")).get("batch", []):
                    if b.get("repo"):
                        out.add(b["repo"].lower())
            except Exception:
                pass
    return out


def _load_cache() -> dict:
    p = SURFACE_CACHE
    if p.exists():
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return {}


def _load_selector():
    """复用 select_batch 的文本打分（不重复实现）。"""
    spec = importlib.util.spec_from_file_location("_sel", ROOT / "app" / "select_batch.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=60, help="先按文本分取前 N 个做预检")
    ap.add_argument("--n", type=int, default=12, help="最终挑几个")
    ap.add_argument("--pool", default=str(POOL / "a1_pool_20261009.json"))
    ap.add_argument("--out", default=str(POOL / "a1_batch2.json"))
    args = ap.parse_args()

    SEL = _load_selector()
    gated = json.load(open(args.pool, encoding="utf-8"))
    passed = {x["repo"].lower(): x for x in gated["passed"]}
    detail = json.load(open(POOL / "pool.json", encoding="utf-8"))["repos"]

    # ---- 第一关：文本分（沿用既有规则）----
    done = _already_prepared()
    if done:
        print(f"已备过的目标（不再选）：{len(done)} 个")
    cand = []
    for key, g in passed.items():
        if key in SEL.EXCLUDE or key in done:
            continue
        it = detail.get(key) or {}
        if not it:
            continue
        blob = ((it.get("description") or "") + " " + (g.get("repo") or "")).lower()
        if any(bad in blob for bad in SEL.NOT_APP_NAME):
            continue
        s, why = SEL.score(it)
        cand.append({"repo": g["repo"], "stars": g.get("stars"), "text_score": s,
                     "why": why, "months": g.get("months_since_push"),
                     "branch": g.get("default_branch"),
                     "desc": (it.get("description") or "")[:110]})
    cand.sort(key=lambda r: (-r["text_score"], -(r["stars"] or 0)))
    top = cand[:args.top]
    print(f"过门 {len(passed)} → 文本分前 {len(top)} → 逐个做攻击面预检\n")

    # ---- 第二关：攻击面预检（真读仓库；结果落缓存，重跑不重复烧 API）----
    tok = gh.token()
    cache = _load_cache()
    ok_rows, bad_rows = [], []
    n_cached = 0
    for i, r in enumerate(top, 1):
        ck = r["repo"].lower()
        if ck in cache:
            pr = cache[ck]
            n_cached += 1
        else:
            pr = SU.probe(r["repo"], r["branch"] or "main", tok=tok)
            cache[ck] = pr
        good, why = SU.verdict(pr)
        rec = {**r, "surface": pr.get("surface"), "surface_score": pr.get("surface_score"),
               "llm_deps": pr.get("llm_deps"), "web_deps": pr.get("web_deps"),
               "vendor_ratio": pr.get("vendor_ratio"), "n_files": pr.get("n_files"),
               "verdict_why": why}
        (ok_rows if good else bad_rows).append(rec)
        flag = "✅" if good else "✗ "
        print(f"{flag} [{i:2}/{len(top)}] {r['repo']:44} 文件{pr.get('n_files') or 0:>5} "
              f"exec={pr.get('surface_score')} llm={pr.get('llm_deps')}")
        if not good:
            print(f"        ↳ {why}")

    ok_rows.sort(key=lambda r: (-r["surface_score"], -(r["stars"] or 0)))
    pick = ok_rows[:args.n]
    SURFACE_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"\n=== 通过预检 {len(ok_rows)} 个 / 被剔 {len(bad_rows)} 个 "
          f"（本次命中缓存 {n_cached}）→ 取前 {len(pick)} ===")
    for i, r in enumerate(pick, 1):
        print(f"{i:2}. {r['repo']:44} {r['stars']:>5}★ exec={r['surface_score']:>3} "
              f"llm={','.join(r['llm_deps'][:3])}")
        print(f"      {r['desc']}")
        print(f"      执行面: {', '.join((r['surface'] or [])[:8])}")

    out = {"_meta": {"generated_at": datetime.now().isoformat(timespec="seconds"),
                     "n": len(pick), "screened": len(top),
                     "passed": len(ok_rows), "rejected": len(bad_rows),
                     "rule": "先文本分取前 N，再读仓库文件树+依赖做攻击面预检"
                             "（必须有执行原语 + LLM 依赖）"},
           "batch": pick,
           "rejected": [{k: v for k, v in r.items() if k != "why"} for r in bad_rows]}
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n→ {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
