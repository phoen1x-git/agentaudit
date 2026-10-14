"""A1 自用版入口 · 从「候选公告池」里筛出**能当验证集的目标仓库**。

    python app/screen_advisory_targets.py [--pool data/target_pool/advisory_pool.json]
                                          [--only pkg1,pkg2] [--max-mb 40]

★ 背景（`docs/117`）：扩"有真值的验证集"需要「**有公开公告 + 有 Agent 攻击面 + 能下载**」三者兼得。
  `advisory_pool.json` 只回答了第一项。本脚本补齐后两项：
    · 公告 → 仓库：从公告 refs 里抽 `github.com/<owner>/<repo>`
    · 攻击面/体量：复用 `core/surface.probe`（1 次 tree + 依赖）+ `remote_source_bytes`

★ 输出 `data/target_pool/advisory_targets.json`，按「公告数 × 攻击面分」排序。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import gh, surface                        # noqa: E402

_REPO = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def _repos_from_refs(refs: list[str]) -> list[str]:
    out = []
    for u in refs or []:
        m = _REPO.match(str(u))
        if not m:
            continue
        owner, repo = m.group(1), m.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        # 公告里常挂 gist / 组织主页（无 repo 段）→ 跳过
        if repo.lower() in ("", "gist.github.com"):
            continue
        out.append(f"{owner}/{repo}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=str(ROOT / "data" / "target_pool" / "advisory_pool.json"))
    ap.add_argument("--out", default=str(ROOT / "data" / "target_pool" / "advisory_targets.json"))
    ap.add_argument("--only", default="")
    ap.add_argument("--max-mb", type=float, default=40.0)
    a = ap.parse_args()

    pool = json.load(open(a.pool, encoding="utf-8"))["items"]
    only = {s.strip() for s in a.only.split(",") if s.strip()}

    # 包 → 仓库候选 计数
    pkg_repos: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    pkg_adv: dict[str, list[dict]] = defaultdict(list)
    for it in pool:
        if only and it["package"] not in only:
            continue
        pkg_adv[it["package"]].append(it)
        for r in _repos_from_refs(it.get("refs")):
            pkg_repos[it["package"]][r] += 1

    rows = []
    tok = gh.token()
    for pkg, repos in sorted(pkg_repos.items()):
        if only and pkg not in only:
            continue
        # 取公告里出现最多的仓库；并列时打印出来让人看
        ranked = sorted(repos.items(), key=lambda kv: -kv[1])
        repo = ranked[0][0]
        advs = pkg_adv[pkg]
        n_exact = sum(1 for x in advs if x["precision"] == "exact")
        n_file = sum(1 for x in advs if x["precision"] == "file")
        rec = {"package": pkg, "repo": repo,
               "repo_candidates": ranked[:3],
               "n_advisories": len(advs), "n_exact": n_exact, "n_file": n_file,
               "advisories": [{"id": x["id"], "aliases": x["aliases"],
                               "summary": x["summary"], "precision": x["precision"],
                               "file": x["target_file"], "func": x["target_function"],
                               "affected": x["affected_ranges"]} for x in advs]}
        # 默认分支
        info = gh.get_json(f"{gh.API}/repos/{repo}", tok=tok)
        branch = (info or {}).get("default_branch") or "main"
        rec["archived"] = bool((info or {}).get("archived"))
        rec["stars"] = (info or {}).get("stargazers_count")
        rec["branch"] = branch
        # 体量（工作树字节）
        tb = None
        for _ in range(3):
            try:
                tb = surface.remote_source_bytes(repo, branch, tok=tok)
            except Exception:                   # noqa: BLE001
                tb = None
            if tb is not None:
                break
            time.sleep(1.2)
        rec["tree_mb"] = round(tb / 1024 / 1024, 1) if tb else None
        # 攻击面
        try:
            pr = surface.probe(repo, branch, tok=tok)
        except Exception as e:                  # noqa: BLE001
            pr = {"ok": False, "err": str(e)[:80]}
        rec["surface_ok"] = pr.get("ok")
        rec["surface_score"] = pr.get("surface_score")
        rec["surface"] = pr.get("surface")
        rec["llm_deps"] = pr.get("llm_deps")
        rec["web_deps"] = pr.get("web_deps")
        rec["n_files"] = pr.get("n_files")
        rec["vendor_ratio"] = pr.get("vendor_ratio")
        rec["size_ok"] = tb is None or rec["tree_mb"] * 1.0 <= a.max_mb
        try:
            ok, why = surface.verdict(pr)
        except Exception:                       # noqa: BLE001
            ok, why = False, "verdict 失败"
        rec["surface_pass"] = ok
        rec["surface_why"] = why
        rows.append(rec)
        flag = "PASS" if (ok and rec["size_ok"]) else "----"
        print(f"[{flag}] {pkg:24} {repo:38} adv={len(advs):2}(ex{n_exact}/f{n_file}) "
              f"tree={rec['tree_mb']}MB exec={rec['surface_score']} "
              f"llm={len(rec['llm_deps'] or [])} files={rec['n_files']}")

    rows.sort(key=lambda r: (not (r["surface_pass"] and r["size_ok"]),
                             -(r["n_exact"] * 10 + r["n_file"]) - (r["surface_score"] or 0)))
    doc = {"_meta": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                     "n_pkgs": len(rows), "max_mb": a.max_mb,
                     "note": "repo 由公告 refs 抽取；tree_mb 用工作树字节（非 GitHub size 字段）"},
           "targets": rows}
    Path(a.out).write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    good = [r for r in rows if r["surface_pass"] and r["size_ok"]]
    print(f"\n== {len(rows)} 个候选包；过攻击面+体量 {len(good)} 个 → {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
