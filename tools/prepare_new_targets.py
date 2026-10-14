"""把 `screened.json` 里 **passed_L2=True** 的那批新目标：**下载 → 建库**（边下边建）。

★★ 三条设计约束（都是踩过的坑逼出来的）：

1. **走路必须用 codeload tarball，不能用 `git clone`** ——
   本机 `git clone` 走系统代理必然 502（`docs` 与 `fetch_target_sources.py` 已记）。
   ⇒ 直接复用 `fetch_target_sources.fetch_tarball`（已实测 HTTP 200 + 只解 `.py`）。
   ★ 但分支要**用 `screened.json` 里真实的 `default_branch`** ——
     实测有脏值（`mian` / `v2.0.1` / `codex/...`），只试 main/master 会漏。

2. **必须可断点续跑（skip-if-done）** ——
   本项目实测：`run_in_background` 的子进程**会在"回合结束"时被杀**。
   ⇒ 所以：① 每建完一个库**立刻写一次报告**；② 重启时**已有库直接跳过**。

3. **磁盘护栏** —— 97 个目标，剩余空间有限；低于 10GB 就**停下报数**，不赌。

用法：
    python tools/prepare_new_targets.py --status          # 只看还差多少
    python tools/prepare_new_targets.py                   # 全部（可反复重启）
    python tools/prepare_new_targets.py --limit 5         # 先小批验证
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import fetch_target_sources as F  # noqa: E402  复用 fetch_tarball / count_py

HOME = os.path.dirname(ROOT)                                  # parent of the project (used for disk checks)
SRC = os.environ.get("AF_SRC_DIR") or os.path.join(ROOT, "_targets", "src")
DB = os.environ.get("AF_DB_DIR") or os.path.join(ROOT, "_targets", "db")
CODEQL = os.environ.get("AF_CODEQL") or os.path.join(ROOT, "_tools", "codeql", "codeql.exe")
SCREENED = os.path.join(ROOT, "data", "target_pool", "screened.json")
REPORT = os.path.join(ROOT, "data", "target_pool", "new_targets_prepare_report.json")

MIN_FREE_GB = 10.0
DB_MIN_MB = 3.0


def free_gb() -> float:
    try:
        u = shutil.disk_usage(HOME)
        return u.free / 1024 ** 3
    except Exception:
        return 999.0


def dirs_for(repo: str) -> tuple[str, str]:
    n = repo.replace("/", "__")
    return os.path.join(SRC, n), os.path.join(DB, f"{n}-db")


def db_mb(d: str) -> float:
    tot = 0
    for dp, _dn, fs in os.walk(d):
        for f in fs:
            try:
                tot += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    return tot / 1024 / 1024


def load_targets() -> list[dict]:
    d = json.load(open(SCREENED, encoding="utf-8"))
    return [x for x in d["items"] if x.get("passed_L2") is True]


def load_report() -> dict:
    if os.path.exists(REPORT):
        try:
            return json.load(open(REPORT, encoding="utf-8"))
        except Exception:
            pass
    return {"_meta": {"purpose": "新目标准备（下载+建库），可断点续跑",
                      "rule": "规则是 .py 数与 db 大小，不是命令返回值"},
            "results": []}


def save_report(rec: dict) -> None:
    tmp = REPORT + ".tmp"
    json.dump(rec, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(tmp, REPORT)                       # ★ 原子写：中断也不会留半个文件


def fetch_with_branch(repo: str, dest: str, branch: str) -> tuple[bool, str]:
    """★ 先把 `screened.json` 里声明的默认分支塞到最前面，再退回 main/master。"""
    old = list(F._BRANCHES)
    try:
        F._BRANCHES = ([branch] if branch else []) + [b for b in old if b != branch]
        return F.fetch_tarball(repo, dest, timeout=900)
    finally:
        F._BRANCHES = old


def build_db(src: str, db: str) -> tuple[str, int]:
    os.makedirs(os.path.dirname(db), exist_ok=True)
    if os.path.exists(db):
        shutil.rmtree(db, ignore_errors=True)
    try:
        r = subprocess.run([CODEQL, "database", "create", db, "--language=python",
                            f"--source-root={src}", "--overwrite"],
                           capture_output=True, text=True, errors="replace", timeout=2700)
        rc = r.returncode
        if rc != 0:
            tail = (r.stderr or r.stdout or "")[-200:].replace("\n", " ")
            return f"DB_FAIL(rc={rc}) {tail[:120]}", 0
    except subprocess.TimeoutExpired:
        return "DB_FAIL(超时 45 分钟)", 0
    except Exception as e:
        return f"DB_FAIL({type(e).__name__}: {e})"[:140], 0
    mb = round(db_mb(db), 1)
    return ("OK" if mb >= DB_MIN_MB else f"DB_FAIL(空壳 {mb}MB)"), mb


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--force", action="store_true", help="连已有的也重建")
    a = ap.parse_args()

    tg = load_targets()
    rep = load_report()
    done = {r["repo"] for r in rep["results"]
            if str(r.get("state", "")).startswith("OK") and not a.force}
    pending = [t for t in tg if t["full_name"] not in done]
    if a.limit:
        pending = pending[:a.limit]

    print(f"★ 目标目标 {len(tg)} 个 ｜ 已完成 {len(done)} 个 ｜ 本次待处理 {len(pending)} 个")
    print(f"  磁盘剩余 {free_gb():.1f} GB（护栏 {MIN_FREE_GB} GB）")
    if a.status:
        for t in pending[:30]:
            s, d = dirs_for(t["full_name"])
            print("   - %-46s src=%s db=%s" % (t["full_name"],
                  "有" if os.path.isdir(s) and F.count_py(s) > 0 else "无",
                  "有" if os.path.isdir(d) and db_mb(d) > DB_MIN_MB else "无"))
        if len(pending) > 30:
            print(f"   ... 另有 {len(pending) - 30} 个")
        return 0

    if not pending:
        print("★ 全部处理完了。")
        return 0

    ok = fail = 0
    for i, t in enumerate(pending, 1):
        repo = t["full_name"]
        src, db = dirs_for(repo)
        br = (t.get("default_branch") or "").strip()

        if free_gb() < MIN_FREE_GB:
            print(f"\n★★ 磁盘只剩 {free_gb():.1f} GB < {MIN_FREE_GB} GB → 硬停（防撑爆）。"
                  f"已处理 {i-1}/{len(pending)}。")
            break

        t0 = time.time()
        print(f"\n[{i}/{len(pending)}] {repo}  (branch={br})", flush=True)

        # ---- 1) 源码（缺才下）----
        n_py = F.count_py(src) if os.path.isdir(src) else 0
        if n_py == 0:
            if os.path.isdir(src):
                shutil.rmtree(src, ignore_errors=True)
            os.makedirs(src, exist_ok=True)
            okf, note = fetch_with_branch(repo, src, br)
            n_py = F.count_py(src) if os.path.isdir(src) else 0
            print(f"    下载: {'✅' if okf else '❌'} {note}  → {n_py} 个 .py", flush=True)
            if n_py == 0:
                rec = {"repo": repo, "state": "NO_CODE", "py": 0, "note": note,
                       "sec": round(time.time() - t0, 1)}
                rep["results"] = [r for r in rep["results"] if r["repo"] != repo] + [rec]
                save_report(rep)
                fail += 1
                continue
        else:
            print(f"    源码已有 {n_py} 个 .py，跳过下载", flush=True)

        # ---- 2) 建库（缺才建）----
        if os.path.isdir(db) and db_mb(db) >= DB_MIN_MB and not a.force:
            print(f"    库已有 {db_mb(db):.1f} MB，跳过", flush=True)
            rec = {"repo": repo, "state": "OK(已有)", "py": n_py,
                   "db_mb": round(db_mb(db), 1), "sec": round(time.time() - t0, 1)}
        else:
            state, mb = build_db(src, db)
            print(f"    建库: {state}  db={mb} MB  用时 {time.time()-t0:.0f}s", flush=True)
            rec = {"repo": repo, "state": state, "py": n_py, "db_mb": mb,
                   "sec": round(time.time() - t0, 1)}
            ok += 1 if state.startswith("OK") else 0
            fail += 0 if state.startswith("OK") else 1
        rep["results"] = [r for r in rep["results"] if r["repo"] != repo] + [rec]
        rep["_meta"]["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        save_report(rep)

    donen = sum(1 for r in rep["results"] if str(r.get("state", "")).startswith("OK"))
    print(f"\n★ 本轮：成功 {ok} ｜ 失败 {fail} ｜ 累计完成 {donen}/{len(tg)}")
    print(f"★ 报告：{REPORT}")
    print(f"★ 磁盘剩余 {free_gb():.1f} GB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
