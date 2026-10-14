"""TaintP2X 靶**自动备料**：下载 → 校验 → 解压 → 建库。

★ 为什么要有这个脚本：备料这一步我手工做了 11 次，踩了 **4 种"假 0"**
  （clone 静默失败 / `export-ignore` 空树 / 目录名撞路径过滤 / 空壳库）。
  判据必须是**数字**，不能是"命令返回 0"。

做的事（每个仓库）：
  1. `git clone --depth 1`（★ 串行，绝不并发 —— 并发会静默失败）
  2. 校验 `find <dir> -name '*.py' | wc -l` > 0
     失败 → 退回 `codeload` zip（分支自动探测 main/master）
  3. 再校验；仍 0 → 记 `NO_CODE`（`export-ignore` 等），跳过
  4. `codeql database create` → 校验 `du -sh <db>` 不能是几百 KB
  5. 输出 `data/target_pool/tp2x_prepare_report.json`（每个仓库的最终状态 + 数字）

用法:
  python tools/prepare_tp2x_targets.py                # 按 positive 数取前 N
  python tools/prepare_tp2x_targets.py --top 20
  python tools/prepare_tp2x_targets.py --repos owner/a,owner/b
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
ROOT = PROJ.parent                                   # 工作区根（项目目录的上一级）
D = PROJ / "data" / "target_pool"
BENCH = D / "taintp2x_benchmark.json"
SRC = ROOT / "_targets" / "tp2x_src"
DB = ROOT / "_targets" / "tp2x_db"
ZIP = ROOT / "_targets" / "tp2x_zip"
CODEQL = ROOT / "_tools" / "codeql" / "codeql.exe"
PY = sys.executable


def _run(cmd, timeout=None, cwd=None):
    # ★ Windows 下 codeql/git 的输出可能不是 UTF-8 → 必须 errors='replace'，
    #   否则子进程读取线程会抛 UnicodeDecodeError（实测踩到）
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                          encoding="utf-8", errors="replace")


def count_py(d: Path) -> int:
    """★ 坑：不能写 `for _, _, fs in os.walk(...)` —— 两个 `_` 是同一个变量，
    第二次赋值会把 dirpath 覆盖成 dirnames（list）。"""
    n = 0
    for dirpath, _dirnames, fs in os.walk(d):
        if f"{os.sep}.git" in dirpath:
            continue
        n += sum(1 for f in fs if f.endswith(".py"))
    return n


def db_size_mb(d: Path) -> float:
    if not d.exists():
        return 0.0
    tot = 0
    for dirpath, _dirnames, fs in os.walk(d):
        for f in fs:
            try:
                tot += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return tot / 1024 / 1024


def gh_json(url: str) -> dict:
    """用 core.gh 走 DoH 拿 JSON（不依赖 curl 的 hosts）。"""
    sys.path.insert(0, str(PROJ))
    from core import gh
    code, body = gh.get(url)
    try:
        return json.loads(body)
    except Exception:
        return {}


def _load_yml_map() -> dict:
    """★ 靶的「repo → (db, src)」**权威映射**来自 core/config/targets*.yml
    （与 `sample_false_negatives.py` 同一个教训：别自己猜目录名）。"""
    m = {}
    for f in (PROJ / "core" / "config").glob("targets*.yml"):
        try:
            cfg = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        for _name, v in (cfg.get("targets") or {}).items():
            rp = (v or {}).get("repo")
            if rp:
                m[rp] = (v.get("db"), v.get("src"))
    return m


_YML_MAP = None


def _resolve(repo: str):
    """兼容两种目录命名：`owner__repo`（a1src 风格）与 `owner_repo`（tp2x 风格）。"""
    a = repo.replace("/", "__")
    b = repo.replace("/", "_")
    return a, b


def prepare_one(repo: str, force: bool = False) -> dict:
    global _YML_MAP
    if _YML_MAP is None:
        _YML_MAP = _load_yml_map()

    a, b = _resolve(repo)
    src = next((SRC / x for x in (a, b) if (SRC / x).exists()), SRC / b)
    db = next((DB / f"{x}-db" for x in (a, b) if (DB / f"{x}-db").exists()), DB / f"{b}-db")
    # ★ yml 里有权威映射就用它（yml 里的 `../_targets/...` 是**相对 PROJ**的）
    if repo in _YML_MAP:
        ydb, ysrc = _YML_MAP[repo]
        if ydb:
            db = (PROJ / ydb).resolve()
        if ysrc:
            src = (PROJ / ysrc).resolve()
    rec = {"repo": repo, "src": str(src), "db": str(db)}

    if db.exists() and db_size_mb(db) > 3 and not force:
        rec.update(state="OK(已有)", py=count_py(src), db_mb=round(db_size_mb(db), 1))
        return rec

    # ---- 1) git clone（串行）----
    if not (src.exists() and count_py(src) > 0):
        if src.exists():
            shutil.rmtree(src, ignore_errors=True)
        SRC.mkdir(parents=True, exist_ok=True)
        r = _run(["git", "clone", "--depth", "1", "-q",
                  f"https://github.com/{repo}.git", str(src)], timeout=900)
        rec["clone_rc"] = r.returncode
    n = count_py(src) if src.exists() else 0

    # ---- 2) 退回 zip（自动探测分支）----
    if n == 0:
        info = gh_json(f"https://api.github.com/repos/{repo}")
        br = info.get("default_branch") or "main"
        ZIP.mkdir(parents=True, exist_ok=True)
        z = ZIP / f"{b}.zip"
        _run(["curl", "-sL", "--max-time", "2400", "-o", str(z),
              f"https://codeload.github.com/{repo}/zip/refs/heads/{br}"], timeout=2500)
        if z.exists() and z.stat().st_size > 1000:
            tmp = ROOT / "_targets" / "tp2x_extract"
            tmp.mkdir(parents=True, exist_ok=True)
            _run(["unzip", "-q", "-o", str(z), "-d", str(tmp)], timeout=900)
            subs = [p for p in tmp.glob(f"{repo.split('/')[-1]}*") if p.is_dir()]
            if subs:
                if src.exists():
                    shutil.rmtree(src, ignore_errors=True)
                shutil.move(str(subs[0]), str(src))
        n = count_py(src) if src.exists() else 0

    rec["py"] = n
    if n == 0:
        rec["state"] = "NO_CODE（export-ignore 等 → 换靶）"
        return rec

    # ---- 3) 建库 ----
    if db.exists():
        shutil.rmtree(db, ignore_errors=True)
    r = _run([str(CODEQL), "database", "create", str(db), "--language=python",
              f"--source-root={src}", "--overwrite"], timeout=2400)
    mb = round(db_size_mb(db), 1)
    rec["db_mb"] = mb
    if mb < 1:
        rec["state"] = f"DB_FAIL(空壳 {mb}MB) rc={r.returncode}"
    else:
        rec["state"] = "OK"
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--repos", default="")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    if a.repos:
        repos = [x.strip() for x in a.repos.split(",") if x.strip()]
    else:
        b = json.load(open(BENCH, encoding="utf-8"))
        cnt = {}
        for it in b["positive"]:
            cnt[it["repo"]] = cnt.get(it["repo"], 0) + 1
        # repo 形如 owner__name → owner/name
        repos = [r.replace("__", "/") for r, _ in
                 sorted(cnt.items(), key=lambda x: -x[1])[: a.top]]

    out = []
    for i, r in enumerate(repos, 1):
        print(f"[{i}/{len(repos)}] {r} ...", flush=True)
        try:
            rec = prepare_one(r, force=a.force)
        except Exception as e:
            rec = {"repo": r, "state": f"EXC {type(e).__name__}: {e}"[:120]}
        print(f"    → {rec.get('state')}  py={rec.get('py')}  db={rec.get('db_mb')}MB", flush=True)
        out.append(rec)

    p = D / "tp2x_prepare_report.json"
    json.dump({"_meta": {"purpose": "靶备料结果（下载/校验/建库）",
                         "rule": "判据是 .py 数与 db 大小，不是命令返回值"},
               "results": out}, open(p, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    ok = sum(1 for r in out if str(r.get("state", "")).startswith("OK"))
    print(f"\n★ 成功 {ok}/{len(out)} → {p}")


if __name__ == "__main__":
    main()
