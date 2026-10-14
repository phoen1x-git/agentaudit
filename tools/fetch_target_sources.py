"""批量**只下载**目标源码（不建库）—— 给"大量扩充目标子"用。

★ 为什么不直接用 `tools/prepare_tp2x_targets.py`：
  那个脚本的最后一步是 `codeql database create`，**每个目标要好几分钟**，
  会把"下载"这一步拖成十几倍。★ 用户要的是"**先下载**" ⇒ 下载与建库要分开。

★ 踩过的坑（来自 prepare_tp2x_targets 的 docstring，这里沿用）：
  · `git clone` 会**静默失败**（返回 0 但目录是空的 / 被 export-ignore 掏空）
  ⇒ **规则必须是数字**：数 `.py` 文件个数，不能看返回码。
  · ★ **串行，绝不并发** —— 并发会静默失败。

用法：
    python tools/fetch_target_sources.py --from-screened        # 下 screened.json 里过筛的
    python tools/fetch_target_sources.py --repos owner/a,owner/b
    python tools/fetch_target_sources.py --from-pool --limit 60  # 下候选池前 60
    python tools/fetch_target_sources.py --status                # 只看已下了多少
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.abspath(os.path.join(ROOT, "..", "_targets", "new"))
POOL = os.path.join(ROOT, "data", "target_pool", "pool.json")
SCREENED = os.path.join(ROOT, "data", "target_pool", "screened.json")
REPORT = os.path.join(ROOT, "data", "target_pool", "fetch_sources_report.json")


def _sh(cmd, timeout=None, cwd=None):
    # ★ Windows 下 git 输出可能不是 UTF-8 ⇒ 必须 errors=replace
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          errors="replace", timeout=timeout)


# ★★★ 2026-10-14 关键发现：**`git clone` 在本机走不通**，但 codeload 通。
#   实测报错：`fatal: unable to access 'https://github.com/…': CONNECT tunnel failed, response 502`
#   以及 `schannel: server closed abruptly`。
#   根因：**系统代理**（git 会读 http_proxy/https_proxy）—— 而 `core/gh.py` 全程
#   用 `urllib.request.ProxyHandler({})` **显式禁用代理**，所以它的 API 调用一直是通的。
#   ⇒ 结论：**绕开 git，直接用 codeload 的 tarball 端点**（已实测 HTTP 200 + application/x-gzip）：
#        https://codeload.github.com/<owner>/<repo>/tar.gz/refs/heads/<branch>
#   也**不要**退回 `git -c http.proxy=` —— 那要依赖 git 的行为，tarball 更可控。
import io
import tarfile
import urllib.request

sys.path.insert(0, ROOT)
from core import gh as _gh  # noqa: E402

_BRANCHES = ("main", "master")


def fetch_tarball(repo: str, dest: str, timeout: int = 600) -> tuple[bool, str]:
    """把 repo 的默认分支 tarball 下下来并解压到 dest。返回 (成功?, 说明)。

    ★ 规则是**解压后数 .py 的个数**，不是"HTTP 200"——因为 200 也可能是个空壳（export-ignore）。
    """
    last = ""
    for br in _BRANCHES:
        url = f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{br}"
        try:
            op = _gh._opener_for(url)                      # ★ 复用 gh.py：禁代理 + 必要时 IP 钉扎
            req = urllib.request.Request(url, headers={"User-Agent": "af-fetch/1.0"})
            with op.open(req, timeout=timeout) as r:
                blob = r.read()
            if not blob:
                last = f"{br}: 空响应"
                continue
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                members = tf.getmembers()
                if not members:
                    last = f"{br}: 空包"
                    continue
                # ★★★ 2026-10-14 提速关键：**只解压需要的文件**。
                #   实测慢在哪：`extractall` 在 Windows 上解**大量小文件**极慢
                #   （500 秒只处理了 1 个仓库）。而我们要的只是**能扫的源码**。
                #   ⇒ 只挑 `.py` + 少量配置文件/README（规则要看依赖与说明），其它全丢。
                #   ★ 这不会影响扫描：CodeQL 只分析 .py。
                KEEP_EXT = (".py", ".pyi", ".cfg", ".toml", ".ini", ".yaml", ".yml")
                KEEP_NAME = ("requirements.txt", "README.md", "README.rst", "pyproject.toml")
                files = []
                for m in members:
                    if not m.isfile():
                        continue
                    base = os.path.basename(m.name)
                    if m.name.endswith(KEEP_EXT) or base in KEEP_NAME:
                        files.append(m)
                if not files:
                    last = f"{br}: 包里没有 .py"
                    continue
                tf.extractall(dest, members=files)
                _kept = len(files)
            subs = [x for x in os.listdir(dest) if os.path.isdir(os.path.join(dest, x))]
            if len(subs) == 1:                              # 剥掉顶层目录
                inner = os.path.join(dest, subs[0])
                for x in os.listdir(inner):
                    shutil.move(os.path.join(inner, x), os.path.join(dest, x))
                os.rmdir(inner)
            return True, f"{br} ({len(blob)/1e6:.1f}MB)"
        except Exception as e:
            last = f"{br}: {type(e).__name__} {str(e)[:90]}"
            continue
    return False, last


def count_py(d: str) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(d):
        dirnames[:] = [x for x in dirnames if x not in (".git", "node_modules", "__pycache__")]
        n += sum(1 for f in filenames if f.endswith(".py"))
    return n


def dir_name(repo: str) -> str:
    return repo.replace("/", "__")


def load_repos(a) -> list[str]:
    if a.repos:
        return [x.strip() for x in a.repos.split(",") if x.strip()]
    src = SCREENED if a.from_screened else POOL
    if not os.path.exists(src):
        print("找不到", src)
        return []
    d = json.load(open(src, encoding="utf-8"))
    rows = d if isinstance(d, list) else (d.get("items") or d.get("repos") or d.get("pool") or [])
    out = []
    for it in rows:
        r = it if isinstance(it, str) else (it.get("repo") or it.get("full_name") or "")
        if r and "/" in r:
            out.append(r)
    return out[:a.limit] if a.limit else out


def already(d: str) -> int:
    """已下载且**有代码**的仓库数。"""
    if not os.path.isdir(d):
        return 0
    n = 0
    for x in os.listdir(d):
        p = os.path.join(d, x)
        if os.path.isdir(p) and count_py(p) > 0:
            n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", default="")
    ap.add_argument("--from-screened", action="store_true")
    ap.add_argument("--from-pool", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args()

    os.makedirs(DEST, exist_ok=True)
    if a.status:
        print(f"已下载且有代码：{already(DEST)} 个  目录：{DEST}")
        return 0

    repos = load_repos(a)
    print(f"待处理 {len(repos)} 个仓库 -> {DEST}")
    print(f"（已完成 {already(DEST)} 个，会自动跳过）\n")

    rec = {"started": datetime.now().isoformat(timespec="seconds"), "dest": DEST, "results": []}
    if os.path.exists(REPORT):
        try:
            old = json.load(open(REPORT, encoding="utf-8"))
            rec["results"] = [x for x in old.get("results", []) if x.get("state") == "OK"]
        except Exception:
            pass
    done = {x["repo"] for x in rec["results"]}

    ok = fail = skip = 0
    t0 = time.time()
    for i, repo in enumerate(repos, 1):
        tgt = os.path.join(DEST, dir_name(repo))
        if repo in done or (os.path.isdir(tgt) and count_py(tgt) > 0):
            skip += 1
            continue
        if os.path.isdir(tgt):
            shutil.rmtree(tgt, ignore_errors=True)

        ts = time.time()
        okr, note = fetch_tarball(repo, tgt, timeout=600)   # ★ codeload tarball，不是 git clone
        n = count_py(tgt) if os.path.isdir(tgt) else 0
        size = 0
        if os.path.isdir(tgt):
            for dp, dn, fn in os.walk(tgt):
                dn[:] = [x for x in dn if x != ".git"]
                for f in fn:
                    try:
                        size += os.path.getsize(os.path.join(dp, f))
                    except OSError:
                        pass
        state = "OK" if n > 0 else "NO_CODE"
        if state == "OK":
            ok += 1
        else:
            fail += 1
            shutil.rmtree(tgt, ignore_errors=True)   # ★ 空壳不留
        rec["results"].append({
            "repo": repo, "state": state, "py": n,
            "mb": round(size / 1e6, 1), "sec": round(time.time() - ts, 1),
            "ok": okr, "note": note[:160],
        })
        el = time.time() - t0
        eta = (el / i) * (len(repos) - i) / 60 if i else 0
        print(f"[{i}/{len(repos)}] {state:8} {repo:44} py={n:<5} "
              f"{round(size/1e6,1):>6}MB {round(time.time()-ts,1):>5}s  "
              f"已用{el/60:.0f}min 预计还需{eta:.0f}min")
        # ★ 每 5 个落一次盘（被终止也能续）
        if i % 5 == 0:
            json.dump(rec, open(REPORT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    rec["finished"] = datetime.now().isoformat(timespec="seconds")
    rec["summary"] = {"ok": ok, "fail": fail, "skip": skip,
                      "minutes": round((time.time() - t0) / 60, 1)}
    json.dump(rec, open(REPORT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\n★ 完成：成功 {ok} ｜ 空壳 {fail} ｜ 跳过 {skip} ｜ 用时 {rec['summary']['minutes']} 分钟")
    print("报告:", REPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
