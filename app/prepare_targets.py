"""A1 自用版入口 · 给一批新目标备料（下源码 + 建 CodeQL 库）。

    python app/prepare_targets.py data/target_pool/a1_batch1.json

★ 这一步是整条链上**最重的**（每个目标要 clone + 建库，几分钟起），所以：
  · 逐个容错，一个失败不影响下一个（失败要出声，写进日志）
  · 已建好的库直接跳过（可反复跑）
  · 支持 --only 只补某几个

产出：
    ../_targets/a1src/<name>/          源码
    ../_targets/a1db/<name>-db/        CodeQL 库
    core/config/targets_a1.yml         给 run_round 用的目标表
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))          # ★ 让 core 可导入（脚本方式运行时 sys.path[0] 是 app/）
WS = ROOT.parent
SRC_ROOT = WS / "_targets" / "a1src"
DB_ROOT = WS / "_targets" / "a1db"
POOL = ROOT / "data" / "target_pool"
CODEQL = WS / "_tools" / "codeql" / "codeql.exe"


def _safe(repo: str) -> str:
    return repo.replace("/", "__").lower()


_MARK = ".af_fetch_ok"
# ★ 30 MB：不是因为装不下，是因为**本机到 codeload 的吞吐只有 ~60 KB/s**
#   （实测：37 MB 的仓库拉了 10 分钟还没完）→ 大仓库会拖垮整批
MAX_REPO_KB = 100000     # ★ 只作 tree 取不到时的兜底；★ size 能高估 2~7 倍，所以给足
# ★★ 真正的闸门是工作树字节数（`git/trees` 里所有 blob 的 size 之和）。
#    为什么不用 size 字段：它含 .git 历史，实测能差 7 倍（sampleproj 16.7MB vs 真实 2.3MB），
#    只按它判会把大批能拉的目标误杀（第一批就误杀了 8 个）。
#    本机到 codeload 实测 ~40–60 KB/s → 120MB 工作树大约要 35–50 分钟，太久了。
MAX_SRC_BYTES = 40 * 1024 * 1024
MAX_FETCH_MB = 200       # ★ 下载字节上限
# ★ 单目标下载秒数上限。为什么是 1800 秒：
#   实测本机到 codeload 只有 **~26 KB/s**（deepanalyze 900s 只收到 23MB/38MB）。
#   → 40MB 工作树 ≈ 26 分钟。给 30 分钟留点余量；再大就别试了，不是"慢"是"拉不完"。
MAX_FETCH_SEC = 1800

# ★ 重试次数。为什么必须重试：实测失败**多半不是"慢"而是连接被掐断** ——
#   `IncompleteRead(901120 bytes read)`（只收到 880KB 就断）。
#   这种是网络抖动，重试通常就好；"给更长时间"对它毫无用处。
RETRIES = 3
# ★ 只在"下载早期就断"时才重试。已收到的字节超过这个数还失败 → 多半是真慢/真大，
#   重试只会把 3 次超时叠成几小时（踩过这类坑的变体）。
RETRY_ONLY_IF_BELOW = 5 * 1024 * 1024


def repo_size_kb(repo: str) -> int | None:
    """用 API 看仓库体积（KB）。★ 挡掉带大模型的仓库（TTS / 权重 / 数据集）。"""
    from core import gh
    try:
        d = gh.get_json(f"{gh.API}/repos/{repo}")
        return int(d.get("size")) if d and d.get("size") is not None else None
    except Exception:
        return None


def _opener(proxy: str | None):
    """构造 urllib opener。`proxy=None` = **显式直连**（不要系统代理）。"""
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _resolve_proxy(args) -> str | None:
    """决定走不走代理。

    ★ 历史：最早本机代理是 `127.0.0.1:53891`，走它一律 `CONNECT tunnel failed, 502`
      → 当时的结论是"必须显式绕开代理"。现在换成了 `127.0.0.1:59483`，实测**可用**，
      而且**并发时比直连快约 31%**（并发直连 81 KB/s vs 并发走代理 107 KB/s）。
      → 于是改成：默认自动用环境变量里的代理，但**失败会自动回退直连**（见 worker），
        并保留 `--no-proxy` / `--proxy` 两个手动开关。
    """
    if args.no_proxy:
        return None
    if args.proxy:
        return args.proxy
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        v = os.environ.get(k)
        if v:
            return v
    return None


def fetch_source(repo: str, ref: str, dst: Path, log,
                 proxy: str | None = None) -> tuple[bool, int]:
    """取源码。★ **不走 git clone，直接下 tarball**。

    为什么不用 `git clone`：本机环境变量里挂着 `http(s)_proxy=...`，git 会继承它
    → `CONNECT tunnel failed, response 502`；而直连 `github.com` 也被 reset。
    ★ 但 `codeload.github.com` **直连可用**（实测 200），所以走下 tarball。

    ★ 完整性判断用标记文件，不用"目录存在"——
      "目录存在"会把上一次中途失败的残骸当成已完成（踩过）。

    返回 (成功?, 已收字节数)。★ 带上字节数是给**调用方决定要不要重试**用的：
    只有"早期就断"才值得重试，见 RETRY_ONLY_IF_BELOW。
    """
    if (dst / _MARK).exists():
        log(f"    [skip] 已取过源码：{dst.name}")
        return True, 0
    if dst.exists():
        log(f"    [clean] 清掉不完整的源码目录：{dst.name}")
        shutil.rmtree(dst, ignore_errors=True)
    dst.parent.mkdir(parents=True, exist_ok=True)

    url = f"https://codeload.github.com/{repo}/tar.gz/{ref}"
    opener = _opener(proxy)
    # ★★ 分块读 + 双上限：仓库 size 字段只能挡住"一眼大"的，
    #    真正卡住的是"看着不大但拉起来没完"。所以再加【秒数】和【字节】两道闸。
    buf = bytearray()
    t0 = time.time()
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "af-kernel"}),
                         timeout=60) as r:
            while True:
                if time.time() - t0 > MAX_FETCH_SEC:
                    log(f"    [FAIL] 下载超时（>{MAX_FETCH_SEC}s，已收 {len(buf)//1024} KB）")
                    return False, len(buf)
                chunk = r.read(1 << 20)          # 1 MB
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_FETCH_MB * 1024 * 1024:
                    log(f"    [FAIL] 下载超过 {MAX_FETCH_MB} MB，放弃")
                    return False, len(buf)
            data = bytes(buf)
    except Exception as e:
        log(f"    [FAIL] 下载中断：{type(e).__name__}: {str(e)[:120]}"
            f"（已收 {len(buf)//1024} KB）")
        return False, len(buf)

    tmp = dst.parent / (dst.name + "__tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(tmp, filter="data")        # ★ filter=data 挡路径穿越
        entries = [p for p in tmp.iterdir()]
        inner = entries[0] if len(entries) == 1 and entries[0].is_dir() else None
        (inner or tmp).rename(dst)
        if inner:
            tmp.rmdir()
    except Exception as e:
        log(f"    [FAIL] 解包：{type(e).__name__}: {str(e)[:120]}")
        shutil.rmtree(tmp, ignore_errors=True)
        return False, len(data)
    (dst / _MARK).write_text(ref, encoding="utf-8")
    log(f"    [ok] 下载并解包 {len(data) // 1024} KB → {dst.name}")
    return True, len(data)


def make_db(name: str, src: Path, db: Path, log) -> bool:
    if (db / "codeql-database.yml").exists():
        log(f"    [skip] 库已存在：{db.name}")
        return True
    if not CODEQL.exists():
        log(f"    [FAIL] 找不到 codeql：{CODEQL}")
        return False
    db.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(CODEQL), "database", "create", str(db),
           "--language=python", f"--source-root={src}", "--overwrite"]
    t = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0 or not (db / "codeql-database.yml").exists():
        log(f"    [FAIL] 建库：{(p.stdout or '')[-300:]}{(p.stderr or '')[-300:]}")
        return False
    log(f"    [ok] 建库 {db.name}（{time.time() - t:.0f}s）")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("batch", help="a1_batch1.json")
    ap.add_argument("--only", default="")
    ap.add_argument("--targets-out", default="",
                    help="目标表输出路径（默认 core/config/targets_a1.yml）")
    ap.add_argument("--jobs", type=int, default=4,
                    help="并发下载路数。★ 实测单连接被限速在 ~36 KB/s，4 路并发能到 ~107 KB/s")
    ap.add_argument("--no-proxy", action="store_true",
                    help="强制直连（不走 http(s)_proxy）")
    ap.add_argument("--proxy", default="",
                    help="指定代理 URL；默认自动采用环境变量里的代理")
    ap.add_argument("--max-mb", type=float, default=40.0,
                    help="★ 工作树体积上限（MB，默认 40）。今夜为跑超大但活跃的靶放宽（如 120）")
    args = ap.parse_args()
    proxy = _resolve_proxy(args)
    batch = json.load(open(ROOT / args.batch if not Path(args.batch).is_absolute() else args.batch,
                           encoding="utf-8"))["batch"]
    only = {s.strip().lower() for s in args.only.split(",") if s.strip()}

    logf = ROOT / "data" / "target_pool" / f"prepare_{datetime.now().strftime('%Y%m%d_%H%M')}.log"
    fh = open(logf, "w", encoding="utf-8")

    def log(msg: str) -> None:
        print(msg, flush=True)
        fh.write(msg + "\n")
        fh.flush()

    done = {}
    log(f"下载：{args.jobs} 路并发；代理 {proxy or '（直连）'}")

    # ---- 先串行过闸门（体积判断要调 API，很快），选出真正要下的 ----
    #      ★ 体积判断必须串行：它读 tree（一次 API 调用），并发没收益还容易撞限流。
    todo: list[tuple] = []          # (repo, branch, name, src, db, tag)
    for i, b in enumerate(batch, 1):
        repo = b["repo"]
        if only and repo.lower() not in only:
            continue
        name = repo.split("/")[-1].lower().replace("-", "_").replace(".", "_")
        branch = b.get("branch") or "main"
        tag = f"[{i}/{len(batch)}]"
        # ★★ 体积两道闸，**优先用"工作树总字节"**（准确），`size` 字段只作兜底：
        #    GitHub 的 `size` 含 .git 历史，实测能差 7 倍（sampleproj：16.7MB vs 真实 2.3MB）
        #    → 只按 size 判，会把大批能拉的目标误杀（第一批就误杀过 8 个）。
        kb = repo_size_kb(repo)
        # ★★ tree 取不到必须**重试**，不能直接落到 `size` 兜底。
        #    实测 API 会**间歇性失败**（并发跑时更明显），而一失败就会用 `size` 判定 ——
        #    `size` 含 .git 历史、能高估 2~7 倍，于是把能下的目标误杀成"太大"。
        #    第二批第一次跑就踩到了：deepanalyze(真 38MB) / otari(真 33MB) 被当成 57/80MB 跳过。
        try:
            from core import surface as _SU
        except Exception:
            _SU = None
        tb = None
        for _att in range(3):
            try:
                tb = _SU.remote_source_bytes(repo, branch) if _SU else None
            except Exception:
                tb = None
            if tb is not None:
                break
            time.sleep(1.5 * (_att + 1))
        if tb is not None:
            mb = tb / 1024 / 1024
            max_bytes = int(getattr(args, "max_mb", 40.0) * 1024 * 1024)
            if tb > max_bytes:
                log(f"{tag} {repo}  [SKIP] 工作树 {mb:.1f} MB > 上限 {args.max_mb:.0f} MB")
                done[repo] = {"status": "too-big", "tree_mb": round(mb, 1)}
                continue
            log(f"{tag} {repo}  工作树 {mb:.1f} MB（size 字段 {kb/1024:.1f} MB）")
        else:
            if kb is not None and kb > MAX_REPO_KB:
                log(f"{tag} {repo}  [SKIP] 仓库 {kb/1024:.0f} MB > 上限"
                    f"（tree 取不到，按 size 字段兜底）")
                done[repo] = {"status": "too-big", "kb": kb}
                continue
            log(f"{tag} {repo}  体积未知（tree 截断），按 size 兜底继续")
        todo.append((repo, branch, name, SRC_ROOT / _safe(repo),
                     DB_ROOT / f"{_safe(repo)}-db", tag))

    # ---- 流水线：N 路并发下载，**下完一个立刻建库** ----
    #   为什么这么排：下载被**单连接限速**（实测 1 路 36 KB/s vs 4 路 107 KB/s），
    #   而建库是 CPU 活（一个约 150s）。两者**重叠**跑，总时长按 max(下载, 建库) 走而不是相加。
    if todo:
        import queue
        import threading

        q: "queue.Queue" = queue.Queue()

        def worker(repo, branch, name, src, db, tag):
            lines: list[str] = []
            # ★ 尝试序列：每轮交替「代理 / 直连」。两个理由：
            #   ① 代理可能被用户关掉 → 必须能自动回退，否则整批下载全废；
            #   ② 失败多半是**连接被掐断**（IncompleteRead），换一条路重试常能过。
            seq: list[str | None] = []
            for _ in range(RETRIES):
                seq += [proxy, None] if proxy else [None]
            ok = False
            for i, m in enumerate(seq, 1):
                label = "代理" if m else "直连"
                try:
                    ok, nb = fetch_source(repo, branch, src, lines.append, proxy=m)
                except Exception as e:                 # noqa: BLE001
                    ok, nb = False, 0
                    lines.append(f"    [FAIL] 未预期异常：{type(e).__name__}: {str(e)[:120]}")
                if ok or i == len(seq):
                    break
                if nb >= RETRY_ONLY_IF_BELOW:
                    lines.append(f"    [stop] 收了 {nb//1024} KB 才断 → 像真慢/真大，不再重试")
                    break
                lines.append(f"    [retry] {label}失败（仅收 {nb//1024} KB）→ 换一路再试")
            q.put((repo, name, src, db, ok, tag, lines))

        threads = [threading.Thread(target=worker, args=t, daemon=True) for t in todo]
        for t in threads:
            t.start()
        for _ in threads:                              # 主线程边收边建库；日志按完成顺序出，不交错
            repo, name, src, db, ok, tag, lines = q.get()
            log(f"{tag} {repo}")
            for m in lines:
                log(m)
            if not ok:
                done[repo] = {"status": "clone-fail"}
                continue
            ok_d = make_db(name, src, db, log)
            done[repo] = {"status": "ok" if ok_d else "db-fail", "name": name}

    # ---- 生成给 run_round 的目标表 ----
    # ★★ 两条硬规矩（都是踩出来的）：
    #   ① **扫描 DB_ROOT 里所有建好的库**，而不是只收"本批成功的" ——
    #      否则写一次就把上一批的目标从表里挤掉（第一批 7 个就这么丢过一次，
    #      虽然磁盘上的库和源码还在，但表里没了，run_round 就看不到它们）。
    #   ② repo 名从**所有批次文件**里反查（不然扫到的库对不上仓库）。
    import yaml
    repo_of: dict[str, str] = {}
    for bp in sorted(POOL.glob("a1_batch*.json")):
        try:
            for b in json.load(open(bp, encoding="utf-8")).get("batch", []):
                if b.get("repo"):
                    repo_of[_safe(b["repo"])] = b["repo"]
        except Exception:
            continue
    tgt = {"version": 1, "updated": datetime.now().strftime("%Y-%m-%d"),
           "note": "A1 目标表（由 app/prepare_targets.py 扫描 _targets/a1db 生成，"
                   "含所有批次已建好的库）", "targets": {}}
    for d in sorted(DB_ROOT.glob("*-db")):
        if not (d / "codeql-database.yml").exists():
            continue
        safe = d.name[:-3]                       # 去掉 "-db"
        repo = repo_of.get(safe)
        if not repo:
            continue
        src = SRC_ROOT / safe
        name = repo.split("/")[-1].lower().replace("-", "_").replace(".", "_")
        # ★ 不能 relative_to(ROOT)：_targets 跟本项目是**兄弟目录**，不在它下面（会 ValueError）
        tgt["targets"][name] = {
            "repo": repo,
            "db": Path(os.path.relpath(d, ROOT)).as_posix(),
            "src": Path(os.path.relpath(src, ROOT)).as_posix(),
        }
    dst = Path(args.targets_out) if getattr(args, "targets_out", "") \
        else (ROOT / "core" / "config" / "targets_a1.yml")
    dst.write_text(yaml.safe_dump(tgt, allow_unicode=True, sort_keys=False), encoding="utf-8")

    ok = sum(1 for v in done.values() if v.get("status") == "ok")
    log(f"\n== 备料完成：本批成功 {ok} / {len(done)}；目标表 {len(tgt['targets'])} 个 → {dst}")
    log(f"   日志 → {logf}")
    fh.close()
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
