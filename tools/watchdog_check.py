"""看门狗判定 —— 「现在有没有人在干活？」（给夜班自动化任务用的单命令入口）。

★ 为什么要封装成脚本：PowerShell 工具的输出**不稳定**（实测两次无返回），
  而判定"有人/没人"是夜班的**第一步、也是最重要的一步** —— 押在不可靠的通道上不行。
  → python 的输出是可靠的，且**判定逻辑只写一次**（`docs/189` 那条"两套拼法"的教训）。

★★ 三层判据（与夜班提示词一致）：
  层1  看进程：有没有 python 在跑我们的脚本（`wmic` 尽力而为；拿不到就跳过，不据此下结论）
  层2  看最新日志 mtime：★ **必须同时看两处** ——
        · `out/round-*/scan.log`（扫描/判定阶段写这里）
        · `data/target_pool/_*.log`（★ 建库/备料写这里，**不在 out/ 下**，是旧判据的盲区）
  层3  合成判定（★ 不确定时倾向「有人在跑」——误判"没人"的代价是重复劳动）

输出（一行结论 + 依据）：
  A = 有人在跑（本轮只写日志、不挂任务）
  B = 链条断了（接手 + 挂新任务）
  C = 疑似卡住（先杀掉卡住的，再按 B）

用法：
    python tools/watchdog_check.py            # 默认阈值 25 分钟
    python tools/watchdog_check.py --min 15
"""
from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
POOL = ROOT / "data" / "target_pool"

SCRIPTS = ("run_round", "prepare_tp2x", "rejudge", "judge_round",
           "ab_judge", "eval_gt", "check_cand")


def newest_logs(limit: int = 6) -> list[tuple[str, float]]:
    """★ 最近活动时刻（返回 [(名字, 距今秒数), ...]，按新到旧）。

    ★★ 2026-10-13 扩充：原来**只看** `out/round-*/scan.log` 和 `data/target_pool/_*.log`
      —— 这两个只覆盖"扫描 / 建库 / 判定"。而**主会话写文档、读代码、做分析**时
      它们**一个都不动** ⇒ 会把"我正忙着"误判成"没人跑" ⇒ 误判 B ⇒
      夜班与主会话**并行**干活（抢配额，正是用户要避免的浪费）。
      → 现在把 `docs/*.md`、`.workbuddy/memory/*.md`、`out/round-*/findings.json` 一并算作活动。
    """
    now = time.time()
    found: list[tuple[str, float]] = []
    mem_dir = ROOT.parent / ".workbuddy" / "memory"
    for pat, label in ((str(OUT / "round-*" / "scan.log"), "scan"),
                       (str(POOL / "_*.log"), "tasklog"),
                       (str(OUT / "round-*" / "findings.json"), "findings"),
                       (str(ROOT / "docs" / "*.md"), "docs"),
                       (str(ROOT / "docs_night" / "*.md"), "docs_night"),
                       (str(mem_dir / "*.md"), "memory"),
                       # ★★ 再补一层：**改代码本身也是"在干活"** —— 实测踩到：
                       #    主会话在改 `tools/*.py` 时，上面五处一个都不动 ⇒ 仍被判 B
                       #    ⇒ 夜班可能与我并行接手。工具/内核/入口的改动同样算活动。
                       (str(ROOT / "tools" / "*.py"), "tool"),
                       (str(ROOT / "core" / "*.py"), "core"),
                       (str(ROOT / "app" / "*.py"), "app")):
        for f in glob.glob(pat):
            try:
                found.append((f"{label}:{os.path.basename(f)}", now - os.path.getmtime(f)))
            except OSError:
                pass
    found.sort(key=lambda x: x[1])
    return found[:limit]


def unfinished_rounds() -> list[str]:
    """★ 未完成的轮次 = `out/round-*/` 目录存在但**缺 `meta.json`**。

    ★★ 2026-10-13 新增：这是「卡住」的**可靠证据**，而且**不需要进程命令行**。

    为什么必须有这条：原来判 C 要靠"强证据（wmic 拿到命令行）"，但
    **新版 Windows 已移除 `wmic`** ⇒ 强证据永远拿不到 ⇒ **C 路径实际永不触发**（死代码）。
    换用文件系统判据后：
      · 轮次**在跑** ⇒ 有 `scan.log` 但暂时没 `meta.json` + `scan.log` 在动 ⇒ 层3 判 A（活动新鲜）；
      · 轮次**卡住/被杀** ⇒ 同样缺 `meta.json`，但活动已停滞 ⇒ 层3 判 **C**（点名是哪个轮次）；
      · 根本没有未完成轮次 ⇒ 判 **B**（没人开过活/都跑完了）。
    ★ 与昨晚看门狗自己的诊断口径一致（"`out/round-staticdyn0/` 只有 `scan.log`、无 `meta.json`"）。
    """
    out: list[str] = []
    for d in glob.glob(str(OUT / "round-*")):
        if not os.path.isdir(d):
            continue
        if not os.path.exists(os.path.join(d, "meta.json")):
            age = -1.0
            logs = glob.glob(os.path.join(d, "*.log")) + [os.path.join(d, "scan.log")]
            for f in logs:
                if os.path.exists(f):
                    try:
                        age = max(age, time.time() - os.path.getmtime(f))
                    except OSError:
                        pass
            # ★★ 只看「最近 24h 内有动静」的 —— 否则会把**几天前的历史遗留**（当时就没跑完的旧轮次）
            #    当成"现在卡住"，判出 C 却无进程可杀（实测踩到：列出 3 天前的 a1b-ctxoff2 等）。
            if age >= 0:
                if age > 24 * 3600:
                    continue
            else:
                try:
                    if time.time() - os.path.getctime(d) > 24 * 3600:
                        continue
                except OSError:
                    pass
            out.append("%s（无 meta.json，日志停在 %s）"
                       % (os.path.basename(d), ("%.0fs 前" % age) if age >= 0 else "无日志"))
    return out


def running_procs() -> list[str]:
    """尽力列出「在跑我们脚本」的 python 进程。★ 命中分**强/弱**两档。

    ★★ 2026-10-13 修（**假 C 的根因**，夜班自己记过 3 次「它自己就是 python ⇒ 恒 ≥1」）：
      · `wmic` 在新版 Windows **已被移除** ⇒ 方法1 必然失败 ⇒ **必然降级到方法2**；
      · 方法2 的 `tasklist` **只给进程名、不给命令行** ⇒ 连**正在执行本脚本的自己**也数进去
        ⇒ 层1 **恒 ≥1** ⇒ 层3 见「有进程 + 日志没动」就判 **C（假 C）**。
      修法两道：
        ① tasklist 结果**按 PID 排除自己与父进程**（CSV 输出里带 PID）；
        ② tasklist 命中一律标 `weak:` 前缀 = **弱证据**，层3 **不许**仅凭弱证据判 C
           （没有命令行就无法区分"我们的任务卡住了"和"只是一个无关的 python"）。
      → 强证据（命令行含 `run_round` 等）**只有 wmic 能给**；给不了就最多判 B，不判 C。
    """
    me = os.getpid()
    try:
        me_parent = os.getppid()
    except Exception:
        me_parent = -1
    hits: list[str] = []
    # 方法1：wmic（有命令行 ⇒ 强证据；新 Windows 无此命令，失败即降级）
    try:
        r = subprocess.run(["wmic", "process", "where", "name='python.exe'", "get", "ProcessId,CommandLine"],
                           capture_output=True, text=True, timeout=25)
        for line in (r.stdout or "").splitlines():
            if any(s in line for s in SCRIPTS):
                hits.append(line.strip()[:150])
    except Exception:
        pass
    if hits:
        return hits
    # 方法2：tasklist（只有名字 ⇒ 弱证据；★ 必须排除自己）
    try:
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=25)
        for line in (r.stdout or "").splitlines():
            if "python.exe" not in line.lower():
                continue
            pid = None
            try:
                pid = int(line.split('","')[1])
            except Exception:
                pid = None
            if pid is not None and pid in (me, me_parent):
                continue                       # ★ 排除本脚本自己（假 C 的根源）
            hits.append("weak:python.exe(tasklist,pid=%s,无命令行)" % pid)
    except Exception:
        pass
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min", type=int, default=25, help="多久没动算「停下」（分钟）")
    a = ap.parse_args()
    thr = a.min * 60

    logs = newest_logs()
    procs = running_procs()
    unfinished = unfinished_rounds()
    newest_age = logs[0][1] if logs else float("inf")

    print("=" * 72)
    print(f"看门狗判定 @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}（阈值 {a.min} 分钟）")
    print("=" * 72)
    print("\n[层1] 在跑我们脚本的 python 进程：")
    if procs:
        for p in procs[:6]:
            tag = "· 弱证据" if p.startswith("weak:") else "★ 强证据（命令行命中）"
            print(f"   {tag} {p}")
    else:
        print("   （没查到 —— ★ 注意：查不到不等于没有，见层3 的保守规则）")

    print("\n[层2] 最近活动 mtime（★ scan / tasklog / findings / docs / memory / tool / core / app 八处都看）：")
    if logs:
        for name, age in logs:
            print(f"   {int(age):>6}s 前   {name}")
    else:
        print("   （一个日志都没有）")

    print("\n[层2b] 未完成的轮次（有目录、缺 meta.json）★ C 的唯一判据：")
    if unfinished:
        for u in unfinished[:5]:
            print(f"   ★ {u}")
    else:
        print("   （无 —— 所有轮次都跑完了）")

    # ---- 层3 合成判定（★ C 的判据 = 「有未完成轮次 + 活动停滞」，不依赖命令行）----
    strong = [p for p in procs if not p.startswith("weak:")]
    weak_n = len(procs) - len(strong)
    if newest_age < thr:
        verdict, why = "A", f"最近活动在 {int(newest_age)}s 内 → 有人在跑（保守判定）"
    elif unfinished:
        verdict, why = ("C", f"有 {len(unfinished)} 个未完成轮次且最近活动 {int(newest_age)}s 没动"
                             f" → 疑似卡住：{'、'.join(unfinished[:3])}")
    else:
        verdict, why = ("B", f"最近活动 {int(newest_age) if logs else -1}s 没动，"
                             f"且**没有未完成轮次** → 链条断了（不是卡住）"
                             f"；弱证据 {weak_n} 条")

    print("\n" + "=" * 72)
    print(f"★ 判定：【情况 {verdict}】 {why}")
    print("   A = 有人在跑 → 本轮只写日志，★ 不挂新任务、不起新扫描")
    print("   B = 链条断了 → 接手推一件事 + ★ 挂新后台任务")
    print("   C = 疑似卡住 → 先杀掉卡住的进程（记明理由），再按 B 接手")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
