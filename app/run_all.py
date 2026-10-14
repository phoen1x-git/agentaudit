#!/usr/bin/env python
"""app/run_all.py —— 一键入口：prepare → scan → report → 账本

★ 设计要点（2026-10-13，依据 docs/221 · P3）
  1. **断点续跑**：每个阶段都有「哨兵」，存在就跳过 ⇒ 中途被杀后重跑**不会重复干活**。
     起因：本项目实测过「后台子进程会随'回合结束'被杀」—— 长流程必须能重入。
  2. **失败即停**：任一阶段非 0 退出 ⇒ 立刻停、报出退出码（**不"继续跑后面的"**，
     因为后面的阶段依赖前面的产物）。
  3. **先看后做**：`--plan` 只打印「每个阶段会做什么 / 为什么跳过」，**一个字节都不写**。
  4. **全程留痕**：stdout 同时 tee 到 `data/target_pool/_run_all_<tag>.log`。

★ 哨兵（= 断点续跑的判据，刻意都选「**跑完才会出现的文件**」）
  ① prepare : 目标表 yml 里**每个目标**的 `src` 目录 + `db` 目录都存在
  ② scan    : `out/round-<tag>/meta.json` 存在
              ★ 它是 `run_round.py` **最后一步**才写的（见该文件 write_meta）
              ⇒ 有它 = 那一轮真的跑完了；没有它 = 没跑完或被中途杀掉 ⇒ 重跑
  ③ report  : `out/round-<tag>/report_draft.md` 存在，**且不比 meta.json 旧**
              （旧了说明轮次数据更新过、报告要重出）
  ④ ledger  : **无哨兵** —— `run_round.py` 已自动记账，这一步只是**只读**地出个汇总

用法（例）
  # 只看会做什么（推荐第一步永远先跑这个）
  python app/run_all.py --tag demo --targets-file core/config/targets_tp2x.yml --only sampleagent,sampletoolkit --plan

  # 真的跑：已有目标表（跳过 prepare）
  AF_SINKS_FS=1 python app/run_all.py --tag demo --targets-file core/config/targets_tp2x.yml --only sampleagent,sampletoolkit

  # 从一批 repo 开始（会自动 prepare）
  python app/run_all.py --tag demo --batch data/target_pool/a1_batch1.json --targets-file core/config/targets_a1.yml

  # 强制重做某几个阶段
  python app/run_all.py --tag demo --targets-file ... --force scan,report
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
OUT = ROOT / "out"
POOL = ROOT / "data" / "target_pool"

STAGES = ("prepare", "scan", "report", "ledger")


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Log:
    """stdout + 文件 双写。"""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(path, "a", encoding="utf-8")

    def __call__(self, msg: str = "") -> None:
        line = f"[{_now()}] {msg}" if msg else ""
        print(line, flush=True)
        self.fh.write(line + "\n")
        self.fh.flush()

    def raw(self, line: str) -> None:
        """子进程输出的原样转发（不额外加时间戳）。"""
        print(line, end="", flush=True)
        self.fh.write(line)
        self.fh.flush()

    def close(self) -> None:
        self.fh.close()


def run_stage(log: Log, cmd: list[str], env: dict | None = None) -> int:
    """跑一个子进程，输出实时转发到 log。返回退出码。"""
    log(f"    $ {' '.join(str(c) for c in cmd)}")
    t0 = time.time()
    p = subprocess.Popen(
        [str(c) for c in cmd],
        cwd=str(ROOT),
        env=env or os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert p.stdout is not None
    for line in p.stdout:
        log.raw(line)
    p.wait()
    log(f"    ← 退出码 {p.returncode}，耗时 {time.time() - t0:.1f}s")
    return p.returncode


# --------------------------------------------------------------------------
# 目标表 / 哨兵
# --------------------------------------------------------------------------
def load_targets(yml: Path) -> list[dict]:
    """读目标表 → [{short, repo, src, db}]（src/db 已解析成绝对路径）。"""
    d = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
    out = []
    for short, v in (d.get("targets") or {}).items():
        v = v or {}
        out.append({
            "short": short,
            "repo": v.get("repo") or "",
            "src": (ROOT / v["src"]).resolve() if v.get("src") else None,
            "db": (ROOT / v["db"]).resolve() if v.get("db") else None,
        })
    return out


def prepare_missing(targets: list[dict]) -> list[str]:
    """列出「还没准备好」的目标（src 目录或 db 目录缺失）。"""
    bad = []
    for t in targets:
        if not t["src"] or not t["src"].is_dir():
            bad.append(f"{t['short']}（src 缺）")
            continue
        if not t["db"] or not (t["db"] / "codeql-database.yml").exists():
            bad.append(f"{t['short']}（db 缺）")
    return bad


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="一键入口：prepare → scan → report → 账本（支持断点续跑）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--tag", required=True, help="轮次名（决定 out/round-<tag>/ 与日志名）")
    ap.add_argument("--targets-file", default="", help="目标表 yml（默认 core/config/targets_a1.yml）")
    ap.add_argument("--batch", default="", help="★ 给了它才会跑 prepare（a1_batch1.json）")
    ap.add_argument("--only", default="", help="逗号分隔，只跑其中几个靶（透传给 prepare 与 scan）")
    ap.add_argument("--gate-mode", default="detect", choices=["", "alive", "detect"],
                    help="scan 的健康门模式（默认 detect；★ 报洞给开发者时用 alive）")
    # prepare 透传
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--max-mb", type=float, default=40.0)
    # 可控性
    ap.add_argument("--plan", "--dry-run", dest="plan", action="store_true",
                    help="★ 只打印每阶段会做什么/为什么跳过，不执行任何东西")
    ap.add_argument("--force", default="",
                    help="强制重做的阶段（逗号分隔，如 scan,report；也可 all）")
    ap.add_argument("--skip", default="",
                    help="显式跳过的阶段（逗号分隔）")
    ap.add_argument("--env", action="append", default=[],
                    help="透传环境变量，可重复，如 --env AF_SINKS_FS=1")
    args = ap.parse_args()

    tag = args.tag
    yml = Path(args.targets_file) if args.targets_file else (ROOT / "core" / "config" / "targets_a1.yml")
    if not yml.is_absolute():
        yml = (ROOT / yml).resolve()
    round_dir = OUT / f"round-{tag}"
    log = Log(POOL / f"_run_all_{tag}.log")

    force = {s.strip().lower() for s in args.force.split(",") if s.strip()}
    if "all" in force:
        force = set(STAGES)
    skip = {s.strip().lower() for s in args.skip.split(",") if s.strip()}

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    for kv in args.env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            env[k.strip()] = v

    log("=" * 78)
    log(f"★ run_all  tag={tag} ｜ targets-file={os.path.relpath(yml, ROOT).replace(os.sep, '/') if yml.exists() else yml}")
    log(f"  only={args.only or '(全部)'} ｜ gate-mode={args.gate_mode} ｜ plan={args.plan}")
    log(f"  force={sorted(force) or '无'} ｜ skip={sorted(skip) or '无'}"
        f" ｜ env 透传 {[k + '=' + v for k, v in (kv.split('=', 1) for kv in args.env)] or '无'}")
    log("=" * 78)

    # ---------- ① prepare ----------
    do_prepare, why_prepare = False, ""
    if args.batch:
        if yml.exists():
            miss = prepare_missing(load_targets(yml))
            if miss and "prepare" not in force:
                do_prepare, why_prepare = True, f"目标表已存在但有 {len(miss)} 个没备齐：{', '.join(miss[:6])}"
            elif miss:
                do_prepare, why_prepare = True, f"--force prepare，且有 {len(miss)} 个没备齐"
            else:
                do_prepare, why_prepare = False, "目标表里每个靶的 src + db 都在"
        else:
            do_prepare, why_prepare = True, "目标表不存在"
    else:
        do_prepare, why_prepare = False, "没给 --batch ⇒ 不跑 prepare"

    # ---------- ② scan ----------
    meta = round_dir / "meta.json"
    scan_sentinel = meta.exists()
    if scan_sentinel and "scan" not in force:
        do_scan, why_scan = False, f"{os.path.relpath(meta, ROOT)} 存在 ⇒ 这一轮真的跑完了"
    elif scan_sentinel:
        do_scan, why_scan = True, "--force scan"
    else:
        do_scan = True
        why_scan = "无 meta.json"
        if round_dir.exists():
            why_scan += "（★ 目录已存在但上一轮**未跑完**——重跑会从扫描开始）"

    # ---------- ③ report ----------
    rep = round_dir / "report_draft.md"
    if rep.exists() and meta.exists() and rep.stat().st_mtime >= meta.stat().st_mtime and "report" not in force:
        do_report, why_report = False, "report_draft.md 比 meta.json 新"
    elif not meta.exists() and scan_sentinel is False:
        do_report, why_report = False, "★ 上游 scan 还没跑完 ⇒ 本阶段先不做"
    else:
        do_report = True
        why_report = ("--force report" if "report" in force else
                      ("report_draft.md 不存在" if not rep.exists() else "report_draft.md 比 meta.json 旧"))

    # ---------- ④ ledger ----------
    do_ledger = True

    # ---- 汇总成计划（★ 唯一的「要不要做」来源；下面的执行全部读它，避免两套判断打架）----
    plan: dict[str, tuple[bool, str]] = {}
    for st, do, why in (("prepare", do_prepare, why_prepare),
                        ("scan", do_scan, why_scan),
                        ("report", do_report, why_report),
                        ("ledger", do_ledger, "只读汇总（无哨兵）")):
        plan[st] = (False, "被 --skip 指定") if st in skip else (do, why)

    log("")
    log("阶段计划：")
    for st in STAGES:
        do, why = plan[st]
        log(f"  {'▶ 执行' if do else '· 跳过'}  {st:<8} {why}")

    if args.plan:
        log("")
        log("★ --plan：以上只是计划，**没有执行任何东西**。去掉 --plan 即真跑。")
        log.close()
        return 0

    # 目标表不存在且不 prepare ⇒ 提前挡住（否则 scan 会失败得很晚）
    if not yml.exists() and not plan["prepare"][0]:
        log(f"\n[FATAL] 目标表不存在且不跑 prepare：{yml}")
        log("        ⇒ 加 --batch 让它先生成，或直接给一个已存在的 --targets-file")
        log.close()
        return 2

    results: list[tuple[str, str, float]] = []

    # ---------- 执行 ① ----------
    if plan["prepare"][0]:
        log("")
        log("──────── ① prepare（下载 + 建 CodeQL 库）────────")
        cmd = [PY, ROOT / "app" / "prepare_targets.py", args.batch,
               "--targets-out", str(yml), "--jobs", str(args.jobs), "--max-mb", str(args.max_mb)]
        if args.only:
            cmd += ["--only", args.only]
            # ★ 两个 --only 的语义**不一样**，容易踩：
            #   prepare_targets 比的是 **repo 全名**（`geekan/sampleagent`），
            #   run_round       比的是 **短名**（`sampleagent`）。
            #   混用会让 prepare 一个都不匹配（看起来"什么都没下"，其实是被 --only 滤没了）。
            log("    ★ 注意：--only 在 prepare 里比的是 **repo 全名**（如 geekan/sampleagent），"
                "在 scan 里比的是**短名**（如 sampleagent）—— 两者语义不同，请按需分开跑。")
        t0 = time.time()
        rc = run_stage(log, cmd, env)
        results.append(("prepare", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))
        if rc != 0:
            log(f"\n[STOP] prepare 失败（退出码 {rc}）⇒ 停止，不继续后面的阶段")
            log.close()
            return rc

    # ---------- 执行 ② ----------
    if plan["scan"][0]:
        log("")
        log("──────── ② scan（静态候选 + LLM 判定）────────")
        cmd = [PY, ROOT / "app" / "run_round.py", "--tag", tag, "--targets-file", str(yml),
               "--gate-mode", args.gate_mode]
        if args.only:
            cmd += ["--only", args.only]
        t0 = time.time()
        rc = run_stage(log, cmd, env)
        results.append(("scan", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))
        if rc != 0:
            log(f"\n[STOP] scan 失败（退出码 {rc}）⇒ 停止")
            log("       ★ 重跑同一条命令即可续上（本阶段没跑完 ⇒ 下次仍会从 scan 开始）")
            log.close()
            return rc

    # ---------- 执行 ③ ----------
    if plan["report"][0]:
        log("")
        log("──────── ③ report（出报告草稿）────────")
        if not meta.exists():
            log(f"[STOP] scan 没跑完（缺 {os.path.relpath(meta, ROOT)}）⇒ 不做 report")
            log.close()
            return 3
        t0 = time.time()
        rc = run_stage(log, [PY, ROOT / "app" / "make_report.py", round_dir], env)
        results.append(("report", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))
        if rc != 0:
            log(f"\n[STOP] report 失败（退出码 {rc}）")
            log.close()
            return rc

    # ---------- 执行 ④（只读）----------
    if plan["ledger"][0]:
        log("")
        log("──────── ④ 账本汇总（只读）────────")
        t0 = time.time()
        rc = run_stage(log, [PY, ROOT / "core" / "candidate_ledger.py", "stats"], env)
        results.append(("ledger", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))

    # ---------- 收尾 ----------
    log("")
    log("=" * 78)
    log("★ 完成。各阶段：")
    for st in STAGES:
        got = next((r for r in results if r[0] == st), None)
        if got:
            log(f"   {st:<8} 执行 · {got[1]:<9} {got[2]:.1f}s")
        else:
            log(f"   {st:<8} 跳过 · {plan[st][1]}")
    log("")
    log(f"   报告草稿 → {os.path.relpath(rep, ROOT) if rep.exists() else '（未生成）'}")
    log("   候选台账 → python core/candidate_ledger.py list --status todo")
    log("=" * 78)
    log.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
