#!/usr/bin/env python
"""app/run_all.py - one-shot driver: prepare -> scan -> report.

Design notes
  1. **Resumable.** Each stage has a sentinel file; if the sentinel exists the stage is
     skipped, so a run that was interrupted does not redo finished work. Long pipeline
     runs must be restartable, because background child processes can die mid-run.
  2. **Fail fast.** If a stage exits non-zero, the run stops there instead of continuing,
     because later stages consume the earlier stages' output.
  3. **Look before you leap.** `--plan` prints what each stage would do and why it would
     be skipped, and writes nothing at all.
  4. **Everything is logged.** stdout is teed to `data/target_pool/_run_all_<tag>.log`.

Sentinels (deliberately chosen as files that only appear once a stage has finished):
  prepare : every target in the yml has both a `src` directory and a `db` directory
  scan    : `out/round-<tag>/meta.json` exists (written as the very last step of run_round)
  report  : `out/round-<tag>/report_draft.md` exists and is not older than meta.json

Usage
  # print the plan, execute nothing (recommended first step)
  python app/run_all.py --tag demo --targets-file core/config/targets.yml --only sampleagent,sampletoolkit --plan

  # a real run against an existing target table (skips prepare)
  AF_SINKS_FS=1 python app/run_all.py --tag demo --targets-file core/config/targets.yml --only sampleagent,sampletoolkit

  # start from a batch of repos (runs prepare automatically)
  python app/run_all.py --tag demo --batch data/target_pool/batch1.json --targets-file core/config/targets.yml

  # redo selected stages
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

STAGES = ("prepare", "scan", "report")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Log:
    """Write to stdout and to a file at the same time."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(path, "a", encoding="utf-8")

    def __call__(self, msg: str = "") -> None:
        line = f"[{_now()}] {msg}" if msg else ""
        print(line, flush=True)
        self.fh.write(line + "\n")
        self.fh.flush()

    def raw(self, line: str) -> None:
        """Forward a child process's output verbatim (no added timestamp)."""
        print(line, end="", flush=True)
        self.fh.write(line)
        self.fh.flush()

    def close(self) -> None:
        self.fh.close()


def run_stage(log: Log, cmd: list[str], env: dict | None = None) -> int:
    """Run a child process, forwarding its output live. Returns the exit code."""
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
    log(f"    <- exit {p.returncode}, {time.time() - t0:.1f}s")
    return p.returncode


def load_targets(yml: Path) -> list[dict]:
    """Read the target table into [{short, repo, src, db}] with absolute paths."""
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
    """List targets that are not ready yet (src directory or database missing)."""
    bad = []
    for t in targets:
        if not t["src"] or not t["src"].is_dir():
            bad.append(f"{t['short']} (no src)")
            continue
        if not t["db"] or not (t["db"] / "codeql-database.yml").exists():
            bad.append(f"{t['short']} (no db)")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(
        description="one-shot driver: prepare -> scan -> report (resumable)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--tag", required=True, help="round name; decides out/round-<tag>/ and the log name")
    ap.add_argument("--targets-file", default="", help="target table yml (default core/config/targets.yml)")
    ap.add_argument("--batch", default="", help="only runs prepare if given (batch1.json)")
    ap.add_argument("--only", default="", help="comma-separated subset of targets (passed to prepare and scan)")
    ap.add_argument("--gate-mode", default="detect", choices=["", "alive", "detect"],
                    help="health gate mode for scan (default detect; use alive when reporting to maintainers)")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--max-mb", type=float, default=40.0)
    ap.add_argument("--plan", "--dry-run", dest="plan", action="store_true",
                    help="print what each stage would do and why it is skipped; execute nothing")
    ap.add_argument("--force", default="", help="stages to redo (comma-separated, or 'all')")
    ap.add_argument("--skip", default="", help="stages to skip (comma-separated)")
    ap.add_argument("--env", action="append", default=[],
                    help="extra environment variable, repeatable, e.g. --env AF_SINKS_FS=1")
    args = ap.parse_args()

    tag = args.tag
    yml = Path(args.targets_file) if args.targets_file else (ROOT / "core" / "config" / "targets.yml")
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
    log(f"run_all  tag={tag} | targets-file={os.path.relpath(yml, ROOT).replace(os.sep, '/') if yml.exists() else yml}")
    log(f"  only={args.only or '(all)'} | gate-mode={args.gate_mode} | plan={args.plan}")
    log(f"  force={sorted(force) or 'none'} | skip={sorted(skip) or 'none'}"
        f" | env {[k + '=' + v for k, v in (kv.split('=', 1) for kv in args.env)] or 'none'}")
    log("=" * 78)

    # ---------- prepare ----------
    do_prepare, why_prepare = False, ""
    if args.batch:
        if yml.exists():
            miss = prepare_missing(load_targets(yml))
            if miss and "prepare" not in force:
                do_prepare, why_prepare = True, f"target table exists but {len(miss)} not ready: {', '.join(miss[:6])}"
            elif miss:
                do_prepare, why_prepare = True, f"--force prepare, and {len(miss)} not ready"
            else:
                do_prepare, why_prepare = False, "src and db present for every target"
        else:
            do_prepare, why_prepare = True, "target table does not exist"
    else:
        do_prepare, why_prepare = False, "no --batch, so prepare is skipped"

    # ---------- scan ----------
    meta = round_dir / "meta.json"
    scan_sentinel = meta.exists()
    if scan_sentinel and "scan" not in force:
        do_scan, why_scan = False, f"{os.path.relpath(meta, ROOT)} exists, so this round finished"
    elif scan_sentinel:
        do_scan, why_scan = True, "--force scan"
    else:
        do_scan = True
        why_scan = "no meta.json"
        if round_dir.exists():
            why_scan += " (directory exists but the previous round did not finish; it restarts from scan)"

    # ---------- report ----------
    rep = round_dir / "report_draft.md"
    if rep.exists() and meta.exists() and rep.stat().st_mtime >= meta.stat().st_mtime and "report" not in force:
        do_report, why_report = False, "report_draft.md is newer than meta.json"
    elif not meta.exists() and scan_sentinel is False:
        do_report, why_report = False, "upstream scan has not finished, so this stage is deferred"
    else:
        do_report = True
        why_report = ("--force report" if "report" in force else
                      ("report_draft.md missing" if not rep.exists() else "report_draft.md older than meta.json"))

    # Single source of truth for "should this stage run".
    plan: dict[str, tuple[bool, str]] = {}
    for st, do, why in (("prepare", do_prepare, why_prepare),
                        ("scan", do_scan, why_scan),
                        ("report", do_report, why_report)):
        plan[st] = (False, "excluded by --skip") if st in skip else (do, why)

    log("")
    log("stage plan:")
    for st in STAGES:
        do, why = plan[st]
        log(f"  {'RUN ' if do else 'skip'}  {st:<8} {why}")

    if args.plan:
        log("")
        log("--plan: nothing above was executed. Drop --plan to run for real.")
        log.close()
        return 0

    if not yml.exists() and not plan["prepare"][0]:
        log(f"\n[FATAL] target table does not exist and prepare will not run: {yml}")
        log("        add --batch to generate it, or point --targets-file at an existing table")
        log.close()
        return 2

    results: list[tuple[str, str, float]] = []

    if plan["prepare"][0]:
        log("")
        log("-------- prepare (fetch sources + build CodeQL databases) --------")
        cmd = [PY, ROOT / "app" / "prepare_targets.py", args.batch,
               "--targets-out", str(yml), "--jobs", str(args.jobs), "--max-mb", str(args.max_mb)]
        if args.only:
            cmd += ["--only", args.only]
            # The two --only flags do not mean the same thing: prepare matches the full repo
            # name (owner/name), run_round matches the short name. Mixing them up makes
            # prepare match nothing, which looks like "nothing was downloaded".
            log("    note: --only matches the full repo name (owner/name) in prepare, "
                "but the short name in scan; run them separately if needed.")
        t0 = time.time()
        rc = run_stage(log, cmd, env)
        results.append(("prepare", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))
        if rc != 0:
            log(f"\n[STOP] prepare failed (exit {rc}); not continuing")
            log.close()
            return rc

    if plan["scan"][0]:
        log("")
        log("-------- scan (static candidates + triage) --------")
        cmd = [PY, ROOT / "app" / "run_round.py", "--tag", tag, "--targets-file", str(yml),
               "--gate-mode", args.gate_mode]
        if args.only:
            cmd += ["--only", args.only]
        t0 = time.time()
        rc = run_stage(log, cmd, env)
        results.append(("scan", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))
        if rc != 0:
            log(f"\n[STOP] scan failed (exit {rc})")
            log("       re-running the same command resumes it (this stage will restart from scan)")
            log.close()
            return rc

    if plan["report"][0]:
        log("")
        log("-------- report (render the draft) --------")
        if not meta.exists():
            log(f"[STOP] scan did not finish (missing {os.path.relpath(meta, ROOT)}); skipping report")
            log.close()
            return 3
        t0 = time.time()
        rc = run_stage(log, [PY, ROOT / "app" / "make_report.py", round_dir], env)
        results.append(("report", "ok" if rc == 0 else f"FAIL({rc})", time.time() - t0))
        if rc != 0:
            log(f"\n[STOP] report failed (exit {rc})")
            log.close()
            return rc

    log("")
    log("=" * 78)
    log("done. stages:")
    for st in STAGES:
        got = next((r for r in results if r[0] == st), None)
        if got:
            log(f"   {st:<8} ran  - {got[1]:<9} {got[2]:.1f}s")
        else:
            log(f"   {st:<8} skip - {plan[st][1]}")
    log("")
    log(f"   report draft -> {os.path.relpath(rep, ROOT) if rep.exists() else '(not generated)'}")
    log("=" * 78)
    log.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
