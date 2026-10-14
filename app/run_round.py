"""Run one scan round.

    python app/run_round.py --tag my-round --targets-file core/config/targets.yml

Turns a set of pre-built CodeQL databases into `out/round-<tag>/`:

    findings.tsv    one row per candidate site
    findings.json   the same rows as JSON
    verdicts.json   the triage verdicts
    scan.log        what happened
    meta.json       run metadata (config stamps, cost, counters)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import static_frontend as SF                  # noqa: E402
from core import finding as F                           # noqa: E402
from core import gate as G                              # noqa: E402
from core import round as R                             # noqa: E402


def load_targets(path: str | None = None) -> dict:
    """Load the target table. Default `core/config/targets.yml`, override with --targets-file."""
    import yaml
    p = Path(path) if path else (ROOT / "core" / "config" / "targets.yml")
    if not p.is_absolute():
        p = ROOT / p
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    out = {}
    for name, t in (cfg.get("targets") or {}).items():
        out[name] = {
            "repo": t.get("repo"),
            "db": (ROOT / t["db"]).resolve() if t.get("db") else None,
            "src": (ROOT / t["src"]).resolve() if t.get("src") else None,
        }
    return out


TARGETS = load_targets()


def _cfg_stamp() -> dict:
    """Version stamp: rule set + content hashes of the external config and key modules."""
    out = {"rules": SF.QUERIES}
    for name in ("sinks.yml", "filters.yml", "static_frontend.py", "finding.py",
                 "cfg.py", "llm_judge.py", "consistency.py", "duality.py"):
        p = (ROOT / "core" / "config" / name) if name.endswith(".yml") else (ROOT / "core" / name)
        if p.exists():
            out[name] = hashlib.sha1(p.read_bytes()).hexdigest()[:12]
    # Stamp the triage rubric separately: changing one line of the prompt can flip a verdict,
    # so the run has to record which version of the rubric produced it.
    try:
        from core import llm_judge as _LJ
        out["rubric"] = hashlib.sha1(_LJ.RUBRIC.encode("utf-8")).hexdigest()[:12]
    except Exception:
        pass
    return out


def _cost_since(since: str) -> tuple[int, float]:
    """Total spend for this run, read back from the usage log.

    The in-process counter reports 0 for a run that was fully served from cache, which
    would understate what the run actually cost. Reading the log keeps the number honest.
    """
    p = ROOT / "data" / "llm_usage.jsonl"
    n, c = 0, 0.0
    if not p.exists():
        return 0, 0.0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("tag") == "kernel_judge" and str(d.get("ts", "")) >= since:
            n += 1
            c += float(d.get("cny") or 0.0)
    return n, round(c, 4)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=datetime.now().strftime("%Y%m%d"),
                    help="round name; decides out/round-<tag>/ and the log name")
    ap.add_argument("--only", default="", help="comma-separated subset of targets to run")
    ap.add_argument("--targets-file", default="", help="target table yml (default core/config/targets.yml)")
    ap.add_argument("--out", default=str(ROOT / "out"), help="output root")
    ap.add_argument("--no-llm", action="store_true",
                    help="skip the LLM triage stage (default: on). "
                         "Candidates only, no verdicts; expect more noise.")
    ap.add_argument("--judge-votes", type=int, default=1,
                    help="ask the triage model N times per finding and take the majority "
                         "(default 1). Repeat runs of the same finding disagree often; N>1 costs N times more.")
    ap.add_argument("--no-gate", action="store_true",
                    help="skip the target health gate (archived / unmaintained repos are skipped by default)")
    ap.add_argument("--gate-mode", default="", choices=["", "alive", "detect"],
                    help="alive = skip archived / unmaintained repos (default); "
                         "detect = keep them, for measuring detection power")
    ap.add_argument("--no-consistency", action="store_true",
                    help="skip the verdict consistency check (report-only by default)")
    ap.add_argument("--no-duality", action="store_true",
                    help="skip the duality candidate generator (strong/weak form side by side "
                         "in one function); runs from the source tree, alongside the CodeQL frontend")
    ap.add_argument("--no-dataflow", action="store_true",
                    help="skip inter-procedural argument-source analysis; the triage stage "
                         "then loses its data-flow evidence")
    ap.add_argument("--consistency-downgrade", action="store_true",
                    help="downgrade findings whose verdict flips within a shape group to "
                         "needs_human (conservative; off by default because it changes verdicts)")
    ap.add_argument("--no-upstream", action="store_true",
                    help="skip the end-of-round upstream check (default: on). Checks only "
                         "vuln candidates, writes upstream.json as evidence, never changes a verdict")
    args = ap.parse_args()

    # The frontend reads this at import time, so it has to be set before anything else.
    os.environ["AF_NO_DATAFLOW"] = "1" if args.no_dataflow else "0"

    # Regenerate the CodeQL queries every run: they are generated from core/config/sinks.yml
    # plus the current AF_SINKS_* switches, so a stale QL silently ignores config changes.
    try:
        import subprocess as _sp
        _r = _sp.run([sys.executable, str(ROOT / "core" / "gen_ql.py")],
                     capture_output=True, text=True, encoding="utf-8", errors="replace")
        _gen_ok = _r.returncode == 0
        _gen_msg = (_r.stdout or "").strip().splitlines()[-1] if (_r.stdout or "").strip() else ""
    except Exception as _e:      # noqa: BLE001
        _gen_ok, _gen_msg = False, f"{type(_e).__name__}: {_e}"

    global TARGETS
    if args.targets_file:
        TARGETS = load_targets(args.targets_file)
    want = [s.strip() for s in args.only.split(",") if s.strip()] or list(TARGETS)
    rd = R.new_round_dir(Path(args.out), args.tag)
    t0 = time.time()
    started = datetime.fromtimestamp(t0).strftime("%Y-%m-%d %H:%M:%S")

    all_findings = []
    per_project = {}
    llm_cost = 0.0
    llm_calls = 0
    llm_cache_hits = 0
    with R.ScanLog(rd / "scan.log") as lg:
        lg.log(f"round dir = {rd}")
        lg.log(f"kernel stamp = {_cfg_stamp()}")
        lg.log(f"[gen_ql] ok={_gen_ok} | {_gen_msg}")
        # Record every switch that changes the candidate set, so a run can be reproduced
        # later. AF_PATH_FILTER defaults to the string "rel", not 0/1.
        _sw_defaults = {"AF_SINKS_EXTRA": "1", "AF_PATH_FILTER": "rel"}
        lg.log("[switches] " + " ".join(
            f"{k}={os.environ.get(k, _sw_defaults.get(k, '0'))}"
            for k in ("AF_SINKS_EXTRA", "AF_SINKS_PATH", "AF_SINKS_HTTP", "AF_SINKS_FS",
                      "AF_SINKS_DYNIMP", "AF_DUALITY_SDK", "AF_PATH_FILTER")))
        for name in want:
            t = TARGETS.get(name)
            if t is None:
                lg.log(f"[SKIP] unknown target {name}")
                continue
            # Health gate: archived / unmaintained / fork / disabled repos are skipped, with a reason.
            if not args.no_gate and t.get("repo"):
                g = G.check(t["repo"], mode=(args.gate_mode or None))
                lg.log(f"[gate] {name} ({t['repo']}) -> {G.summary(g)}")
                if g["verdict"] == "SKIP":
                    per_project[name] = {"status": "gated-out", "n": 0, "reasons": g["reasons"]}
                    continue
                if g["verdict"] == "UNKNOWN":
                    lg.log("       health unknown -> continuing anyway (not silently skipped)")
            db = t.get("db")
            if not db or not (db / "codeql-database.yml").exists():
                lg.log(f"[SKIP] {name}: database missing or incomplete -> {db}")
                per_project[name] = {"status": "no-db", "n": 0}
                continue
            lg.log(f"--- {name} : {db}")
            try:
                fnd = SF.run_db_to_findings(str(db), name, on_log=lg.log)
            except Exception as e:            # fail loudly, never silently
                lg.log(f"[FAIL] {name} error: {type(e).__name__}: {e}")
                per_project[name] = {"status": "error", "n": 0}
                continue
            n_sf = len(fnd)
            # Candidate generator #2: strong/weak form side by side in one function.
            # Runs straight from the source tree, in parallel with the CodeQL frontend.
            n_du = 0
            if not args.no_duality and t.get("src"):
                try:
                    from core import duality as DX
                    dx = DX.scan_dir(t["src"], name, on_log=lg.log)
                    n_du = len(dx)
                    fnd = list(fnd) + list(dx)
                except Exception as e:
                    lg.log(f"[duality][FAIL] {name}: {type(e).__name__}: {e}")
            elif not args.no_duality:
                lg.log(f"[duality] {name}: no src in the target table -> skipped (frontend only)")
            if not fnd:
                lg.log(f"[WARN] {name} returned 0 hits -- either there is nothing here, "
                       "or the checks do not cover it; verify separately")
            before = len(fnd)
            fnd = F.dedup(fnd)
            lg.log(f"[dedup] {name}: {before} -> {len(fnd)} (merged by fingerprint)")
            per_project[name] = {"status": "ok", "n": len(fnd), "n_raw": before,
                                 "n_static_frontend": n_sf, "n_duality": n_du}
            all_findings.extend(fnd)

        # ---- LLM triage ----
        if not args.no_llm and all_findings:
            from core import llm_judge as LJ
            _v = max(1, args.judge_votes)
            lg.log(f"[judge] triaging {len(all_findings)} candidates (AI-assisted, not human-verified)"
                   + (f" | {_v} votes each, majority" if _v > 1 else " | single pass"))
            if _v > 1:
                lg.log(f"[judge] N>1: cost x{_v}; each vote uses a fresh tag to bypass the cache "
                       "(otherwise all N votes return the same cached answer)")
            LJ.judge(all_findings, on_log=lg.log, votes=_v)
            llm_calls = LJ.LC.USAGE.calls
            llm_cost = round(LJ.LC.USAGE.cny, 4)
            llm_cache_hits = LJ.LC.USAGE.hit_cache
            lg.log("[judge] " + LJ.cost_report().replace("\n", " | "))
            from collections import Counter
            lg.log("[judge] distribution " + str(dict(Counter(f.ai_verdict for f in all_findings))))

        # ---- Verdict consistency check (report-only by default) ----
        if not args.no_consistency and all_findings:
            from core import consistency as CS
            cres = CS.check(all_findings)
            st = cres["stats"]
            lg.log(f"[consistency] shape groups {st['n_shape_groups']} | "
                   f"same input, different verdict {st['n_strict_inconsistent']} (should be 0) | "
                   f"subjective drift {st['n_drift_groups']} groups")
            if args.consistency_downgrade and cres["drift"]:
                ch = CS.apply_downgrade(all_findings, cres)
                lg.log(f"[consistency] downgraded {len(ch)} findings to needs_human (conservative)")
                cres = CS.check(all_findings)
                lg.log(f"[consistency] after downgrade: {cres['stats']['n_drift_groups']} drift groups")
            CS.write_report(rd / "consistency.md", cres)
            lg.log("[consistency] -> consistency.md")

        R.write_findings(rd / "findings.tsv", all_findings)
        R.write_verdicts(rd / "verdicts.json", all_findings)
        R.write_findings_json(rd / "findings.json", all_findings)
        lg.log(f"[done] {len(all_findings)} candidates -> {rd / 'findings.tsv'}")

    n_log, c_log = _cost_since(started)
    if n_log or c_log:
        llm_calls, llm_cost = n_log, c_log

    meta = {
        "tag": args.tag,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "elapsed_sec": round(time.time() - t0, 1),
        "kernel_stamp": _cfg_stamp(),
        "per_project": per_project,
        "n_findings": len(all_findings),
        "duality_enabled": not args.no_duality,
        "llm_calls": llm_calls,
        "llm_cache_hits": llm_cache_hits,
        "llm_cost_cny": llm_cost,
        "llm_review": "AI-assisted, not human-verified",
        # Record the aggregation policy: a bare "N vulnerabilities" number is meaningless
        # without saying how many times each finding was judged and how the votes were combined.
        "judge_aggregation": {
            "votes_per_finding": max(1, args.judge_votes),
            "policy": "majority" if max(1, args.judge_votes) > 1 else "single",
            "tie_rule": "needs_human" if max(1, args.judge_votes) > 1 else None,
        },
        "human_minutes": None,
        "judge_oparg": os.environ.get("AF_JUDGE_OPARG", "0") == "1",
        # Effective switch values at run time (env var unset -> module default).
        # Runs that changed any of these are not directly comparable to each other.
        "judge_switches_effective": {
            "AF_JUDGE_ARGCTX": os.environ.get("AF_JUDGE_ARGCTX", "1") != "0",
            "AF_JUDGE_OPARG": os.environ.get("AF_JUDGE_OPARG", "0") == "1",
            "AF_JUDGE_REPOCFG": os.environ.get("AF_JUDGE_REPOCFG", "0") == "1",
            "AF_JUDGE_CFGSRC": os.environ.get("AF_JUDGE_CFGSRC", "0") == "1",
        },
        "sink_switches_effective": {
            "AF_SINKS_PATH": os.environ.get("AF_SINKS_PATH", "0") == "1",
            "AF_SINKS_HTTP": os.environ.get("AF_SINKS_HTTP", "0") == "1",
            "AF_SINKS_FS": os.environ.get("AF_SINKS_FS", "0") == "1",
            "AF_DUALITY_SDK": os.environ.get("AF_DUALITY_SDK", "0") == "1",
            "AF_SINKS_EXTRA": os.environ.get("AF_SINKS_EXTRA", "1") == "1",
            "AF_SINKS_DYNIMP": os.environ.get("AF_SINKS_DYNIMP", "0") == "1",
            "AF_PATH_FILTER": os.environ.get("AF_PATH_FILTER", "rel"),
        },
    }

    # The ScanLog context has exited by now, so lg.log() would write to a closed handle.
    def _safe_log(msg: str) -> None:
        try:
            if getattr(lg, "_fh", None) is not None and lg._fh.closed:
                print(msg)
                return
            lg.log(msg)
        except (ValueError, AttributeError):
            print(msg)

    # ---- End-of-round upstream check (default on) ----
    # Only checks candidates headed for `vuln`; writes upstream.json as evidence and never
    # changes a verdict. Failure here must not invalidate a whole CodeQL run.
    up_sum = None
    if not args.no_upstream and all_findings:
        try:
            from core import upstream as UP
            res = UP.run_round_dir(rd, on_log=_safe_log)
            up_sum = {
                "checked": len(res),
                "still_present": sum(1 for v in res.values() if v.get("still_present") is True),
                "gone": sum(1 for v in res.values() if v.get("still_present") is False),
                "archived": sum(1 for v in res.values() if v.get("archived")),
                "not_checked": sum(1 for v in res.values() if v.get("error")),
            }
        except Exception as e:
            up_sum = {"error": f"{type(e).__name__}: {e}"}
            _safe_log(f"[upstream] check failed (round continues): {up_sum['error']}")
        if up_sum is not None:
            meta["upstream"] = up_sum

    R.write_meta(rd / "meta.json", meta)
    print(f"\n== round done: {len(all_findings)} findings, {meta['elapsed_sec']}s -> {rd}")
    return 0 if all_findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
