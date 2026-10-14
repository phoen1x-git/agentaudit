#!/usr/bin/env python
"""Scan a target with one command.

    python app/scan.py --demo                    # scan the bundled sample project
    python app/scan.py --path ./myproject        # scan a project already on disk
    python app/scan.py --repo owner/name         # fetch a GitHub repo and scan it

This is the simple entry point: it resolves a source tree, runs the checks, optionally
triages the candidates with an LLM, and writes a report. It is the same engine as
`app/run_round.py`, minus the target-pool machinery.

Two modes:

* **full** - a CodeQL database is built and the CodeQL queries run, plus the AST checks.
  Needs the CodeQL CLI (see README). Produces `results.sarif` alongside the report.
* **offline** - only the built-in AST checks run. No CodeQL, no API key, no downloads.
  It finds strictly less; the run records which mode produced it.

LLM triage is **off by default**. Pass `--llm` to turn it on; the run prints the number of
candidates and the estimated cost first, and `AF_LLM_MAX_CNY` stops it at the cap.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from core import cfg as CFG                      # noqa: E402
from core import duality as DX                   # noqa: E402
from core import finding as F                    # noqa: E402
from core import workspace                       # noqa: E402
from core import static_frontend as SF           # noqa: E402
import ast_scan                                  # noqa: E402


def _log(msg: str = "") -> None:
    print(msg, flush=True)


def _safe_name(repo: str) -> str:
    return repo.replace("/", "__").lower()


def codeql_available() -> bool:
    if not os.path.exists(_codeql_exe()):
        return False
    ql = SF.ql_dir()
    return all(os.path.exists(os.path.join(ql, q)) for q in SF.QUERIES)


def _codeql_exe() -> str:
    exe = SF.codeql_exe()
    if os.path.exists(exe):
        return exe
    # On a platform where the CLI unpacks without an extension, accept that too.
    alt = str(exe)[:-4] if str(exe).endswith(".exe") else str(exe) + ".exe"
    return alt if os.path.exists(alt) else exe


def build_db(src: Path, db: Path) -> bool:
    if (db / "codeql-database.yml").exists():
        _log(f"[db] reusing {db}")
        return True
    exe = _codeql_exe()
    db.parent.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "database", "create", str(db), "--language=python",
           f"--source-root={src}", "--overwrite"]
    _log("[db] " + " ".join(cmd[1:]))
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0 or not (db / "codeql-database.yml").exists():
        _log(f"[db] FAILED (exit {p.returncode})")
        _log(((p.stdout or "") + (p.stderr or ""))[-1500:])
        return False
    _log(f"[db] built in {time.time() - t0:.0f}s -> {db}")
    return True


def scan_codeql(src: Path, db: Path, project: str, sarif_out: Path) -> list[F.Finding]:
    if not SF.run_analyze(str(db), str(sarif_out), _log):
        raise SystemExit("CodeQL analysis failed -- that is not the same as 'no findings'")
    raw = SF.parse_sarif(str(sarif_out), project)
    _log(f"[codeql] {len(raw)} raw results")
    argsrc = SF.run_and_parse_argsrc(str(db), project, _log)
    fnd = SF.finalize(raw, str(db), CFG.load_filters(), _log, argsrc=argsrc)
    fnd = list(fnd) + DX.scan_dir(src, project, on_log=_log)
    return F.dedup(fnd)


def fetch_repo(repo: str, dst_root: Path) -> Path:
    """Clone the repo shallowly; fall back to the tarball downloader."""
    dst = dst_root / _safe_name(repo)
    if (dst / ".af_fetch_ok").exists() or (dst / ".git").exists():
        _log(f"[fetch] reusing {dst}")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("git"):
        _log(f"[fetch] git clone --depth 1 https://github.com/{repo}")
        p = subprocess.run(["git", "clone", "--depth", "1",
                            f"https://github.com/{repo}", str(dst)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if p.returncode == 0:
            return dst
        _log("[fetch] git clone failed, falling back to the tarball downloader")
        shutil.rmtree(dst, ignore_errors=True)
    sys.path.insert(0, str(ROOT / "app"))
    from prepare_targets import fetch_source           # noqa: E402
    import urllib.request
    ref = "HEAD"
    try:
        with urllib.request.urlopen(
                f"https://api.github.com/repos/{repo}", timeout=20) as r:
            import json as _json
            ref = _json.load(r).get("default_branch") or "main"
    except Exception:
        pass
    ok, _n = fetch_source(repo, ref, dst, _log)
    if not ok:
        raise SystemExit(f"could not fetch {repo}")
    return dst


def count_source_files(src: Path, ignore: list[str]) -> int:
    """How many .py files the scan would look at. Counted, not read.

    The skip list is matched against the path *relative to the source root*, so a project that
    itself lives under a directory called `build` or `site-packages` is not skipped wholesale.
    """
    import fnmatch
    pats = [p.replace("\\", "/") for p in ignore]
    n = 0
    for p in src.rglob("*.py"):
        rel = p.relative_to(src).as_posix()
        if any(part in ast_scan.SKIP_DIRS for part in Path(rel).parts[:-1]):
            continue
        if any(fnmatch.fnmatch(rel, pat) for pat in pats):
            continue
        n += 1
    return n


def _matches_ignore(rel: str, ignore: list[str]) -> bool:
    import fnmatch
    rel = rel.replace("\\", "/")
    return any(fnmatch.fnmatch(rel, p.replace("\\", "/")) for p in ignore)


def changed_files(src: Path, ref: str) -> set[str]:
    """Files changed since `ref`, as posix paths relative to `src` (tracked + untracked)."""
    if not shutil.which("git"):
        raise SystemExit("--diff needs git on PATH")
    top = subprocess.run(["git", "-C", str(src), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    if top.returncode != 0:
        raise SystemExit(f"--diff needs a git checkout: {src}\n{(top.stderr or '').strip()}")
    # git reports paths relative to the repository root, not to src.
    prefix = os.path.relpath(src.resolve(), Path(top.stdout.strip()).resolve())
    prefix = "" if prefix == "." else prefix.replace("\\", "/") + "/"

    out: set[str] = set()
    for cmd in (["git", "-C", str(src), "diff", "--name-only", ref],
                ["git", "-C", str(src), "ls-files", "--others", "--exclude-standard"]):
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if p.returncode != 0:
            raise SystemExit(f"--diff failed: {' '.join(cmd[3:])}\n{(p.stderr or '').strip()}")
        for x in (p.stdout or "").splitlines():
            x = x.strip().replace("\\", "/")
            if not x:
                continue
            if prefix and not x.startswith(prefix):
                continue
            out.add(x[len(prefix):] if prefix else x)
    return out


def _write_stats_log(*, mode: str, findings, src: Path, ignore: list[str],
                     elapsed: float, db: Path | None) -> None:
    """Append one statistics-only record to the local scan log.

    See tools/scan_log.py: counts and settings, never source, paths or project names.
    """
    try:
        import scan_log
        if not scan_log.logging_enabled():
            _log("[log] disabled by AGENTAUDIT_NO_LOG")
            return
        codeql = scan_log.codeql_version_of(_codeql_exe()) if db is not None else ""
        stamp = ast_scan._stamp()
        rules_hash = "".join(sorted(stamp.values()))[:16]
        rec = scan_log.build_record(
            mode=mode, n_files=count_source_files(src, ignore), findings=findings,
            elapsed_sec=elapsed, codeql_version=codeql,
            n_ignore_patterns=len(ignore), rules_hash=rules_hash)
        scan_log.append(rec)
        _log(f"[log] recorded {rec['n_files']} files / {rec['n_candidates']} candidates "
             f"-> {scan_log.log_path()}  (statistics only; `--no-log` to skip)")
    except Exception as e:      # never fail a scan over bookkeeping
        _log(f"[log] not recorded ({type(e).__name__}: {e})")


def main() -> int:
    ap = argparse.ArgumentParser(description="scan a target with one command")
    src_grp = ap.add_mutually_exclusive_group(required=True)
    src_grp.add_argument("--demo", action="store_true", help="scan the bundled sample project")
    src_grp.add_argument("--path", help="a project directory already on disk")
    src_grp.add_argument("--repo", help="a GitHub repository, owner/name")
    ap.add_argument("--project", default="", help="project name used in reports (default: derived)")
    ap.add_argument("--tag", default="", help="round name (default: derived from the target)")
    ap.add_argument("--out", default=str(workspace() / "out"),
                    help="where to write the round (default: ./out)")
    ap.add_argument("--llm", action="store_true",
                    help="triage the candidates with an LLM (spends API credits; off by default)")
    ap.add_argument("--no-codeql", action="store_true",
                    help="force the offline AST-only mode even if CodeQL is available")
    ap.add_argument("--lang", default="en", choices=["en", "zh"], help="report language")
    ap.add_argument("--diff", nargs="?", const="HEAD~1", default="",
                    metavar="REF",
                    help="only report candidates in files changed since REF (default HEAD~1); "
                         "the source tree must be a git checkout")
    ap.add_argument("--fail-on", default="none", choices=["none", "any", "vuln"],
                    help="exit non-zero when a candidate is reported (any) or when one was "
                         "triaged vuln (vuln); default: always exit 0")
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob, relative to the source root "
                         "(repeatable), e.g. --ignore 'vendor/**'")
    ap.add_argument("--serve", action="store_true",
                    help="after the scan, serve the round directory on localhost")
    ap.add_argument("--no-log", action="store_true",
                    help="do not append to the local statistics log (see tools/scan_log.py)")
    a = ap.parse_args()

    if a.demo:
        src = ROOT / "demo"
        project = a.project or "demo-agent"
        tag = a.tag or "demo"
        if not src.is_dir():
            raise SystemExit(f"bundled demo project not found: {src}")
    elif a.path:
        src = Path(a.path).expanduser().resolve()
        project = a.project or src.name
        tag = a.tag or project
    else:
        if a.no_codeql:
            pass
        src = fetch_repo(a.repo, workspace() / "_targets" / "src")
        project = a.project or a.repo.split("/")[-1]
        tag = a.tag or _safe_name(a.repo)

    mode = "offline"
    if not a.no_codeql and codeql_available():
        mode = "full"
    rd = Path(a.out) / f"round-{tag}"
    rd.mkdir(parents=True, exist_ok=True)

    _log("=" * 74)
    _log(f"scan  project={project}  source={src}")
    _log(f"mode  {mode}" + ("" if mode == "full" else "  (AST checks only, no CodeQL)"))
    _log("=" * 74)

    t0 = time.time()
    sarif_out = rd / "results.sarif"
    findings: list[F.Finding] = []
    db = None
    if mode == "full":
        db = workspace() / "_targets" / "db" / f"{project}-db"
        if not build_db(src, db):
            _log("[warn] could not build the CodeQL database -> falling back to the AST-only mode")
            mode = "offline"
        else:
            try:
                findings = scan_codeql(src, db, project, sarif_out)
            except SystemExit as e:
                _log(f"[warn] {e}")
                _log("[warn] falling back to the AST-only mode")
                mode = "offline"
                findings = []
    if mode == "offline":
        if not a.no_codeql and not findings:
            _log("[note] running the AST checks only.")
            _log("       see the README for how to install CodeQL; a full run finds more.")
        findings = ast_scan.scan_dir(src, project, on_log=_log, ignore=a.ignore)
    if a.ignore and mode == "full":
        before = len(findings)
        findings = [f for f in findings if not _matches_ignore(f.sink_uri, a.ignore)]
        _log(f"[ignore] {len(a.ignore)} pattern(s) -> {before} candidates filtered to {len(findings)}")
    elif a.ignore:
        _log(f"[ignore] {len(a.ignore)} pattern(s) applied while collecting sources")

    llm_cost = 0.0
    llm_calls = 0
    if a.llm and findings:
        from core import llm_judge as LJ
        _log(f"[llm] triaging {len(findings)} candidates; "
             f"the hard cap is AF_LLM_MAX_CNY={os.environ.get('AF_LLM_MAX_CNY', '30')} CNY")
        LJ.judge(findings, on_log=_log, votes=1)
        llm_calls = LJ.LC.USAGE.calls
        llm_cost = round(LJ.LC.USAGE.cny, 4)
        _log(f"[llm] {llm_calls} calls, {llm_cost} CNY")

    changed: set[str] = set()
    if a.diff:
        changed = changed_files(src, a.diff)
        before = len(findings)
        findings = [f for f in findings if f.sink_uri.replace("\\", "/") in changed]
        _log(f"[diff] {len(changed)} file(s) changed since {a.diff} -> "
             f"{before} candidates filtered down to {len(findings)}")

    meta_extra = {
        "scanner": "codeql" if mode == "full" else "ast-only",
        "source_root": str(src),
        "project": project,
        "llm_triage": bool(a.llm),
    }
    if a.diff:
        meta_extra["diff_ref"] = a.diff
        meta_extra["diff_files"] = sorted(changed)
    ast_scan.write_round(Path(a.out), tag, findings, meta_extra=meta_extra,
                         keep_sarif=str(sarif_out) if mode == "full" else None)
    _log(f"[out] {len(findings)} candidates -> {rd}")

    select = "vuln" if a.llm else "all"
    for script, args in (("make_report.py", ["--select", select, "--lang", a.lang]),
                         ("make_index.py", ["--lang", a.lang])):
        cmd = [sys.executable, str(ROOT / "app" / script), str(rd), *args]
        subprocess.run(cmd, check=False)

    # Logged last, so the elapsed time means the same thing as the "done in" line below.
    if not a.no_log:
        _write_stats_log(mode=mode, findings=findings, src=src, ignore=a.ignore,
                         elapsed=time.time() - t0, db=(db if mode == "full" else None))

    _log("")
    _log("=" * 74)
    _log(f"done in {time.time() - t0:.1f}s")
    _log(f"  report  {rd / 'report_draft.md'}")
    _log(f"  index   {rd / 'index.html'}")
    _log(f"  table   {rd / 'findings.tsv'}")
    if (rd / "results.sarif").exists():
        _log(f"  sarif   {rd / 'results.sarif'}")
    _log("=" * 74)

    if a.serve and a.fail_on == "none":
        # Hand over to the local viewer. Note it does not return until Ctrl-C, so it is not
        # combined with --fail-on (which is meant for a non-interactive build step).
        _log("[serve] starting the local viewer; Ctrl-C to stop")
        os.execv(sys.executable,
                 [sys.executable, str(ROOT / "app" / "serve.py"), str(rd)])
    elif a.serve:
        _log("[serve] skipped: --serve and --fail-on are for different situations "
             "(one is interactive, the other is a build gate)")

    if a.fail_on == "any" and findings:
        _log(f"[fail-on] {len(findings)} candidate(s) reported -> exit 1")
        return 1
    if a.fail_on == "vuln":
        vulns = [f for f in findings if (f.ai_verdict or "").strip() == "vuln"]
        if vulns:
            _log(f"[fail-on] {len(vulns)} candidate(s) triaged vuln -> exit 1")
            return 1
        if not a.llm:
            _log("[fail-on] note: no triage ran this round, so `vuln` can never be set; "
                 "use --llm, or --fail-on any")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
