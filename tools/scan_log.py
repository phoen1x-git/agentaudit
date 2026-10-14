#!/usr/bin/env python
"""A local log of scan statistics, and an optional way to share the numbers.

One project scanned once says almost nothing. The point of this file is to make it easy to
accumulate statistics over many scans, and to let you share those numbers if you want to.

**What is recorded**: counts and settings only — how many files, how many candidates, how they
split across checks and verdicts, the elapsed time, the tool version, the mode, and hashes of
the rule configuration.

**What is deliberately not recorded**: source code, file paths, project names, snippets,
fingerprints, or anything else that identifies what you scanned.

**Nothing is uploaded, ever.** There is no network code in this file. The only way any of it
leaves your machine is if you take it yourself, which is what `--export` is for: it writes a
small aggregate and refuses to write anything that fails a redaction check.

    python tools/scan_log.py                  # summarise what is logged locally
    python tools/scan_log.py --show           # print the raw records
    python tools/scan_log.py --export         # write and print a shareable aggregate
    python tools/scan_log.py --clear          # delete the local log (asks first)

Set `AGENTAUDIT_NO_LOG=1`, or pass `--no-log` to `app/scan.py`, to stop recording.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import workspace  # noqa: E402

SCHEMA = 1


def log_path() -> Path:
    """The log lives in the working directory, not in the installation.

    Resolved on every call so that `AGENTAUDIT_HOME`, or simply running from a different
    directory, takes effect without restarting anything.
    """
    return workspace() / "data" / "scan_log.jsonl"

# Anything not in this set is not shareable. New fields must be added here deliberately.
SHAREABLE_KEYS = {
    "schema", "ts", "agentaudit", "mode", "python", "os", "codeql",
    "n_files", "n_candidates", "n_ignore_patterns", "elapsed_sec",
    "by_rule", "by_verdict", "n_sink_rules", "rules_hash",
}
# The aggregate written by --export has its own, smaller shape.
SHAREABLE_AGG_KEYS = {
    "schema", "agentaudit", "n_scans", "versions", "modes", "totals", "by_rule", "by_verdict",
}
MAX_STRING = 48


def _verdicts(findings) -> dict:
    c = Counter((getattr(f, "ai_verdict", "") or "").strip() or "untriaged" for f in findings)
    return dict(sorted(c.items()))


def _rules(findings) -> dict:
    c = Counter(getattr(f, "rule", "") or "?" for f in findings)
    return dict(sorted(c.items()))


def build_record(*, mode: str, n_files: int, findings, elapsed_sec: float,
                 codeql_version: str | None = None, n_ignore_patterns: int = 0,
                 rules_hash: str = "", n_sink_rules: int = 0) -> dict:
    """Build one log record. Only counts and settings go in here."""
    from core import __version__
    try:
        n_sink_rules = n_sink_rules or _count_sink_rules()
    except Exception:
        pass
    return {
        "schema": SCHEMA,
        "ts": datetime.now().isoformat(timespec="seconds"),
        "agentaudit": __version__,
        "mode": mode,
        "python": "%d.%d" % sys.version_info[:2],
        "os": platform.system().lower(),
        "codeql": (codeql_version or "")[:32],
        "n_files": int(n_files),
        "n_candidates": len(findings),
        "n_ignore_patterns": int(n_ignore_patterns),
        "elapsed_sec": round(float(elapsed_sec), 1),
        "by_rule": _rules(findings),
        "by_verdict": _verdicts(findings),
        "n_sink_rules": int(n_sink_rules),
        "rules_hash": rules_hash[:16],
    }


def _count_sink_rules() -> int:
    import yaml
    p = ROOT / "core" / "config" / "sinks.yml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return len(data.get("sinks") or [])


def codeql_version_of(exe: str) -> str:
    """Ask the CLI for its version, or return "" -- never fail a scan over this."""
    import subprocess
    try:
        p = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        for line in (p.stdout or "").splitlines():
            if line.strip().lower().startswith("codeql"):
                return line.strip().split(":", 1)[-1].strip() or line.strip()
    except Exception:
        pass
    return ""


def logging_enabled() -> bool:
    import os
    return os.environ.get("AGENTAUDIT_NO_LOG", "0") != "1"


def append(rec: dict) -> None:
    """Append a record, refusing anything that is not statistics-only.

    The check is here rather than only at export time, so a record with anything identifying
    in it can never reach the file in the first place.
    """
    problems = audit_shareable(rec, allowed=SHAREABLE_KEYS)
    if problems:
        raise ValueError("refusing to log a record that is not statistics-only: "
                         + "; ".join(problems))
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")


def read_all(path: Path | None = None) -> list[dict]:
    p = path or log_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# Redaction: refuse to share anything that is not a plain number or a short token
# ---------------------------------------------------------------------------
def audit_shareable(obj, path: str = "", allowed: set[str] | None = None) -> list[str]:
    """Return a list of problems. An empty list means the object is safe to share.

    Keys are only length-checked; the content checks apply to **values**, because a rule id
    legitimately contains a slash (`ast/dangerous-call`) while a path in a value never should.
    """
    problems: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}" if path else k
            if allowed is not None and k not in allowed:
                problems.append(f"unexpected key: {here}")
            if isinstance(k, str) and len(k) > MAX_STRING:
                problems.append(f"{here}: key is {len(k)} chars (max {MAX_STRING})")
            if isinstance(k, str) and ("\\" in k or "://" in k):
                problems.append(f"{here}: key looks like a path or URL: {k!r}")
            problems += audit_shareable(v, here, allowed=None)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            problems += audit_shareable(v, f"{path}[{i}]", allowed=None)
    elif isinstance(obj, str):
        if len(obj) > MAX_STRING:
            problems.append(f"{path}: string is {len(obj)} chars (max {MAX_STRING})")
        if "/" in obj or "\\" in obj:
            problems.append(f"{path}: looks like a path: {obj!r}")
        if "://" in obj:
            problems.append(f"{path}: looks like a URL: {obj!r}")
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, (int, float)):
        pass
    elif obj is None:
        pass
    else:
        problems.append(f"{path}: unexpected type {type(obj).__name__}")
    return problems


def export(records: list[dict]) -> dict:
    """Aggregate the local log into a small, explicitly shareable object."""
    from core import __version__
    by_rule: Counter = Counter()
    by_verdict: Counter = Counter()
    modes: Counter = Counter()
    versions: Counter = Counter()
    for r in records:
        by_rule.update(r.get("by_rule") or {})
        by_verdict.update(r.get("by_verdict") or {})
        modes[r.get("mode", "?")] += 1
        versions[r.get("agentaudit", "?")] += 1
    return {
        "schema": SCHEMA,
        "agentaudit": __version__,
        "n_scans": len(records),
        "versions": dict(sorted(versions.items())),
        "modes": dict(sorted(modes.items())),
        "totals": {
            "files": sum(int(r.get("n_files") or 0) for r in records),
            "candidates": sum(int(r.get("n_candidates") or 0) for r in records),
            "elapsed_sec": round(sum(float(r.get("elapsed_sec") or 0) for r in records), 1),
        },
        "by_rule": dict(sorted(by_rule.items())),
        "by_verdict": dict(sorted(by_verdict.items())),
    }


def summarise(records: list[dict], stream=sys.stdout) -> None:
    if not records:
        print("no scans logged yet", file=stream)
        print(f"  (the log would be {log_path()})", file=stream)
        return
    agg = export(records)
    print(f"scans logged    {agg['n_scans']}   (from {log_path()})", file=stream)
    print(f"files scanned   {agg['totals']['files']}", file=stream)
    print(f"candidates      {agg['totals']['candidates']}", file=stream)
    print(f"modes           {agg['modes']}", file=stream)
    if agg["by_verdict"]:
        print(f"verdicts        {agg['by_verdict']}", file=stream)
    print("by check:", file=stream)
    for k, v in sorted(agg["by_rule"].items(), key=lambda kv: -kv[1]):
        print(f"  {v:>6}  {k}", file=stream)
    print("\nNothing here identifies what was scanned. `--export` writes this as JSON.",
          file=stream)


def main() -> int:
    ap = argparse.ArgumentParser(description="local scan statistics")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--show", action="store_true", help="print the raw records")
    g.add_argument("--export", action="store_true",
                   help="write an aggregate that is safe to share, and print it")
    g.add_argument("--clear", action="store_true", help="delete the local log")
    ap.add_argument("--out", default="", help="where to write the export (default: stdout only)")
    a = ap.parse_args()

    if a.clear:
        path = log_path()
        if not path.exists():
            print("nothing to clear")
            return 0
        n = len(read_all())
        path.unlink()
        print(f"deleted {path} ({n} record(s))")
        return 0

    records = read_all()

    if a.show:
        if not records:
            print("no scans logged yet")
            return 0
        for r in records:
            print(json.dumps(r, ensure_ascii=False, sort_keys=True))
        return 0

    if a.export:
        agg = export(records)
        problems = audit_shareable(agg, allowed=SHAREABLE_AGG_KEYS)
        if problems:
            print("refusing to export: the aggregate failed the redaction check", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            print("this is a bug -- please report it", file=sys.stderr)
            return 1
        text = json.dumps(agg, ensure_ascii=False, indent=2, sort_keys=True)
        if a.out:
            out = Path(a.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + "\n", encoding="utf-8")
            print(f"wrote {out}")
            print("Nothing was uploaded. Read it before you send it.", file=sys.stderr)
        else:
            print(text)
        return 0

    summarise(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
