#!/usr/bin/env python
"""Show *why* a candidate was reported.

    python app/explain.py out/round-my-round                  # every candidate
    python app/explain.py out/round-my-round --index 3        # just the third one
    python app/explain.py out/round-my-round --fp <fingerprint>
    python app/explain.py out/round-my-round --src ./myproject

For each candidate it prints the source line that was flagged, the call chain that reaches
it, the guards that sit on that path, and where the dangerous argument comes from. All of
that is recorded by the scan; this command only renders it.

Nothing here is a judgement. It shows the evidence the scan collected, which is exactly what
you need in order to decide whether the candidate is worth anything.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# What each check is looking for, in one line.
RULE_DOC = {
    "py-qs/caller": "a dangerous call, traced back to the entry point that can reach it",
    "py-qs/bb-l7": "a string constraint applied somewhere between an entry point and a dangerous call",
    "py-qs/str-constraint": "a dangerous call whose argument is constrained (or not) by a string operation",
    "duality": "one function that does the same job safely on one line and unsafely on another",
}

AST_RULE_DOC = {
    "ast/dangerous-call": "a call to something that executes code, commands or queries",
    "ast/injection-surface": "untrusted input flowing into such a call",
    "ast/input-to-sink": "untrusted input and a dangerous call written in the same expression",
    "ast/unauth-endpoint": "an HTTP route with no authentication anywhere near it",
    "ast/inconsistent-auth": "a file whose routes disagree about requiring authentication",
    "ast/arg-source-unknown": "a dangerous call whose argument origin cannot be determined here",
    "ast/duality": "one function that does the same job safely on one line and unsafely on another",
}


def _read_line(src_root: str, rel: str, line: int) -> str:
    if not src_root or not rel or not line:
        return ""
    p = Path(src_root) / rel
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for i, s in enumerate(fh, 1):
                if i == line:
                    return s.rstrip("\n")
    except OSError:
        pass
    return ""


def _guard_line(src_root: str, spec: str) -> str:
    """A guard is recorded as `abs_path#line:col`."""
    path, _, pos = spec.rpartition("#")
    line = pos.split(":", 1)[0]
    if not line.isdigit():
        return spec
    text = _read_line("", path, int(line))
    name = os.path.basename(path)
    return f"{name}:{line}  {text.strip()[:110]}" if text else f"{name}:{line}"


def _arg_sources(entry: dict) -> list[str]:
    out = []
    for a in entry.get("arg_sources") or []:
        i = a.get("i", "?")
        kind = a.get("kind", "?")
        if kind == "local":
            out.append(f"arg{i}: a value computed locally in this file")
            continue
        src_text = (a.get("src_text") or "").replace("ControlFlowNode for ", "").strip()
        where = f"{a.get('src_file', '?')}:{a.get('src_line', '?')}"
        out.append(f"arg{i}: {kind}  ({src_text} @ {where})" if src_text else f"arg{i}: {kind} @ {where}")
    return out


def _pretty_hop(hop: str) -> str:
    """Turn a serialised chain hop into something readable.

    The frontend encodes a hop as `func@file$$start:col$$end:col`; the offsets are only
    useful to a machine, so they are dropped here.
    """
    hop = hop.strip().split("](", 1)[0].rstrip("]")
    loc = ""
    if "@" in hop:
        hop, loc = hop.rsplit("@", 1)
    if "$$" in loc:
        path, _, nums = loc.partition("$$")
        line = nums.split(":", 1)[0]
        loc = f"{path}:{line}" if line.isdigit() else path
    return f"{hop}  ({loc})" if loc else hop


def _read_span(src_root: str, rel: str, line: int, before: int = 2, after: int = 2):
    """Return [(lineno, text)] around a line, so the reader sees the surrounding code."""
    if not src_root or not rel or not line:
        return []
    p = Path(src_root) / rel
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    line = int(line)
    lo = max(1, line - before)
    hi = min(len(lines), line + after)
    return [(i, lines[i - 1]) for i in range(lo, hi + 1)]


def explain_one(n: int, total: int, fp: str, row: dict, src_root: str) -> str:
    rule = row.get("rule", "")
    rel = row.get("file", "")
    try:
        line = int(row.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    L = ["-" * 78]
    L.append(f"[{n}/{total}]  {rule}  {row.get('project', '')}  {rel}:{line}")
    L.append(f"fingerprint  {fp}")

    doc = RULE_DOC.get(rule) or AST_RULE_DOC.get(rule)
    if doc:
        L.append(f"this check   {doc}")

    snippet = row.get("snippet", "") or _read_line(src_root, rel, line)
    span = _read_span(src_root, rel, line)
    if span:
        L += ["", "surrounding source"]
        for ln, text in span:
            mark = ">" if ln == line else " "
            L.append(f"  {mark} {ln:>4}: {text.rstrip()[:110]}")
    elif snippet:
        L += ["", "source line", f"  {line}: {snippet}"]
    elif rel:
        L.append(f"\n(source not available; pass --src pointing at the project root"
                 + (f", tried {src_root!r}" if src_root else "") + ")")

    chain = row.get("chain", "")
    depth = row.get("depth", 0)
    entry = row.get("entry", "")
    if "->" in chain or (entry and depth):
        L += ["", f"call chain   (depth {depth}" + (f", entry {entry}" if entry else "") + ")"]
        for hop in (chain.split("->") if chain else [entry]):
            if hop.strip():
                L.append(f"  {_pretty_hop(hop)}")

    guards = row.get("guards_list") or []
    if guards:
        L += ["", f"guards on the path ({len(guards)})"]
        for g in guards:
            L.append(f"  {_guard_line(src_root, g)}")
    else:
        L += ["", "guards on the path (0)  -- nothing between the entry and this call was seen"]

    args = _arg_sources(row)
    if args:
        L += ["", "where the argument comes from"]
        for a in args:
            L.append(f"  {a}")
    else:
        L += ["", "where the argument comes from  -- not determined by this scan"]

    verdict = (row.get("ai_verdict") or "").strip()
    if verdict:
        L += ["", f"triage       {verdict}  (confidence {row.get('conf')})"]
        if row.get("ai_reason"):
            L.append(f"  {row['ai_reason']}")
    else:
        L += ["", "triage       not run for this round"]

    L.append("-" * 78)
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="show why a candidate was reported")
    ap.add_argument("round_dir", help="a round directory, e.g. out/round-my-round")
    ap.add_argument("--fp", default="", help="explain only this fingerprint")
    ap.add_argument("--index", type=int, default=0, help="explain only the N-th candidate (1-based)")
    ap.add_argument("--src", default="", help="source root (default: recorded in the round)")
    a = ap.parse_args()

    rd = Path(a.round_dir)
    fj = rd / "findings.json"
    ts = rd / "findings.tsv"
    rows = {}
    if fj.exists():
        rows = json.loads(fj.read_text(encoding="utf-8")) or {}
    if not rows and ts.exists():
        # A round may only have the table (it is the primary artefact); fall back to it.
        import csv
        with open(ts, encoding="utf-8-sig", newline="") as fh:
            rows = {(r.get("fingerprint") or f"{r.get('file')}:{r.get('line')}"): r
                    for r in csv.DictReader(fh, delimiter="\t")}
    if not rows:
        print(f"no candidates found in {rd}; run a scan first")
        return 1

    meta = {}
    if (rd / "meta.json").exists():
        meta = json.loads((rd / "meta.json").read_text(encoding="utf-8"))
    src_root = a.src or meta.get("source_root", "")
    if not src_root:
        # run_round rounds carry the source root per finding instead
        src_root = next((r.get("src_root") for r in rows.values() if r.get("src_root")), "")

    order = sorted(rows.items(), key=lambda kv: (kv[1].get("file", ""), kv[1].get("line", 0)))
    if a.fp:
        order = [(k, v) for k, v in order if k == a.fp]
        if not order:
            print(f"fingerprint not found: {a.fp}")
            return 1
    elif a.index:
        if not 1 <= a.index <= len(order):
            print(f"--index must be between 1 and {len(order)}")
            return 1
        order = [order[a.index - 1]]

    total = len(rows)
    for i, (fp, row) in enumerate(order, 1):
        idx = a.index or ([k for k, _ in sorted(rows.items(), key=lambda kv: (kv[1].get("file", ""), kv[1].get("line", 0)))].index(fp) + 1)
        print(explain_one(idx, total, fp, row, src_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
