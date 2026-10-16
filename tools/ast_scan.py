#!/usr/bin/env python
"""Offline scan: run the built-in AST checks over a source tree.

    python tools/ast_scan.py --path ./demo --project demo-agent

No CodeQL and no API key are needed. This is a **subset** of a full run: it finds
call-site-shaped problems (dangerous calls, untrusted input reaching them, routes with no
authentication, strong/weak form side by side) but it cannot follow values across files or
through a framework, so a full CodeQL-backed scan will find more. The output says which
mode produced it.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ast_criteria as A                        # noqa: E402
from core import duality as DX                  # noqa: E402
from core import finding as F                   # noqa: E402

# Rule bucket -> (stable rule id, human label)
RULES = {
    "code_exec_sink": ("ast/dangerous-call", "dangerous call"),
    "injection_surface": ("ast/injection-surface", "untrusted input reaching a dangerous call"),
    "dangerous_cooccurrence": ("ast/input-to-sink", "untrusted input and dangerous call in one expression"),
    "unauth_endpoint": ("ast/unauth-endpoint", "route with no authentication"),
    "inconsistent_auth": ("ast/inconsistent-auth", "authentication inconsistent within one file"),
    "input_source_unknown": ("ast/arg-source-unknown", "argument source could not be determined"),
}

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "site-packages", "node_modules", "build", "dist"}
_SINK_RE = re.compile(r"([A-Za-z_][A-Za-z_.]*)\s*$")


def _name_of(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _sink_from_snippet(snippet: str) -> str:
    """Name the call a line actually makes, by parsing it. Empty if there is none."""
    if not snippet:
        return ""
    try:
        tree = ast.parse(snippet.strip())
    except SyntaxError:
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            nm = _name_of(node.func)
            if nm:
                return nm
    return ""


def _sink_of(kind: str, snippet: str, fallback: str) -> str:
    """Prefer the call parsed out of the source line; fall back to the rule's message."""
    nm = _sink_from_snippet(snippet)
    if nm:
        return nm
    m = _SINK_RE.search(kind or "")
    if m and m.group(1) not in ("True", "False", "None") and not m.group(1)[0].isdigit():
        return m.group(1)
    return fallback


def collect_sources(src_root: Path, ignore: list[str] | None = None) -> dict[str, str]:
    """Read every .py file under `src_root`.

    `ignore` is a list of glob patterns matched against the path relative to `src_root`
    (e.g. "vendor/**", "*/generated/*.py"), so generated or vendored trees can be excluded.
    """
    import fnmatch
    pats = [p.replace("\\", "/") for p in (ignore or [])]
    files: dict[str, str] = {}
    for p in sorted(src_root.rglob("*.py")):
        rel = p.relative_to(src_root).as_posix()
        # Check the parts *relative to src_root*. Using the absolute parts would skip every
        # file when the project itself happens to live under a directory called `build`,
        # `venv` or `site-packages` -- e.g. an installed copy, or a checkout under ~/build.
        if any(part in SKIP_DIRS for part in Path(rel).parts[:-1]):
            continue
        if any(fnmatch.fnmatch(rel, pat) for pat in pats):
            continue
        try:
            files[rel] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return files


def scan_dir(src_root: str | os.PathLike, project: str | None = None,
             on_log=None, ignore: list[str] | None = None) -> list[F.Finding]:
    """Run the AST checks plus the strong/weak-form check over a source tree."""
    root = Path(src_root)
    project = project or root.name
    log = on_log or (lambda _m: None)
    if not root.is_dir():
        raise SystemExit(f"source directory not found: {root}")

    files = collect_sources(root, ignore=ignore)
    res, failed = A.analyze_files(files)
    if failed:
        log(f"[ast] {len(failed)} file(s) failed to parse: {failed[:5]}")

    out: list[F.Finding] = []
    for bucket, (rule, label) in RULES.items():
        for h in res.get(bucket, {}).get("hits", []):
            rel = h.get("file", "")
            line = int(h.get("line") or 0)
            kind = h.get("kind", "")
            snippet = h.get("text", "") or ""
            sink = _sink_of(kind, snippet, rule.split("/", 1)[-1])
            out.append(F.Finding(
                project=project,
                # The rule goes into the fingerprint so two different checks firing on the
                # same line stay separate; `sink` itself stays readable for the report.
                fingerprint=F.make_fingerprint(project, rel, f"{rule}|{sink}", snippet),
                rule=rule,
                sink_func=sink,
                sink_uri=rel,
                sink_line=line,
                entry=h.get("fn", "") or "",
                depth=0,
                snippet=snippet,
                chain=f"{label} (line {line})",
                src_root=str(root),
            ))

    # Strong/weak form coexistence within one function.
    du = DX.scan_dir(root, project, on_log=log)
    pats = [p.replace("\\", "/") for p in (ignore or [])]
    if pats:
        du = [f for f in du if not any(fnmatch.fnmatch(f.sink_uri.replace("\\", "/"), p) for p in pats)]
    for fd in du:
        fd.rule = "ast/duality"
        fd.chain = fd.chain.replace("弱[", "weak[").replace("] vs 强 ", "] vs strong ")
    out.extend(du)

    out = F.dedup(out)
    log(f"[ast] {len(files)} files -> {len(out)} candidates")
    return out


def _stamp() -> dict:
    """Hash the files that decide what this scan can find, so a run is identifiable."""
    import hashlib
    out = {}
    for rel in ("tools/ast_criteria.py", "tools/is_test_path.py", "core/duality.py",
                "core/config/sinks.yml", "core/config/filters.yml"):
        p = ROOT / rel
        if p.exists():
            out[rel.split("/")[-1]] = hashlib.sha1(p.read_bytes()).hexdigest()[:12]
    return out


def write_round(out_root: Path, tag: str, findings: list[F.Finding],
                meta_extra: dict | None = None, keep_sarif: str | None = None) -> Path:
    """Write a round directory in the same layout app/run_round.py produces."""
    from datetime import datetime
    rd = out_root / f"round-{tag}"
    rd.mkdir(parents=True, exist_ok=True)
    from core import round as R
    R.write_findings(rd / "findings.tsv", findings)
    R.write_verdicts(rd / "verdicts.json", findings)
    R.write_findings_json(rd / "findings.json", findings)
    meta = {
        "tag": tag,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "kernel_stamp": _stamp(),
        "n_findings": len(findings),
        "llm_calls": 0,
        "llm_cache_hits": 0,
        "llm_cost_cny": 0.0,
        "llm_review": "not run",
    }
    if keep_sarif and Path(keep_sarif).exists():
        (rd / "results.sarif").write_text(Path(keep_sarif).read_text(encoding="utf-8"), encoding="utf-8")
        meta["sarif"] = "results.sarif"
    if meta_extra:
        meta.update(meta_extra)
    R.write_meta(rd / "meta.json", meta)
    return rd


def main() -> int:
    ap = argparse.ArgumentParser(description="offline AST scan of a source tree")
    ap.add_argument("--path", required=True, help="source directory to scan")
    ap.add_argument("--project", default="", help="project name used in fingerprints and reports")
    ap.add_argument("--tag", default="astscan")
    ap.add_argument("--out", default=str(ROOT / "out"))
    ap.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob, relative to --path (repeatable)")
    a = ap.parse_args()
    fnd = scan_dir(a.path, a.project or Path(a.path).name, on_log=print, ignore=a.ignore)
    rd = write_round(Path(a.out), a.tag, fnd,
                     meta_extra={"scanner": "ast-only", "source_root": str(Path(a.path).resolve())})
    print(json.dumps({"round_dir": str(rd), "n_findings": len(fnd)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
