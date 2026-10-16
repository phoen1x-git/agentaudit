#!/usr/bin/env python
"""Export a round's findings as SARIF 2.1.0, so they can go into GitHub Code Scanning.

    python tools/to_sarif.py out/round-my-round
    python tools/to_sarif.py out/round-my-round --out agentaudit.sarif --all

The scanner has always *read* SARIF (that is how the CodeQL frontend gets its results); this
is the other direction, so the findings can be seen in a code-scanning UI or an editor
instead of only in a markdown table.

Two deliberate choices:

* **Relative URIs only.** No absolute path and no `originalUriBaseIds` are emitted, so a
  SARIF uploaded from your machine does not carry your filesystem layout.
* **`level` is `warning` for everything.** A candidate is not a confirmed vulnerability, and
  SARIF levels are read by tools that will not see the surrounding caveats. The triage
  verdict goes in `properties` and in the message instead, and rows already triaged
  `not_vuln` are left out unless `--all` is given.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# One line per check, shown by a code-scanning UI next to the result.
RULE_HELP = {
    "py-qs/caller": "a dangerous call, traced back to the entry point that can reach it",
    "py-qs/bb-l7": "a string constraint between an entry point and a dangerous call",
    "py-qs/str-constraint": "a dangerous call whose argument is or is not constrained",
    "duality": "one function doing the same job safely on one line and unsafely on another",
    "ast/dangerous-call": "a call to something that executes code, commands or queries",
    "ast/injection-surface": "untrusted input flowing into such a call",
    "ast/input-to-sink": "untrusted input and a dangerous call in one expression",
    "ast/unauth-endpoint": "an HTTP route with no authentication near it",
    "ast/inconsistent-auth": "routes in one file disagreeing about authentication",
    "ast/arg-source-unknown": "a dangerous call whose argument origin is undetermined",
    "ast/duality": "one function doing the same job safely on one line and unsafely on another",
}


def _rows(rd: Path, include_all: bool) -> list[dict]:
    fj = rd / "findings.json"
    rows: list[dict] = []
    if fj.exists():
        rows = list((json.loads(fj.read_text(encoding="utf-8")) or {}).values())
    if not rows and (rd / "findings.tsv").exists():
        import csv
        with open(rd / "findings.tsv", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
    if not rows:
        raise SystemExit(f"no candidates found in {rd}; run a scan first")
    if not include_all:
        rows = [r for r in rows if (r.get("ai_verdict") or "").strip() != "not_vuln"]
    return rows


def _uri(row: dict) -> str:
    """A relative, posix-style path. Never absolute -- see the module docstring."""
    p = (row.get("file") or "").replace("\\", "/").lstrip("/")
    # A Windows drive letter would still be absolute; drop the prefix rather than leak it.
    if len(p) > 2 and p[1] == ":":
        p = p[2:].lstrip("/")
    return p


def build(rd: Path, rows: list[dict], project: str = "") -> dict:
    from core import __version__

    seen: list[str] = []
    for r in rows:
        rid = r.get("rule") or "unknown"
        if rid not in seen:
            seen.append(rid)

    rules = []
    for rid in seen:
        rules.append({
            "id": rid,
            "name": rid.replace("/", "_"),
            "shortDescription": {"text": RULE_HELP.get(rid, rid)},
            "defaultConfiguration": {"level": "warning"},
            "help": {
                "text": RULE_HELP.get(rid, rid)
                + " Every result is a candidate for a human to review, not a confirmed finding.",
            },
        })
    index = {rid: i for i, rid in enumerate(seen)}

    results = []
    for r in rows:
        rid = r.get("rule") or "unknown"
        line = int(r.get("line") or 0)
        verdict = (r.get("ai_verdict") or "").strip()
        conf = r.get("conf")
        where = f"{_uri(r)}:{line}"
        text = f"{RULE_HELP.get(rid, rid)}. Call site: `{where}`."
        if r.get("sink"):
            text += f" Sink: `{r['sink']}`."
        text += (" Triaged: %s (confidence %s)." % (verdict, conf) if verdict
                 else " Not triaged: this round ran no LLM step.")
        text += " Candidate for review, not a confirmed vulnerability."
        if r.get("ai_reason"):
            text += " " + str(r["ai_reason"])

        region: dict = {"startLine": line} if line > 0 else {}
        result = {
            "ruleId": rid,
            "ruleIndex": index[rid],
            "level": "warning",
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(r)},
                    **({"region": region} if region else {}),
                },
            }],
            "partialFingerprints": {"agentauditFingerprint": r.get("fingerprint", "")},
            "properties": {
                "agentaudit/verdict": verdict or "untriaged",
                "agentaudit/sink": r.get("sink", ""),
                "agentaudit/project": project or r.get("project", ""),
            },
        }
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentaudit",
                    "version": __version__,
                    "informationUri": "https://github.com/phoen1x-git/agentaudit",
                    "rules": rules,
                },
            },
            "columnKind": "utf16CodeUnits",
            "results": results,
            "properties": {
                "agentaudit/note": ("Candidates for human review. Nothing was executed and no "
                                    "finding is confirmed; see LIMITATIONS.md for what the "
                                    "scan cannot see."),
            },
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="export a round as SARIF 2.1.0")
    ap.add_argument("round_dir", help="a round directory, e.g. out/round-my-round")
    ap.add_argument("--out", default="", help="where to write (default: <round>/agentaudit.sarif)")
    ap.add_argument("--all", action="store_true",
                    help="include rows already triaged not_vuln (they are left out by default)")
    a = ap.parse_args()

    rd = Path(a.round_dir)
    if not rd.is_dir():
        raise SystemExit(f"not a directory: {rd}")
    rows = _rows(rd, a.all)

    project = ""
    if (rd / "meta.json").exists():
        meta = json.loads((rd / "meta.json").read_text(encoding="utf-8"))
        project = meta.get("project", "") or meta.get("tag", "")

    doc = build(rd, rows, project)
    out = Path(a.out) if a.out else (rd / "agentaudit.sarif")
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    n_rules = len(doc["runs"][0]["tool"]["driver"]["rules"])
    print(f"wrote {out} ({len(rows)} result(s), {n_rules} rule(s))")
    print("relative paths only; no absolute path is included")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
