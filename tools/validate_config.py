#!/usr/bin/env python
"""Validate the rule configuration, and optionally print the rule table for the README.

    python tools/validate_config.py              # check the config; exit 1 on an error
    python tools/validate_config.py --table      # print the markdown table

Run this after editing core/config/*.yml. A typo in a field name is otherwise silent: the
generator simply ignores the entry and the check quietly stops covering that function.
See CONFIGURING.md for what the fields mean.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

CFG = ROOT / "core" / "config"

SINK_MATCHERS = ("obj", "obj2", "obj_suffix", "name", "func")
SINK_FIELDS = {"id", "source", "cls", "enabled", "group", "note"} | set(SINK_MATCHERS)
SOURCE_KINDS = {"method", "attr", "name", "obj_method"}
SOURCE_FIELDS = {"id", "kind", "names", "obj_names", "obj_suffix", "note"}

ERR: list[str] = []
WARN: list[str] = []


def _err(msg: str) -> None:
    ERR.append(msg)


def _warn(msg: str) -> None:
    WARN.append(msg)


def check_sinks() -> list[dict]:
    p = CFG / "sinks.yml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    sinks = data.get("sinks") or []
    if not sinks:
        _err("sinks.yml: no `sinks:` entries at all")
        return []
    seen: dict[str, int] = {}
    for i, s in enumerate(sinks, 1):
        if not isinstance(s, dict):
            _err(f"sinks.yml #{i}: entry is not a mapping")
            continue
        sid = s.get("id")
        if not sid:
            _err(f"sinks.yml #{i}: missing `id` (the generator skips entries without one)")
            continue
        if sid in seen:
            _err(f"sinks.yml: duplicate id `{sid}` (first seen at #{seen[sid]})")
        seen[sid] = seen.get(sid, i)
        if s.get("source") not in ("paper", "extra"):
            _err(f"sinks.yml `{sid}`: `source` must be `paper` or `extra`, got {s.get('source')!r}")
        if s.get("cls") not in ("direct", "structural"):
            _err(f"sinks.yml `{sid}`: `cls` must be `direct` or `structural`, got {s.get('cls')!r}")
        elif s["cls"] == "structural":
            _warn(f"sinks.yml `{sid}`: `cls: structural` needs a definition site to chase, "
                  "so it is not generated -- it will not be checked")
        if not any(s.get(k) for k in SINK_MATCHERS):
            _err(f"sinks.yml `{sid}`: no matcher -- needs at least one of {', '.join(SINK_MATCHERS)}")
        unknown = set(s) - SINK_FIELDS
        if unknown:
            _err(f"sinks.yml `{sid}`: unknown field(s) {sorted(unknown)}; the generator ignores "
                 f"them, so the entry would silently match nothing. Known: {sorted(SINK_FIELDS)}")
        if s.get("obj") == "*":
            _warn(f"sinks.yml `{sid}`: `obj: \"*\"` matches every object and is very noisy")
    return sinks


def check_sources() -> list[dict]:
    p = CFG / "sources.yml"
    if not p.exists():
        _warn("sources.yml: missing; inter-procedural argument sources will be empty")
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    sources = data.get("sources") or []
    seen: set[str] = set()
    for i, s in enumerate(sources, 1):
        if not isinstance(s, dict):
            _err(f"sources.yml #{i}: entry is not a mapping")
            continue
        sid = s.get("id")
        if not sid:
            _err(f"sources.yml #{i}: missing `id`")
            continue
        if sid in seen:
            _err(f"sources.yml: duplicate id `{sid}`")
        seen.add(sid)
        if s.get("kind") not in SOURCE_KINDS:
            _err(f"sources.yml `{sid}`: `kind` must be one of {sorted(SOURCE_KINDS)}, "
                 f"got {s.get('kind')!r}")
        if not (s.get("names") or s.get("obj_names")):
            _err(f"sources.yml `{sid}`: needs `names` or `obj_names`")
        unknown = set(s) - SOURCE_FIELDS
        if unknown:
            _err(f"sources.yml `{sid}`: unknown field(s) {sorted(unknown)}")
    return sources


def check_filters() -> dict:
    p = CFG / "filters.yml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    for k in ("path_segments", "filename_re", "substrings"):
        if k not in data:
            _warn(f"filters.yml: no `{k}` key (allowed, but the filter then ignores that layer)")
    return data


def table(sinks: list[dict]) -> str:
    """Render the enabled sink rules as a markdown table."""
    rows = ["| Rule | Matches | Group | Default |", "|---|---|---|---|"]
    for s in sinks:
        if not s.get("enabled", True):
            continue
        parts = []
        if s.get("name"):
            parts.append(f"`{s['name']}(...)`")
        if s.get("obj"):
            parts.append(f"`{s['obj']}.{s.get('func', '*')}(...)`")
        if s.get("obj2"):
            parts.append(f"`{s['obj2']}.{s.get('func', '*')}(...)`")
        if s.get("obj_suffix"):
            parts.append(f"`*{s['obj_suffix']}.{s.get('func', '*')}(...)`")
        group = s.get("group", "")
        default = "**on**" if s.get("source") == "extra" and not group else ("on (baseline)"
                                                                           if s.get("source") == "paper" else "off")
        if group:
            default = f"off (`AF_SINKS_{group.upper()}`)"
        rows.append(f"| `{s['id']}` | {', '.join(parts) or '-'} | {group or '-'} | {default} |")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="validate core/config/*.yml")
    ap.add_argument("--table", action="store_true", help="print the rule table as markdown")
    a = ap.parse_args()

    sinks = check_sinks()
    sources = check_sources()
    check_filters()

    if a.table:
        print(table(sinks))
        print()
        print(f"<!-- {len(sinks)} sink rules, {len(sources)} source rules -->")
        return 0

    for w in WARN:
        print(f"WARN  {w}")
    for e in ERR:
        print(f"ERROR {e}")
    print(f"\n{len(sinks)} sink rules, {len(sources)} source rules, "
          f"{len(WARN)} warning(s), {len(ERR)} error(s)")
    if ERR:
        print("config is invalid; see CONFIGURING.md")
        return 1
    print("config ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
