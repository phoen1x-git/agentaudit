"""Responsiveness check for candidate targets (read-only, cheap).

For each candidate repo, asks:
  - does it have a SECURITY.md / security policy?   (reporting channel exists?)
  - when was the last issue/PR closed?               (does a human act on issues?)
  - how many open issues?                            (backlog)
This is 约定① from  ("会不会回信") — measurable before download.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))
import gh  # noqa: E402

SRC = ROOT / "data" / "target_pool" / "_select_v1.json"
OUT = ROOT / "data" / "target_pool" / "_responsiveness.json"


def days_since(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None
    return (datetime.now(timezone.utc) - dt).days


def main() -> None:
    good = json.load(open(SRC, encoding="utf-8"))["good"]
    rows = []
    for x in good:
        r = x["repo"]
        code, _ = gh.get(f"{gh.API}/repos/{r}/contents/SECURITY.md")
        has_sec = code == 200
        closed = gh.get_json(f"{gh.API}/repos/{r}/issues?state=closed&per_page=1&sort=updated")
        last_closed = None
        if isinstance(closed, list) and closed:
            last_closed = closed[0].get("closed_at") or closed[0].get("updated_at")
        iss = gh.get_json(f"{gh.API}/repos/{r}/issues?state=open&per_page=1")
        n_open = None
        rows.append({
            "repo": r, "has_security_md": has_sec,
            "days_since_last_closed": days_since(last_closed),
            "last_closed_at": last_closed,
            "commits_90d": x.get("commits_90d"), "surface_score": x.get("surface_score"),
            "stars": x.get("stars"),
        })
        print(f"  {r:42} SEC={has_sec} lastclose={days_since(last_closed)}d", file=sys.stderr)

    rows.sort(key=lambda x: (x["days_since_last_closed"] if x["days_since_last_closed"] is not None else 9999))

    print("\n===== 回应速度（约定①）=====")
    print(f"{'repo':42} {'SEC.md':>6} {'上次关issue':>11} {'c90':>4} {'exec':>5} {'stars':>6}")
    for x in rows:
        d = x["days_since_last_closed"]
        ds = f"{d:.0f}d" if d is not None else "?"
        print(f"{x['repo']:42} {'YES' if x['has_security_md'] else '-':>6} {ds:>11} "
              f"{x['commits_90d']:>4} {str(x['surface_score']):>5} {x['stars']:>6}")

    OUT.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nwritten: {OUT}")


if __name__ == "__main__":
    main()
