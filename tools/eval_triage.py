"""Offline fixed-response policy replay. No model calls or target execution."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import workspace  # noqa: E402
from core import llm_judge as LJ  # noqa: E402
from core import triage_contract as T  # noqa: E402
from core.finding import Finding  # noqa: E402


def read_cases(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "triage-replay-v1" or not data.get("cases"):
        raise ValueError("invalid or empty replay dataset")
    seen = set()
    for c in data["cases"]:
        if c["id"] in seen or c["split"] not in {"dev", "heldout"}:
            raise ValueError("duplicate case or invalid split")
        seen.add(c["id"])
        if hashlib.sha256(c["source"]["text"].encode("utf-8")).hexdigest() != c["source"]["sha256"]:
            raise ValueError(f"source hash mismatch: {c['id']}")
        if T.digest(c["response"]) != c["response_sha256"]:
            raise ValueError(f"response hash mismatch: {c['id']}")
        if c["origin"]["kind"] != "synthetic":
            raise ValueError("this evaluator accepts synthetic replay cases only")
        if c["expected"] not in {"vuln", "not_vuln", "needs_human", "error"}:
            raise ValueError("invalid expected output")
    return data


def replay(data: dict, split: str = "dev") -> dict:
    selected = [c for c in data["cases"] if split == "all" or c["split"] == split]
    if not selected:
        raise ValueError("selected split is empty")
    rows = []
    for c in selected:
        source = c["source"]
        snapshot = {"lines": [{"file": source["file"], "line": i, "text": text}
                              for i, text in enumerate(source["text"].splitlines(), 1)],
                    "files": [{"path": source["file"], "sha256": source["sha256"]}],
                    "blocking_gaps": []}
        fd = Finding(project="synthetic-replay", fingerprint=c["id"])
        try:
            LJ._apply(fd, c["response"], snapshot)
        except T.ContractError:
            pass  # _apply records a distinct error, never a safe classification.
        rows.append({"id": c["id"], "split": c["split"], "reference": c["reference"],
                     "legacy": c["legacy_result"]["ai_verdict"], "current": fd.ai_verdict,
                     "expected": c["expected"], "matches": fd.ai_verdict == c["expected"],
                     "adjustments": fd.judge_json["_audit"].get("adjustments", []),
                     "error": fd.judge_json["_audit"].get("error")})
    summary = {}
    for label in ("legacy", "current"):
        summary[label] = {
            "distribution": dict(sorted(Counter(r[label] for r in rows).items())),
            "risky_reference_auto_excluded": sum(r["reference"] == "risky" and r[label] == "not_vuln"
                                                  for r in rows),
            "constrained_reference_unresolved": sum(r["reference"] == "constrained"
                                                     and r[label] == "needs_human" for r in rows),
            "invalid_responses_separated": sum(r["reference"] == "invalid" and r[label] == "error"
                                                for r in rows),
        }
    return {"scope": "synthetic fixed-response policy regression; NOT detection/model accuracy",
            "split": split, "n_cases": len(rows),
            "expected_matches": sum(r["matches"] for r in rows),
            "dataset_sha256": T.digest(data), "policy": LJ.policy_stamp(),
            "legacy_implementation": data["legacy_implementation"],
            "summary": summary, "cases": rows}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=Path, default=ROOT / "tests/fixtures/triage/cases.json")
    ap.add_argument("--split", choices=["dev", "heldout", "all"], default="dev")
    ap.add_argument("--out", type=Path, default=workspace() / "out" / "triage-eval")
    a = ap.parse_args(argv)
    try:
        result = replay(read_cases(a.cases), a.split)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"[eval] invalid dataset: {exc}")
        return 2
    a.out.mkdir(parents=True, exist_ok=True)
    path = a.out / f"{a.split}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(f"[eval] {a.split}: {result['expected_matches']}/{result['n_cases']} policy expectations matched")
    print("[eval] synthetic replay only; no target execution or model accuracy measurement")
    print(f"[eval] {path}")
    return 0 if result["expected_matches"] == result["n_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
