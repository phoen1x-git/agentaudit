"""Join a validated human-review submission back to private case identities.

The command consumes the opinion-masked packet, its private mapping, and the
validated submission. It writes a private result file. It never changes the
original findings or fills the machine/human verdict columns.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from statistics import median
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.review_pack import _digest  # noqa: E402


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _hash_without(value: dict, field: str) -> str:
    return _digest({key: item for key, item in value.items() if key != field})


def merge(packet: dict, mapping: dict, validated: dict | list[dict]) -> dict:
    if packet.get("schema") != "agentaudit-evidence-review-pack-v1":
        raise ValueError("unsupported packet schema")
    if mapping.get("schema") != "agentaudit-review-map-v1":
        raise ValueError("unsupported review mapping schema")
    submissions = validated if isinstance(validated, list) else [validated]
    if not submissions:
        raise ValueError("at least one validated submission is required")
    packet_hash = packet.get("packet_sha256")
    if _hash_without(packet, "packet_sha256") != packet_hash:
        raise ValueError("packet hash mismatch")
    if mapping.get("packet_sha256") != packet_hash:
        raise ValueError("packet identity mismatch")
    if _hash_without(mapping, "mapping_sha256") != mapping.get("mapping_sha256"):
        raise ValueError("mapping hash mismatch")

    map_by_review = {row["review_id"]: row for row in mapping.get("cases", [])}
    results_by_case = {review_id: [] for review_id in map_by_review}
    reviewer_ids = set()
    distribution = {"confirmed": 0, "rejected": 0, "undetermined": 0}
    for submission in submissions:
        if submission.get("schema") != "agentaudit-validated-review-submission-v1":
            raise ValueError("submission has not passed review validation")
        if submission.get("packet_sha256") != packet_hash:
            raise ValueError("packet identity mismatch")
        for review in submission.get("reviews", []):
            review_id = review.get("review_id")
            if review_id not in map_by_review:
                raise ValueError("submission contains an unknown review id")
            reviewer_id = review.get("reviewer_id")
            reviewer_key = (reviewer_id, review_id)
            if reviewer_key in reviewer_ids:
                raise ValueError("the same reviewer submitted a duplicate review for a case")
            reviewer_ids.add(reviewer_key)
            identity = map_by_review[review_id]
            result = review.get("result")
            distribution[result] = distribution.get(result, 0) + 1
            results_by_case[review_id].append({
                "record_id": identity.get("record_id"),
                "project": identity.get("project"),
                "candidate": identity.get("candidate"),
                "historical_claim": identity.get("historical_claim"),
                "human_review": {
                    "reviewer_id": reviewer_id,
                    "review_started_at": review.get("review_started_at"),
                    "reviewed_at": review.get("reviewed_at"),
                    "duration_seconds": review.get("duration_seconds"),
                    "result": result,
                    "rationale": review.get("rationale"),
                    "evidence_ids": review.get("evidence_ids"),
                    "dimensions": review.get("dimensions"),
                    "external_evidence": review.get("external_evidence"),
                    "unresolved_questions": review.get("unresolved_questions"),
                },
            })

    results = []
    agreement_cases = []
    durations = []
    for review_id, reviews in results_by_case.items():
        if not reviews:
            continue
        decisions = [row["human_review"]["result"] for row in reviews]
        durations.extend(
            row["human_review"]["duration_seconds"] for row in reviews
            if isinstance(row["human_review"].get("duration_seconds"), (int, float))
        )
        agreement = len(set(decisions)) == 1 if len(decisions) >= 2 else None
        agreement_cases.append({"review_id": review_id, "reviewer_count": len(reviews), "exact_agreement": agreement})
        results.append({"review_id": review_id, "reviews": reviews,
                        "reviewer_count": len(reviews), "exact_agreement": agreement})

    comparable = [row for row in agreement_cases if row["exact_agreement"] is not None]
    full_coverage = len(results_by_case) == len(map_by_review) and all(results_by_case.values())
    missing = sorted(review_id for review_id, rows in results_by_case.items() if not rows)
    return {
        "schema": "agentaudit-merged-human-review-v1",
        "packet_sha256": packet_hash,
        "mapping_sha256": mapping["mapping_sha256"],
        "validated_submission_sha256": [_digest(row) for row in submissions],
        "review_count": sum(len(rows) for rows in results_by_case.values()),
        "reviewer_count": len({reviewer for reviewer, _ in reviewer_ids}),
        "full_case_coverage": bool(full_coverage),
        "missing_review_ids": missing,
        "distribution": distribution,
        "reviewer_agreement": {
            "cases_with_multiple_reviews": len(comparable),
            "exact_agreement_cases": sum(row["exact_agreement"] is True for row in comparable),
            "exact_agreement_rate": (sum(row["exact_agreement"] is True for row in comparable) / len(comparable)
                                      if comparable else None),
            "case_details": agreement_cases,
            "scope": "descriptive exact agreement only; no chance correction and no claim of reviewer accuracy",
        },
        "comparison": {
            "historical_label_status": "not_available_in_source_records",
            "accuracy": None,
            "agreement": None,
            "manual_review_time": {
                "self_reported_seconds_total": round(sum(durations), 3) if durations else None,
                "self_reported_seconds_median": round(median(durations), 3) if durations else None,
                "observation_count": len(durations),
                "meaning": "Reviewer-entered start and finish timestamps; interruptions are included unless excluded by the reviewer.",
            },
            "meaning": "This file joins human results to private identities. It does not infer correctness or compare to an absent independent label.",
        },
        "results": results,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentaudit review-merge", description=__doc__)
    parser.add_argument("--packet", type=Path, required=True,
                        help="the packet.json the reviewers were given")
    parser.add_argument("--mapping", type=Path, required=True,
                        help="the private mapping written by review-pack")
    parser.add_argument("--validated", type=Path, action="append", required=True,
                        help="validated JSON submission; repeat for multiple reviewers")
    parser.add_argument("--out", type=Path, required=True,
                        help="where to write the merged result; it names the projects, so keep it private")
    args = parser.parse_args(argv)
    try:
        validated = [_load(path) for path in args.validated]
        merged = merge(_load(args.packet), _load(args.mapping), validated)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"merged {merged['review_count']} human reviews; historical accuracy remains unmeasured")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"merge_review_submission: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
