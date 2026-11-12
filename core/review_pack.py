"""Prepare opinion-free evidence packets and validate human review submissions.

This module validates structure and citations only. It never assigns or changes a
security verdict.
"""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime
from typing import Any


PACK_SCHEMA = "agentaudit-evidence-review-pack-v1"
REVIEW_SCHEMA = "agentaudit-human-review-v1"
RESULTS = {"confirmed", "rejected", "undetermined"}
DIMENSIONS = {
    "input_origin": {"supported", "not_supported", "unknown"},
    "input_control": {"supported", "not_supported", "unknown"},
    "execution_effect": {"supported", "not_supported", "unknown"},
    "effective_guard": {"supported", "not_supported", "unknown"},
    "runtime_scope": {"supported", "not_supported", "unknown"},
    "impact": {"supported", "not_supported", "unknown"},
}


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _source_key(ref: dict) -> tuple:
    return (
        ref.get("file"), ref.get("sha256"), ref.get("start_line"), ref.get("end_line"),
        tuple((row.get("line"), row.get("text")) for row in ref.get("text", [])),
    )


def _validate_source_ref(ref: dict) -> None:
    if not isinstance(ref, dict):
        raise ValueError("source reference must be an object")
    if not isinstance(ref.get("file"), str) or not ref["file"]:
        raise ValueError("source reference is missing a file")
    if not isinstance(ref.get("sha256"), str) or len(ref["sha256"]) != 64:
        raise ValueError("source reference has an invalid SHA-256")
    start, end = ref.get("start_line"), ref.get("end_line")
    if (isinstance(start, bool) or not isinstance(start, int) or isinstance(end, bool)
            or not isinstance(end, int) or start < 1 or end < start):
        raise ValueError("source reference has an invalid line range")
    rows = ref.get("text")
    if not isinstance(rows, list) or len(rows) != end - start + 1:
        raise ValueError("source reference lines do not match the declared range")
    for offset, row in enumerate(rows):
        if (not isinstance(row, dict) or row.get("line") != start + offset
                or not isinstance(row.get("text"), str)):
            raise ValueError("source reference has invalid line text")


def build_review_pack(records: list[dict], *, seed: int = 0) -> tuple[dict, dict]:
    """Return an opinion-free packet and a separate identity/source mapping."""
    if not records:
        raise ValueError("at least one evidence record is required")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    rng = random.Random(seed)
    source_ids = [record.get("id") for record in records]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("evidence record ids must be unique")
    order = list(range(len(records)))
    rng.shuffle(order)
    ordered = [records[index] for index in order]
    packet_cases, map_cases = [], []
    evidence_counter = 0

    for ordinal, record in enumerate(ordered, 1):
        if record.get("schema") != "agentaudit-review-record-v1":
            raise ValueError("unsupported evidence record schema")
        review_id = f"review-{ordinal:03d}"
        aliases: dict[str, str] = {}
        evidence_by_key: dict[tuple, dict] = {}
        evidence_rows: list[dict] = []

        def add_ref(ref: dict, role: str, *, retrieved: bool | None = None) -> str:
            nonlocal evidence_counter
            _validate_source_ref(ref)
            key = _source_key(ref)
            if key in evidence_by_key:
                evidence_id = evidence_by_key[key]["id"]
                existing = evidence_by_key[key]
                if role not in existing["roles"]:
                    existing["roles"].append(role)
                if retrieved is not None:
                    existing["retrieved"] = retrieved
                return evidence_id
            evidence_counter += 1
            evidence_id = f"E{evidence_counter:05d}"
            alias = aliases.setdefault(ref["file"], f"source-{len(aliases) + 1:02d}")
            row = {
                "id": evidence_id,
                "source": alias,
                "sha256": ref["sha256"],
                "start_line": ref["start_line"],
                "end_line": ref["end_line"],
                "lines": ref["text"],
                "roles": [role],
            }
            if retrieved is not None:
                row["retrieved"] = retrieved
            evidence_rows.append(row)
            evidence_by_key[key] = row
            return evidence_id

        candidate_refs = record.get("candidate_source", [])
        if not candidate_refs:
            raise ValueError("evidence record has no candidate source")
        candidate_ids = [add_ref(ref, "candidate") for ref in candidate_refs]
        expected = []
        for item in record.get("expected_material", []):
            evidence_id = add_ref(item["source"], "preselected_context", retrieved=item.get("retrieved"))
            expected.append({"evidence_id": evidence_id, "retrieved": bool(item.get("retrieved"))})
        investigation_ids = []
        for item in record.get("collected_evidence", []):
            evidence_id = add_ref(item["source"], "collected_context")
            investigation_ids.append({
                "evidence_id": evidence_id,
                "kind": item.get("kind", ""),
                "relation_status": item.get("relation"),
                "meaning": item.get("meaning", ""),
            })
        reviewed_refs = []
        source_review = record.get("source_review") or {}
        for fact in source_review.get("reviewed_facts", []):
            for ref in fact.get("references", []):
                reviewed_refs.append({"evidence_id": add_ref(ref, "additional_context")})

        observations = record.get("static_observations", {})
        packet_case = {
            "review_id": review_id,
            "language": record.get("candidate", {}).get("language", "python"),
            "candidate": {
                "kind": record.get("candidate", {}).get("kind", "call_site"),
                "sink_name": record.get("candidate", {}).get("sink_name", ""),
                "line": record["candidate"]["line"],
                "evidence_ids": candidate_ids,
            },
            "evidence": evidence_rows,
            "retrieval_context": {
                "preselected_locations": expected,
                "additional_collected_context": investigation_ids,
                "independently_reviewed_source_context": reviewed_refs,
            },
            "tool_observations": {
                "status": observations.get("status", "unknown"),
                "observations": observations.get("observations", []),
                "limitations": observations.get("limitations", []),
                "scope": observations.get("scope", ""),
            },
            "known_unknowns": [
                question for question in record.get("open_questions", [])
                if not any(token in question.lower() for token in ("历史", "模型意见", "旧自动", "historical", "old model"))
            ],
        }
        packet_cases.append(packet_case)
        map_cases.append({
            "review_id": review_id,
            "record_id": record.get("id"),
            "project": record.get("project"),
            "candidate": record.get("candidate"),
            "source_aliases": aliases,
            "historical_claim": record.get("historical_claim"),
        })

    packet = {"schema": PACK_SCHEMA, "cases": packet_cases}
    packet["packet_sha256"] = _digest(packet)
    mapping = {"schema": "agentaudit-review-map-v1", "packet_sha256": packet["packet_sha256"], "cases": map_cases}
    mapping["mapping_sha256"] = _digest(mapping)
    return packet, mapping


def review_template(packet: dict) -> dict:
    if packet.get("schema") != PACK_SCHEMA:
        raise ValueError("unsupported packet schema")
    reviews = []
    for case in packet.get("cases", []):
        evidence_ids = [row["id"] for row in case.get("evidence", [])]
        reviews.append({
            "schema": REVIEW_SCHEMA,
            "review_id": case["review_id"],
            "packet_sha256": packet["packet_sha256"],
            "reviewer_id": "",
            "review_started_at": "",
            "reviewed_at": "",
            "historical_opinion_consulted": None,
            "result": "",
            "rationale": "",
            "evidence_ids": [],
            "dimensions": {key: "unknown" for key in DIMENSIONS},
            "external_evidence": [],
            "unresolved_questions": [],
            "available_evidence_ids": evidence_ids,
        })
    return {"schema": "agentaudit-human-review-submission-v1", "packet_sha256": packet["packet_sha256"], "reviews": reviews}


def validate_review_submissions(packet: dict, submission: dict, *, require_all: bool = True) -> dict:
    """Validate form structure and evidence references; do not validate truth."""
    if packet.get("schema") != PACK_SCHEMA:
        raise ValueError("unsupported packet schema")
    expected_hash = packet.get("packet_sha256")
    without_hash = {key: value for key, value in packet.items() if key != "packet_sha256"}
    if _digest(without_hash) != expected_hash:
        raise ValueError("packet hash mismatch")
    if submission.get("schema") != "agentaudit-human-review-submission-v1":
        raise ValueError("unsupported review submission schema")
    if submission.get("packet_sha256") != expected_hash:
        raise ValueError("submission refers to a different packet")
    packet_cases = {case["review_id"]: case for case in packet.get("cases", [])}
    reviews = submission.get("reviews")
    if not isinstance(reviews, list):
        raise ValueError("reviews must be a list")
    seen = set()
    accepted = []
    for row in reviews:
        if not isinstance(row, dict) or row.get("schema") != REVIEW_SCHEMA:
            raise ValueError("invalid review record")
        review_id = row.get("review_id")
        if review_id not in packet_cases:
            raise ValueError("review refers to an unknown case")
        if review_id in seen:
            raise ValueError("duplicate review for a case")
        seen.add(review_id)
        if row.get("packet_sha256") != expected_hash:
            raise ValueError("review record refers to a different packet")
        if not isinstance(row.get("reviewer_id"), str) or not row["reviewer_id"].strip():
            raise ValueError("reviewer_id is required")
        parsed_times = {}
        for name in ("review_started_at", "reviewed_at"):
            if not isinstance(row.get(name), str) or not row[name].strip():
                raise ValueError(f"{name} is required")
            try:
                parsed_times[name] = datetime.fromisoformat(row[name])
            except ValueError as exc:
                raise ValueError(f"{name} must be an ISO 8601 timestamp") from exc
            if parsed_times[name].tzinfo is None or parsed_times[name].utcoffset() is None:
                raise ValueError(f"{name} must include a timezone")
        duration_seconds = (parsed_times["reviewed_at"] - parsed_times["review_started_at"]).total_seconds()
        if duration_seconds < 0:
            raise ValueError("reviewed_at cannot be earlier than review_started_at")
        if row.get("historical_opinion_consulted") is not False:
            raise ValueError("the review packet must be completed before consulting historical opinions")
        result = row.get("result")
        if result not in RESULTS:
            raise ValueError("result must be confirmed, rejected, or undetermined")
        rationale = row.get("rationale")
        if not isinstance(rationale, str) or len(rationale.strip()) < 20:
            raise ValueError("a rationale of at least 20 characters is required")
        cited = row.get("evidence_ids")
        if not isinstance(cited, list) or not cited or any(not isinstance(value, str) for value in cited):
            raise ValueError("at least one evidence id must be cited")
        available = {item["id"] for item in packet_cases[review_id].get("evidence", [])}
        if len(set(cited)) != len(cited) or not set(cited) <= available:
            raise ValueError("review contains duplicate or unknown evidence ids")
        dimensions = row.get("dimensions")
        if not isinstance(dimensions, dict) or set(dimensions) != set(DIMENSIONS):
            raise ValueError("review dimensions are incomplete")
        for key, choices in DIMENSIONS.items():
            if dimensions.get(key) not in choices:
                raise ValueError(f"invalid review dimension: {key}")
        if not isinstance(row.get("external_evidence"), list) or not all(isinstance(x, str) for x in row["external_evidence"]):
            raise ValueError("external_evidence must be a list of notes")
        if not isinstance(row.get("unresolved_questions"), list) or not all(isinstance(x, str) for x in row["unresolved_questions"]):
            raise ValueError("unresolved_questions must be a list of strings")
        accepted.append({key: value for key, value in row.items() if key != "available_evidence_ids"}
                        | {"duration_seconds": round(duration_seconds, 3)})
    if require_all and seen != set(packet_cases):
        raise ValueError("submission does not cover every packet case")
    return {
        "schema": "agentaudit-validated-review-submission-v1",
        "packet_sha256": expected_hash,
        "review_count": len(accepted),
        "reviews": accepted,
        "validation_scope": "form completeness, packet identity and evidence references only; human claims are not independently verified",
        "validated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
