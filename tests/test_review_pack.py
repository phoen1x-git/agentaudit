from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.review_pack import (  # noqa: E402
    build_review_pack,
    review_template,
    validate_review_submissions,
)
from tools.merge_review_submission import merge  # noqa: E402


def reference(file="src/app.py", line=4, text="    run(value)"):
    return {
        "file": file,
        "sha256": "a" * 64,
        "start_line": line,
        "end_line": line,
        "text": [{"line": line, "text": text}],
    }


def record(record_id, project, line, old_claim):
    candidate = reference(line=line, text="    eval(value)")
    context = reference(line=line + 1, text="    return value")
    return {
        "schema": "agentaudit-review-record-v1",
        "id": record_id,
        "project": project,
        "candidate": {"file": "src/app.py", "line": line, "entry_name": "run"},
        "historical_claim": {"claim": old_claim, "confidence": "0.99"},
        "independent_vulnerability_label": None,
        "candidate_source": [candidate],
        "expected_material": [{"source": context, "retrieved": True}],
        "collected_evidence": [{"source": context, "kind": "local_dependency", "meaning": "syntactic only"}],
        "source_review": {"reviewed_facts": [{"claim": "private interpretation", "references": [context]}]},
        "static_observations": {"status": "observed", "observations": [{"kind": "syntax"}]},
        "open_questions": ["实际部署和运行时绑定未知", "历史模型意见尚未复核"],
    }


def completed_submission(packet):
    submission = review_template(packet)
    for row in submission["reviews"]:
        row.update(
            reviewer_id="reviewer-1",
            review_started_at="2026" + "-11-02T11:55:00+08:00",
            reviewed_at="2026" + "-11-02T12:00:00+08:00",
            historical_opinion_consulted=False,
            result="undetermined",
            rationale="证据不足以确认完整运行路径或实际输入控制。",
            evidence_ids=[row["available_evidence_ids"][0]],
            external_evidence=[],
            unresolved_questions=["runtime dispatch"],
        )
    return submission


def test_packet_masks_history_and_identity_but_keeps_cited_source_and_mapping():
    rows = [record("case-a", "project-a", 4, "FIRST PRIVATE OPINION"),
            record("case-b", "project-b", 14, "SECOND PRIVATE OPINION")]
    packet, mapping = build_review_pack(rows, seed=17)
    packet_text = str(packet)
    assert "PRIVATE OPINION" not in packet_text
    assert "project-a" not in packet_text and "project-b" not in packet_text
    assert "src/app.py" not in packet_text
    assert "eval(value)" in packet_text
    assert packet["packet_sha256"] == mapping["packet_sha256"]
    assert {row["record_id"] for row in mapping["cases"]} == {"case-a", "case-b"}
    assert build_review_pack(rows, seed=17)[0] == packet


def test_packet_is_not_labeled_as_independent_ground_truth():
    packet, _ = build_review_pack([record("case-a", "project-a", 4, "HISTORICAL CLAIM")])
    assert "independent_vulnerability_label" not in str(packet)
    assert any(q == "实际部署和运行时绑定未知" for q in packet["cases"][0]["known_unknowns"])
    assert all("历史模型意见" not in q for q in packet["cases"][0]["known_unknowns"])


def test_valid_submission_checks_packet_and_citations_only():
    packet, _ = build_review_pack([record("case-a", "project-a", 4, "HISTORICAL CLAIM")])
    submission = completed_submission(packet)
    result = validate_review_submissions(packet, submission)
    assert result["review_count"] == 1
    assert "not independently verified" in result["validation_scope"]
    assert result["reviews"][0]["result"] == "undetermined"


@pytest.mark.parametrize("mutation", ["wrong_packet", "viewed_history", "unknown_evidence", "missing_rationale", "unknown_result"])
def test_invalid_submission_is_rejected(tmp_path, mutation):
    packet, _ = build_review_pack([record("case-a", "project-a", 4, "HISTORICAL CLAIM")])
    submission = completed_submission(packet)
    row = submission["reviews"][0]
    if mutation == "wrong_packet":
        row["packet_sha256"] = "0" * 64
    elif mutation == "viewed_history":
        row["historical_opinion_consulted"] = True
    elif mutation == "unknown_evidence":
        row["evidence_ids"] = ["E99999"]
    elif mutation == "missing_rationale":
        row["rationale"] = "too short"
    else:
        row["result"] = "maybe"
    with pytest.raises(ValueError):
        validate_review_submissions(packet, submission)


def test_tampered_packet_or_incomplete_batch_is_rejected():
    records = [record("case-a", "project-a", 4, "HISTORICAL CLAIM"),
               record("case-b", "project-b", 14, "OTHER CLAIM")]
    packet, _ = build_review_pack(records)
    partial = completed_submission(packet)
    partial["reviews"].pop()
    with pytest.raises(ValueError, match="every packet case"):
        validate_review_submissions(packet, partial)
    changed = copy.deepcopy(packet)
    changed["cases"][0]["known_unknowns"].append("tampered")
    with pytest.raises(ValueError, match="packet hash"):
        validate_review_submissions(changed, completed_submission(changed))


def test_validated_reviews_merge_back_without_mutating_source_records():
    rows = [record("case-a", "project-a", 4, "HISTORICAL CLAIM"),
            record("case-b", "project-b", 14, "OTHER CLAIM")]
    packet, mapping = build_review_pack(rows, seed=3)
    submission = completed_submission(packet)
    submission["reviews"][0]["result"] = "confirmed"
    validated = validate_review_submissions(packet, submission)
    merged = merge(packet, mapping, validated)
    assert merged["review_count"] == 2
    assert merged["distribution"]["confirmed"] == 1
    assert merged["comparison"]["accuracy"] is None
    assert {item["reviews"][0]["record_id"] for item in merged["results"]} == {"case-a", "case-b"}
    assert merged["reviewer_agreement"]["exact_agreement_rate"] is None
    assert merged["comparison"]["manual_review_time"]["self_reported_seconds_total"] == 600


def test_merge_reports_descriptive_inter_reviewer_agreement():
    rows = [record("case-a", "project-a", 4, "HISTORICAL CLAIM"),
            record("case-b", "project-b", 14, "OTHER CLAIM")]
    packet, mapping = build_review_pack(rows, seed=9)
    first = completed_submission(packet)
    first["reviews"][0]["result"] = "confirmed"
    first["reviews"][1]["result"] = "undetermined"
    second = completed_submission(packet)
    for row in second["reviews"]:
        row["reviewer_id"] = "reviewer-2"
    second["reviews"][0]["result"] = "confirmed"
    second["reviews"][1]["result"] = "rejected"
    merged = merge(packet, mapping, [validate_review_submissions(packet, first),
                                     validate_review_submissions(packet, second)])
    stats = merged["reviewer_agreement"]
    assert merged["reviewer_count"] == 2 and merged["review_count"] == 4
    assert stats["cases_with_multiple_reviews"] == 2
    assert stats["exact_agreement_cases"] == 1
    assert stats["exact_agreement_rate"] == 0.5
    assert "no chance correction" in stats["scope"]
    assert merged["comparison"]["manual_review_time"]["observation_count"] == 4


def test_merge_rejects_packet_or_mapping_identity_mismatch():
    packet, mapping = build_review_pack([record("case-a", "project-a", 4, "HISTORICAL CLAIM")])
    validated = validate_review_submissions(packet, completed_submission(packet))
    bad_mapping = copy.deepcopy(mapping)
    bad_mapping["packet_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        merge(packet, bad_mapping, validated)


def test_review_cli_validate_and_merge_multiple_reviewers(tmp_path):
    packet, mapping = build_review_pack([record("case-a", "project-a", 4, "HISTORICAL CLAIM")])
    packet_path = tmp_path / "packet.json"
    mapping_path = tmp_path / "mapping.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    mapping_path.write_text(json.dumps(mapping), encoding="utf-8")
    validated_paths = []
    now = datetime.now(timezone.utc)
    for index, decision in enumerate(("confirmed", "rejected"), 1):
        submission = review_template(packet)
        row = submission["reviews"][0]
        row.update(
            reviewer_id=f"reviewer-{index}",
            review_started_at=(now - timedelta(minutes=5)).isoformat(),
            reviewed_at=now.isoformat(),
            historical_opinion_consulted=False,
            result=decision,
            rationale="本复核结论引用包内证据，并记录了当前缺少的运行时信息。",
            evidence_ids=[row["available_evidence_ids"][0]],
            external_evidence=[],
            unresolved_questions=[],
        )
        submission_path = tmp_path / f"submission-{index}.json"
        validated_path = tmp_path / f"validated-{index}.json"
        submission_path.write_text(json.dumps(submission), encoding="utf-8")
        checked = subprocess.run(
            [sys.executable, str(ROOT / "tools/validate_review_pack.py"), "--packet", str(packet_path),
             "--submission", str(submission_path), "--out", str(validated_path)],
            capture_output=True, text=True, cwd=ROOT,
        )
        assert checked.returncode == 0, checked.stdout + checked.stderr
        validated_paths.append(validated_path)

    merged_path = tmp_path / "merged.json"
    args = [sys.executable, str(ROOT / "tools/merge_review_submission.py"),
            "--packet", str(packet_path), "--mapping", str(mapping_path), "--out", str(merged_path)]
    for path in validated_paths:
        args.extend(["--validated", str(path)])
    merged = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    assert merged.returncode == 0, merged.stdout + merged.stderr
    result = json.loads(merged_path.read_text(encoding="utf-8"))
    assert result["review_count"] == 2
    assert result["reviewer_agreement"]["exact_agreement_rate"] == 0
    assert result["comparison"]["accuracy"] is None
    assert result["comparison"]["manual_review_time"]["observation_count"] == 2
