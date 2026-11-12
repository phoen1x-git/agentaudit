from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.review_pack import build_review_pack, review_template  # noqa: E402
from tools.build_external_review_records import build  # noqa: E402


def write_round(path: Path, *, include_primary: bool = True) -> None:
    lines = [
        {"file": "app/main.ts", "line": 1, "text": "export function run(input: string) {"},
        {"file": "app/main.ts", "line": 2, "text": "  return blocks[index];"},
        {"file": "app/main.ts", "line": 3, "text": "}"},
    ]
    if not include_primary:
        lines = [lines[0], lines[2]]
    finding = {
        "project": "sample-project",
        "language": "typescript",
        "rule": "security/private-rule-name",
        "file": "app/main.ts",
        "line": 2,
        "snippet": "return blocks[index];",
        "analysis_provenance": {
            "backend": "Private Analyzer",
            "backend_version": "1.2.3",
            "source_version_status": "matched_referenced_files",
            "backend_results": [{"message": "PRIVATE EXTERNAL ANALYZER MESSAGE"}],
        },
        "backend_evidence": {
            "files": [{"path": "app/main.ts", "sha256": "a" * 64}],
            "lines": lines,
            "blocking_gaps": [],
        },
    }
    path.mkdir(parents=True)
    (path / "findings.json").write_text(json.dumps({"app/main.ts:abc": finding}), encoding="utf-8")


def test_external_records_are_referenced_and_opinion_free(tmp_path):
    round_dir = tmp_path / "round"
    out_dir = tmp_path / "records"
    write_round(round_dir)

    assert build(round_dir, out_dir) == 1
    record = json.loads((out_dir / "case-001.json").read_text(encoding="utf-8"))
    assert record["candidate"]["kind"] == "external_analysis_result"
    assert record["candidate_source"][0]["sha256"] == "a" * 64
    assert record["candidate_source"][0]["text"][0]["text"] == "  return blocks[index];"
    assert record["static_observations"]["status"] == "not_run"

    packet, _ = build_review_pack([record])
    template = review_template(packet)
    case = packet["cases"][0]
    assert case["candidate"]["kind"] == "external_analysis_result"
    assert "PRIVATE EXTERNAL ANALYZER MESSAGE" not in json.dumps(packet)
    assert "security/private-rule-name" not in json.dumps(packet)
    assert "Private Analyzer" not in json.dumps(packet)
    assert template["reviews"][0]["available_evidence_ids"] == [row["id"] for row in case["evidence"]]


def test_external_record_builder_requires_primary_source_excerpt(tmp_path):
    round_dir = tmp_path / "round"
    out_dir = tmp_path / "records"
    write_round(round_dir, include_primary=False)

    with pytest.raises(ValueError, match="missing primary evidence"):
        build(round_dir, out_dir)
    assert not out_dir.exists()


def test_external_record_builder_preserves_existing_output(tmp_path):
    round_dir = tmp_path / "round"
    out_dir = tmp_path / "records"
    write_round(round_dir)
    out_dir.mkdir()
    existing = out_dir / "case-001.json"
    existing.write_text("existing reviewer material", encoding="utf-8")

    with pytest.raises(ValueError, match="output directory already exists"):
        build(round_dir, out_dir)
    assert existing.read_text(encoding="utf-8") == "existing reviewer material"
    assert list(out_dir.iterdir()) == [existing]


def test_external_record_builder_rejects_incomplete_batch_before_writing(tmp_path):
    round_dir = tmp_path / "round"
    out_dir = tmp_path / "records"
    write_round(round_dir)
    findings_path = round_dir / "findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    invalid = json.loads(json.dumps(next(iter(findings.values()))))
    invalid["line"] = 99
    findings["invalid-later-candidate"] = invalid
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    with pytest.raises(ValueError, match="missing primary evidence"):
        build(round_dir, out_dir)
    assert not out_dir.exists()


def test_external_record_builder_rejects_empty_batch(tmp_path):
    round_dir = tmp_path / "round"
    round_dir.mkdir()
    (round_dir / "findings.json").write_text("{}", encoding="utf-8")
    out_dir = tmp_path / "records"

    with pytest.raises(ValueError, match="no external findings"):
        build(round_dir, out_dir)
    assert not out_dir.exists()
