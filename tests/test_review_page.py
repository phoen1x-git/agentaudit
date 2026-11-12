from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.review_pack import build_review_pack, review_template  # noqa: E402
from tools.render_review_page import render  # noqa: E402
from tools import build_review_pack as packet_builder  # noqa: E402


def ref(line=4, text="    eval(value)"):
    return {"file": "src/app.py", "sha256": "b" * 64, "start_line": line,
            "end_line": line, "text": [{"line": line, "text": text}]}


def make_record():
    context = ref(5, "    return value")
    return {
        "schema": "agentaudit-review-record-v1", "id": "case-a", "project": "private-project",
        "candidate": {"file": "src/app.py", "line": 4, "entry_name": "run"},
        "historical_claim": {"claim": "old opinion", "confidence": "0.8"},
        "candidate_source": [ref()],
        "expected_material": [{"source": context, "retrieved": True}],
        "collected_evidence": [{"source": context, "kind": "context", "meaning": "syntax"}],
        "source_review": {"reviewed_facts": []},
        "static_observations": {"status": "inconclusive", "observations": [], "limitations": [], "scope": "source only"},
        "open_questions": ["runtime path unknown"],
    }


def test_rendered_page_is_self_contained_and_masks_opinions():
    packet, _ = build_review_pack([make_record()])
    page = render(packet, review_template(packet))
    assert "old opinion" not in page
    assert "private-project" not in page
    assert "default-src 'none'" in page
    assert "connect-src 'none'" in page
    assert "review-template" not in page
    assert "review_started_at" in page
    assert "exportSubmission" in page and "importSubmission" in page
    assert "fetch(" not in page and "XMLHttpRequest" not in page
    assert "<script>" in page and "</script>" in page


def test_render_escapes_script_sensitive_source_text():
    row = make_record()
    row["candidate_source"] = [ref(4, "    value = '</script><script>alert(1)</script>'")]
    packet, _ = build_review_pack([row])
    page = render(packet, review_template(packet))
    assert "</script><script>alert(1)</script>" not in page
    assert "\\u003c/script\\u003e" in page


def test_renderer_rejects_packet_template_mismatch():
    packet, _ = build_review_pack([make_record()])
    template = review_template(packet)
    template["packet_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash mismatch"):
        render(packet, template)


def test_packet_builder_writes_separate_mapping_and_blank_form(tmp_path):
    records = tmp_path / "records"
    records.mkdir()
    (records / "case-001.json").write_text(json.dumps(make_record()), encoding="utf-8")
    public = tmp_path / "public"
    private = tmp_path / "private" / "mapping.json"
    assert packet_builder.main([str(records), "--out", str(public), "--mapping-out", str(private)]) == 0
    packet = json.loads((public / "packet.json").read_text(encoding="utf-8"))
    mapping = json.loads(private.read_text(encoding="utf-8"))
    form = json.loads((public / "review-template.json").read_text(encoding="utf-8"))
    assert packet["packet_sha256"] == mapping["packet_sha256"]
    assert form["reviews"][0]["result"] == ""
    assert (public / "review.html").is_file()
    assert not (public / "mapping.json").exists()


@pytest.mark.parametrize("conflict", ["existing_packet", "existing_mapping", "nested_mapping"])
def test_packet_builder_rejects_unsafe_destinations_without_writing(tmp_path, conflict):
    records = tmp_path / "records"
    records.mkdir()
    (records / "case-001.json").write_text(json.dumps(make_record()), encoding="utf-8")
    public = tmp_path / "public"
    private = tmp_path / "private-mapping.json"
    if conflict == "existing_packet":
        public.mkdir()
        (public / "review-template.json").write_text("saved reviewer material", encoding="utf-8")
    elif conflict == "existing_mapping":
        private.write_text("saved private mapping", encoding="utf-8")
    else:
        private = public / "private" / "mapping.json"
    before = {str(path.relative_to(tmp_path)): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert packet_builder.main([str(records), "--out", str(public), "--mapping-out", str(private)]) == 2
    after = {str(path.relative_to(tmp_path)): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert before == after


def test_packet_builder_validates_rendering_before_creating_output(tmp_path, monkeypatch):
    records = tmp_path / "records"
    records.mkdir()
    (records / "case-001.json").write_text(json.dumps(make_record()), encoding="utf-8")
    public = tmp_path / "public"
    private = tmp_path / "private-mapping.json"

    def fail_render(*_):
        raise ValueError("render validation failed")

    monkeypatch.setattr(packet_builder, "render_review_page", fail_render)
    assert packet_builder.main([str(records), "--out", str(public), "--mapping-out", str(private)]) == 2
    assert not public.exists()
    assert not private.exists()
