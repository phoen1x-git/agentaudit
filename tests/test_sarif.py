"""The SARIF export is structurally valid, and it does not leak the machine it ran on.

SARIF is read by tools that will not see any of this project's caveats, so the format has to
carry the honesty on its own: every result is a `warning`, the verdict travels in
`properties`, and no absolute path is emitted.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ast_scan  # noqa: E402
import to_sarif  # noqa: E402

DRIVE = re.compile(r"(^|[^A-Za-z0-9])([A-Za-z]:[\\/]|/(home|Users)/)")


@pytest.fixture(scope="module")
def doc(tmp_path_factory):
    findings = ast_scan.scan_dir(ROOT / "demo", "demo-agent")
    rd = ast_scan.write_round(tmp_path_factory.mktemp("out"), "sarif", findings,
                              meta_extra={"scanner": "ast-only", "project": "demo-agent"})
    rows = to_sarif._rows(rd, include_all=False)
    return to_sarif.build(rd, rows, "demo-agent")


def test_shape_matches_sarif_2_1_0(doc):
    assert doc["version"] == "2.1.0"
    assert "sarif-2.1.0" in doc["$schema"]
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "agentaudit"
    assert driver["version"]
    assert isinstance(driver["rules"], list) and driver["rules"]
    assert isinstance(run["results"], list)


def test_every_result_points_at_a_declared_rule(doc):
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = {r["id"] for r in rules}
    for res in doc["runs"][0]["results"]:
        assert res["ruleId"] in ids
        assert 0 <= res["ruleIndex"] < len(rules)
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


def test_rule_ids_are_unique(doc):
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


def test_results_have_a_location_and_a_message(doc):
    for res in doc["runs"][0]["results"]:
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] > 0
        assert res["message"]["text"].strip()
        assert res["partialFingerprints"]["agentauditFingerprint"]


def test_every_level_is_warning(doc):
    """A candidate is not a confirmed vulnerability; SARIF levels are consumed by tools."""
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels <= {"warning"}, levels


def test_the_message_does_not_claim_confirmation(doc):
    """The honest wording negates the claim ("not a confirmed vulnerability"), which is fine."""
    for res in doc["runs"][0]["results"]:
        text = res["message"]["text"].lower()
        for claim in ("we confirmed", "is confirmed", "has been confirmed", "proven",
                      "verified exploit"):
            assert claim not in text, f"a SARIF message claims {claim!r}"
        assert "candidate" in text
        if "confirmed" in text:
            assert "not a confirmed" in text, "`confirmed` is used without being negated"


def test_no_absolute_paths_are_emitted(doc):
    blob = json.dumps(doc)
    assert not DRIVE.search(blob), "the SARIF contains an absolute path"
    for res in doc["runs"][0]["results"]:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/") and ":" not in uri
        assert "\\" not in uri


def test_triage_state_travels_in_properties(doc):
    for res in doc["runs"][0]["results"]:
        assert res["properties"]["agentaudit/verdict"]


def test_rows_triaged_not_vuln_are_left_out(tmp_path):
    rows = [
        {"rule": "ast/dangerous-call", "file": "a.py", "line": 1, "sink": "eval",
         "ai_verdict": "not_vuln", "fingerprint": "f1"},
        {"rule": "ast/dangerous-call", "file": "b.py", "line": 2, "sink": "eval",
         "ai_verdict": "vuln", "fingerprint": "f2"},
    ]
    rd = tmp_path / "round-x"
    rd.mkdir()
    (rd / "findings.json").write_text(json.dumps({"f1": rows[0], "f2": rows[1]}), encoding="utf-8")

    assert len(to_sarif.build(rd, to_sarif._rows(rd, include_all=False), "")["runs"][0]["results"]) == 1
    assert len(to_sarif.build(rd, to_sarif._rows(rd, include_all=True), "")["runs"][0]["results"]) == 2
