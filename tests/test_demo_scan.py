"""Scanning the bundled sample project produces the candidates it is designed to trip.

This is the end-to-end test: it runs the same code path as `app/scan.py --demo`, so a
change that breaks the offline scanner fails here.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ast_scan  # noqa: E402

DEMO = ROOT / "demo"

# Checks the sample project is built to trip. If one of these stops firing, either the
# sample changed or a check regressed -- both worth failing over.
EXPECTED_RULES = {
    "ast/dangerous-call",
    "ast/injection-surface",
    "ast/input-to-sink",
    "ast/unauth-endpoint",
    "ast/inconsistent-auth",
    "ast/arg-source-unknown",
    "ast/duality",
}


@pytest.fixture(scope="module")
def findings():
    assert DEMO.is_dir(), "the bundled demo project is missing"
    return ast_scan.scan_dir(DEMO, "demo-agent")


def test_demo_directory_exists():
    assert (DEMO / "README.md").exists()
    assert (DEMO / "agent").is_dir()


def test_finds_the_expected_rule_set(findings):
    found = {f.rule for f in findings}
    missing = EXPECTED_RULES - found
    assert not missing, f"these checks no longer fire on the demo project: {sorted(missing)}"


def test_finds_a_useful_number_of_candidates(findings):
    assert len(findings) >= 8, f"only {len(findings)} candidates on the demo project"


def test_every_candidate_carries_the_evidence_it_claims(findings):
    for f in findings:
        assert f.fingerprint, f"no fingerprint for {f.rule} at {f.sink_uri}:{f.sink_line}"
        assert f.project == "demo-agent"
        assert f.sink_uri.endswith(".py"), f"odd path in {f.sink_uri!r}"
        assert f.sink_line > 0, f"no line for {f.fingerprint}"
        assert f.snippet.strip(), f"no source line for {f.fingerprint}"
        assert f.rule.startswith("ast/"), f"unexpected rule id {f.rule!r}"


def test_candidates_are_deduplicated(findings):
    fps = [f.fingerprint for f in findings]
    assert len(fps) == len(set(fps)), "two candidates share a fingerprint"


def test_fingerprints_do_not_depend_on_the_absolute_path(findings):
    # The same tree scanned from a relative and an absolute path must give the same identity,
    # otherwise two rounds can never be compared.
    from_abs = ast_scan.scan_dir(DEMO.resolve(), "demo-agent")
    assert {f.fingerprint for f in findings} == {f.fingerprint for f in from_abs}


def test_offline_scan_writes_a_readable_round(tmp_path, findings):
    rd = ast_scan.write_round(tmp_path, "unit", findings,
                              meta_extra={"scanner": "ast-only", "source_root": str(DEMO)})
    for name in ("findings.tsv", "findings.json", "verdicts.json", "meta.json"):
        assert (rd / name).exists(), f"{name} was not written"
    head = (rd / "findings.tsv").read_text(encoding="utf-8-sig").splitlines()[0]
    assert head.split("\t")[:4] == ["fingerprint", "project", "rule", "sink"]
