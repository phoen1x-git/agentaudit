"""The report and the HTML index render, and they never overstate what was done.

The whole point of the report template is that it cannot claim more than the scan did.
These tests check that promise holds, including for a round where no triage ran.
"""
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ast_scan  # noqa: E402

# Words that would turn a candidate into a claim. The report is allowed to say what was NOT
# done ("not verified by execution"); it is not allowed to assert the opposite.
FORBIDDEN_CLAIMS = ("human-verified", "human verified", "we confirmed",
                    "confirmed vulnerability", "proven exploitable",
                    "verified vulnerable", "exploitability verified")


@pytest.fixture(scope="module")
def round_dir(tmp_path_factory):
    findings = ast_scan.scan_dir(ROOT / "demo", "demo-agent")
    out = tmp_path_factory.mktemp("out")
    return ast_scan.write_round(out, "unit", findings,
                                meta_extra={"scanner": "ast-only",
                                            "source_root": str(ROOT / "demo")})


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "app" / script), *args],
                          capture_output=True, text=True, cwd=str(ROOT))


def test_report_renders(round_dir):
    p = _run("make_report.py", str(round_dir), "--select", "all")
    assert p.returncode == 0, p.stdout + p.stderr
    assert (round_dir / "report_draft.md").exists()


def test_report_never_claims_verification(round_dir):
    text = (round_dir / "report_draft.md").read_text(encoding="utf-8").lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in text, f"the report claims {claim!r}"
    assert "not verified by execution" in text
    assert "candidate" in text


def test_untriaged_round_says_so_instead_of_showing_confidence(round_dir):
    _run("make_report.py", str(round_dir), "--select", "all")
    text = (round_dir / "report_draft.md").read_text(encoding="utf-8")
    assert "no LLM triage was run" in text
    assert "not triaged" in text
    # No fabricated confidence: an untriaged row must not print a number.
    assert "0.0 |" not in text


def test_vuln_selection_is_empty_without_triage(round_dir):
    _run("make_report.py", str(round_dir), "--select", "vuln")
    text = (round_dir / "report_draft.md").read_text(encoding="utf-8")
    assert "triaged `vuln` **0**" in text


def test_report_lists_every_candidate_in_the_table(round_dir):
    _run("make_report.py", str(round_dir), "--select", "all")
    rows = list(csv.DictReader(open(round_dir / "findings.tsv", encoding="utf-8-sig"),
                               delimiter="\t"))
    text = (round_dir / "report_draft.md").read_text(encoding="utf-8")
    assert text.count("| `ast/") == len(rows)


def test_report_language_switch(round_dir):
    p = _run("make_report.py", str(round_dir), "--select", "all", "--lang", "zh")
    assert p.returncode == 0, p.stdout + p.stderr
    text = (round_dir / "report_draft.md").read_text(encoding="utf-8")
    assert "未经实跑验证" in text


def test_index_renders_and_declares_its_language(round_dir):
    assert _run("make_index.py", str(round_dir), "--lang", "en").returncode == 0
    html = (round_dir / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in html
    assert "<table" in html

    assert _run("make_index.py", str(round_dir), "--lang", "zh").returncode == 0
    html = (round_dir / "index.html").read_text(encoding="utf-8")
    assert '<html lang="zh-CN">' in html


def test_explain_works_from_the_table_alone(round_dir, tmp_path):
    """`--explain` must still work when only findings.tsv is present."""
    bare = tmp_path / "bare"
    bare.mkdir()
    for name in ("findings.tsv", "meta.json"):
        (bare / name).write_bytes((round_dir / name).read_bytes())
    p = _run("explain.py", str(bare), "--index", "1")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "this check" in p.stdout
    assert "surrounding source" in p.stdout
