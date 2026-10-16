"""The rule configuration is valid, and the validator actually rejects broken input.

A typo in `core/config/sinks.yml` fails silently at run time: the generator ignores the
entry and the check quietly stops covering that function. These tests exist so that a broken
config fails loudly in CI instead.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = ROOT / "core" / "config"
VALIDATOR = ROOT / "tools" / "validate_config.py"

MATCHERS = ("obj", "obj2", "obj_suffix", "name", "func")


@pytest.fixture(scope="module")
def sinks():
    return (yaml.safe_load((CFG / "sinks.yml").read_text(encoding="utf-8")) or {}).get("sinks") or []


def test_validator_passes_on_the_shipped_config():
    p = subprocess.run([sys.executable, str(VALIDATOR)], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "config ok" in p.stdout


def test_shipped_config_is_not_empty(sinks):
    assert len(sinks) >= 20, "the sink list looks truncated"


def test_every_sink_has_a_matcher(sinks):
    for s in sinks:
        assert any(s.get(k) for k in MATCHERS), f"{s.get('id')!r} can never match anything"


def test_every_sink_declares_its_source_and_class(sinks):
    for s in sinks:
        assert s.get("source") in ("paper", "extra"), f"{s.get('id')!r} has a bad `source`"
        assert s.get("cls") in ("direct", "structural"), f"{s.get('id')!r} has a bad `cls`"


def test_sink_ids_are_unique(sinks):
    ids = [s.get("id") for s in sinks]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate sink ids: {sorted(dupes)}"


def test_groups_are_known(sinks):
    allowed = {"fs", "path", "http", "dynimp"}
    seen = {s.get("group") for s in sinks if s.get("group")}
    assert seen <= allowed, f"unknown sink group(s): {sorted(seen - allowed)}"


def test_validator_rejects_an_unknown_field(tmp_path, monkeypatch):
    """The quiet failure mode: a misspelled field name means the entry matches nothing."""
    _, errs = _problems_for(_sinks() + _entry("objectname: os, func: system", "typo"),
                            tmp_path, monkeypatch)
    assert any("unknown field" in e for e in errs), errs


def test_validator_rejects_a_duplicate_id(tmp_path, monkeypatch):
    _, errs = _problems_for(
        _sinks() + _entry("name: eval") + _entry("name: exec"), tmp_path, monkeypatch)
    assert any("duplicate id" in e for e in errs), errs


def test_validator_rejects_an_entry_without_a_matcher(tmp_path, monkeypatch):
    _, errs = _problems_for(_sinks() + _entry(""), tmp_path, monkeypatch)
    assert any("no matcher" in e for e in errs), errs


def test_validator_rejects_a_bad_source_and_class(tmp_path, monkeypatch):
    _, errs = _problems_for(_sinks() + _entry("name: eval, source: elsewhere, cls: whatever"),
                            tmp_path, monkeypatch)
    assert any("`source` must be" in e for e in errs), errs
    assert any("`cls` must be" in e for e in errs), errs


def _sinks() -> str:
    return (CFG / "sinks.yml").read_text(encoding="utf-8")


def _entry(fields: str, sid: str = "broken") -> str:
    return f"\n  - {{id: {sid}, {fields}}}\n" if fields else f"\n  - {{id: {sid}}}\n"


def _problems_for(config_text: str, tmp_path, monkeypatch):
    """Run the validator's checks against a scratch config, in the same process.

    Each defect has to be *detected*; that does not need a second interpreter, and starting one
    costs seconds on Windows. The CLI end of it is covered by the pass test above.
    """
    import tools.validate_config as V

    root = tmp_path / "cfgroot" / "core" / "config"
    root.mkdir(parents=True)
    for f in CFG.glob("*.yml"):
        (root / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "sinks.yml").write_text(config_text, encoding="utf-8")

    monkeypatch.setattr(V, "CFG", root)
    monkeypatch.setattr(V, "ERR", [])
    monkeypatch.setattr(V, "WARN", [])
    sinks = V.check_sinks()
    V.check_sources()
    return sinks, list(V.ERR)
