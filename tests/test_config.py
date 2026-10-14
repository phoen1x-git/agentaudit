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


def test_validator_rejects_an_unknown_field(tmp_path):
    """The quiet failure mode: a misspelled field name means the entry matches nothing."""
    broken = (CFG / "sinks.yml").read_text(encoding="utf-8")
    broken += "\n  - {id: typo, source: extra, cls: direct, objectname: os, func: system}\n"
    assert _run_validator_on(broken).returncode == 1


def test_validator_rejects_a_duplicate_id():
    broken = (CFG / "sinks.yml").read_text(encoding="utf-8")
    broken += ("\n  - {id: dupe, source: extra, cls: direct, name: eval}\n"
               "  - {id: dupe, source: extra, cls: direct, name: exec}\n")
    assert _run_validator_on(broken).returncode == 1


def test_validator_rejects_an_entry_without_a_matcher():
    broken = (CFG / "sinks.yml").read_text(encoding="utf-8")
    broken += "\n  - {id: nomatcher, source: extra, cls: direct}\n"
    p = _run_validator_on(broken)
    assert p.returncode == 1
    assert "no matcher" in p.stdout


def _run_validator_on(config_text: str) -> subprocess.CompletedProcess:
    """Run the validator inside a scratch tree whose sinks.yml is `config_text`.

    The scratch tree keeps the real layout (`tools/validate_config.py`, `core/config/*.yml`)
    because the validator resolves its paths relative to itself.
    """
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "core" / "config").mkdir(parents=True)
        (root / "tools").mkdir()
        for f in CFG.glob("*.yml"):
            (root / "core" / "config" / f.name).write_text(f.read_text(encoding="utf-8"),
                                                           encoding="utf-8")
        (root / "core" / "config" / "sinks.yml").write_text(config_text, encoding="utf-8")
        (root / "tools" / "validate_config.py").write_text(VALIDATOR.read_text(encoding="utf-8"),
                                                           encoding="utf-8")
        return subprocess.run([sys.executable, str(root / "tools" / "validate_config.py")],
                              capture_output=True, text=True, cwd=str(root),
                              env=dict(os.environ, PYTHONIOENCODING="utf-8"))
