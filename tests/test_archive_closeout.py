from __future__ import annotations

import json
from pathlib import Path
import sys
import zipfile
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.archive_closeout import make_archive, verify_archive  # noqa: E402


def test_archive_manifest_verifies_selected_repository_and_ignored_files(tmp_path):
    token = uuid.uuid4().hex
    scratch = ROOT / "out" / f"archive-closeout-test-{token}"
    ignored = scratch / "sample.txt"
    ignored.parent.mkdir(parents=True, exist_ok=True)
    ignored.write_text("private experiment", encoding="utf-8")
    archive = scratch / "snapshot.zip"
    manifest_path = scratch / "manifest.json"

    try:
        manifest = make_archive(archive, manifest_path, [scratch.relative_to(ROOT).as_posix()])
        assert "tools/archive_closeout.py" in {row["path"] for row in manifest["files"]}
        assert f"out/archive-closeout-test-{token}/sample.txt" in {row["path"] for row in manifest["files"]}
        assert verify_archive(archive, json.loads(manifest_path.read_text(encoding="utf-8")))["status"] == "verified"
    finally:
        for path in scratch.iterdir():
            path.unlink(missing_ok=True)
        scratch.rmdir()


def test_archive_verifier_rejects_tampered_entries(tmp_path):
    archive = ROOT / "out" / f"archive-tamper-{uuid.uuid4().hex}.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"file_count": 1, "archive_sha256": "invalid", "files": [
        {"path": "src/file.py", "size": 3, "sha256": "0" * 64},
    ]}
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("src/file.py", b"bad")
    try:
        with pytest.raises(ValueError, match="hash mismatch"):
            verify_archive(archive, manifest)
    finally:
        archive.unlink(missing_ok=True)


def test_archive_refuses_overwrite_and_paths_outside_repository(tmp_path):
    archive = ROOT / "out" / f"archive-existing-{uuid.uuid4().hex}.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"saved")
    try:
        with pytest.raises(ValueError, match="refusing to overwrite"):
            make_archive(archive, ROOT / "out/manifest.json", [])
        outside = tmp_path / "external"
        outside.mkdir()
        with pytest.raises(ValueError, match="outside the repository"):
            make_archive(ROOT / "out/other.zip", ROOT / "out/other.json", [str(outside)])
    finally:
        archive.unlink(missing_ok=True)
