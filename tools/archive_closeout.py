"""Create and verify a local, hash-manifested closeout archive."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {
    ".git", ".pytest_cache", ".workbuddy", "__pycache__", ".venv", "venv",
    "node_modules", "data", "logs", "_targets", "build", "dist",
}
SKIP_NAMES = {"node_modules"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".db", ".key", ".token"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _included(path: Path, *, allow_out: bool = False) -> bool:
    rel = path.relative_to(ROOT)
    skipped = SKIP_PARTS - ({"out"} if allow_out else set())
    if any(part in skipped or part in SKIP_NAMES for part in rel.parts):
        return False
    return path.is_file() and path.suffix.lower() not in SKIP_SUFFIXES


def collect_files(extra_paths: list[str]) -> list[Path]:
    paths = {path for path in ROOT.rglob("*") if _included(path)}
    for value in extra_paths:
        target = (ROOT / value).resolve()
        try:
            target.relative_to(ROOT.resolve())
        except ValueError as exc:
            raise ValueError(f"archive input is outside the repository: {value}") from exc
        if not target.exists():
            raise ValueError(f"archive input does not exist: {value}")
        if target.is_file():
            paths.add(target)
        else:
            paths.update(path for path in target.rglob("*") if _included(path, allow_out=True))
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def make_archive(archive: Path, manifest_path: Path, extra_paths: list[str]) -> dict:
    archive = archive.resolve()
    manifest_path = manifest_path.resolve()
    for destination in (archive, manifest_path):
        try:
            destination.relative_to(ROOT.resolve())
        except ValueError as exc:
            raise ValueError("archive and manifest must stay inside the repository") from exc
        if destination.exists():
            raise ValueError(f"refusing to overwrite existing output: {destination}")
    files = collect_files(extra_paths)
    if not files:
        raise ValueError("no files selected")
    rows = []
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in files:
            raw = path.read_bytes()
            rel = path.relative_to(ROOT).as_posix()
            bundle.writestr(rel, raw)
            rows.append({"path": rel, "size": len(raw), "sha256": sha256(raw)})
    payload = {
        "schema": "agentaudit-closeout-archive-v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "archive": archive.relative_to(ROOT).as_posix(),
        "archive_sha256": sha256(archive.read_bytes()),
        "file_count": len(rows),
        "files": rows,
        "excluded": sorted(SKIP_PARTS | SKIP_NAMES | {".git history", "full external target repositories", "CodeQL databases"}),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    verify_archive(archive, payload)
    return payload


def verify_archive(archive: Path, manifest: dict) -> dict:
    expected = {row["path"]: row for row in manifest["files"]}
    if len(expected) != manifest.get("file_count"):
        raise ValueError("manifest contains duplicate or missing file entries")
    with zipfile.ZipFile(archive, "r") as bundle:
        actual_names = set(bundle.namelist())
        if actual_names != set(expected):
            raise ValueError("archive entries do not match manifest")
        for name, row in expected.items():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe archive path: {name}")
            raw = bundle.read(name)
            if len(raw) != row["size"] or sha256(raw) != row["sha256"]:
                raise ValueError(f"archive file hash mismatch: {name}")
    archive_hash = sha256(archive.read_bytes())
    if archive_hash != manifest.get("archive_sha256"):
        raise ValueError("archive hash mismatch")
    return {"file_count": len(expected), "archive_sha256": archive_hash, "status": "verified"}


def _git_status(executable: str | None = None) -> str:
    git = executable or shutil.which("git")
    if not git:
        return "unavailable"
    try:
        result = subprocess.run([git, "status", "--short"], cwd=ROOT, capture_output=True, text=True, check=True)
        return result.stdout
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--archive", type=Path, required=True)
    create.add_argument("--manifest", type=Path, required=True)
    create.add_argument("--include", action="append", default=[], help="additional ignored output path, relative to repository")
    create.add_argument("--verification", type=Path, help="write an environment and git status record")
    create.add_argument("--git-executable", help="git executable to record repository status")
    verify = sub.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = make_archive(ROOT / args.archive, ROOT / args.manifest, args.include)
            if args.verification:
                import platform
                record = {"archive_verification": {key: value for key, value in result.items() if key != "files"},
                          "git_status_porcelain": _git_status(args.git_executable), "python": sys.version,
                          "platform": platform.platform(), "created_at_utc": result["created_at_utc"]}
                target = ROOT / args.verification
                if target.exists():
                    raise ValueError(f"refusing to overwrite verification record: {target}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"verified {result['file_count']} files; archive sha256 {result['archive_sha256']}")
            return 0
        manifest = json.loads((ROOT / args.manifest).read_text(encoding="utf-8"))
        result = verify_archive(ROOT / args.archive, manifest)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"archive_closeout: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
