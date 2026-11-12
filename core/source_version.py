"""Content versions for the Python source inputs of a local CodeQL database."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .triage_contract import digest


def python_tree(root: Path) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise OSError("Python source root is not a directory")
    files = []
    symlink_dirs = []
    for directory, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "__pycache__"})
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink():
                symlink_dirs.append(path.relative_to(root).as_posix())
        for name in sorted(names):
            if name.endswith(".py"):
                path = Path(directory) / name
                files.append({"path": path.relative_to(root).as_posix(),
                              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {"scope": "python-files-v1", "root": str(root), "sha256": digest(files),
            "files": files, "symlink_dirs_not_followed": symlink_dirs}


def database_status(db: Path, root: str) -> dict:
    marker = db / "agentaudit-source.json"
    if not marker.exists():
        return {"backend": "codeql", "source_version_status": "unverified",
                "reason": "database has no source-version marker"}
    try:
        stored = json.loads(marker.read_text(encoding="utf-8"))["source"]
        if not isinstance(stored, dict) or stored.get("scope") != "python-files-v1":
            raise ValueError("invalid source-version marker")
        current = python_tree(Path(root)) if root else None
        matched = current == stored and not stored.get("symlink_dirs_not_followed")
        return {"backend": "codeql", "source_version_status": "matched" if matched else "mismatch",
                "source_tree_sha256": stored["sha256"],
                "observed_tree_sha256": current["sha256"] if current else None}
    except (OSError, ValueError, KeyError, TypeError):
        return {"backend": "codeql", "source_version_status": "unverified",
                "reason": "database source version could not be checked"}
