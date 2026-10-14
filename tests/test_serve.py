"""The local viewer serves one directory, on localhost, and nothing else.

`--serve` exposes a directory over HTTP, so the boundaries matter: it must not bind to a
routable interface, must not walk out of the directory, and must not list directories.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVE = ROOT / "app" / "serve.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(port: int, path: str) -> tuple[str, bytes]:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    status = data.split(b"\r\n", 1)[0].decode(errors="replace")
    return status, data


@pytest.fixture
def served(tmp_path):
    round_dir = tmp_path / "round-x"
    (round_dir / "sub").mkdir(parents=True)
    (round_dir / "index.html").write_text("<html><body><table>hi</table></body></html>",
                                          encoding="utf-8")
    (round_dir / "findings.tsv").write_text("a\tb\n", encoding="utf-8")
    (round_dir / "sub" / "page.html").write_text("<html>sub</html>", encoding="utf-8")

    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(SERVE), str(round_dir),
                             "--port", str(port), "--no-browser"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            cwd=str(ROOT))
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            _get(port, "/index.html")
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail("the server never came up")
    try:
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_serves_the_index(served):
    status, body = _get(served, "/index.html")
    assert "200" in status, status
    assert b"<table" in body


def test_serves_other_files_in_the_same_directory(served):
    status, body = _get(served, "/findings.tsv")
    assert "200" in status, status
    assert b"a\tb" in body


def test_does_not_escape_the_directory(served):
    for path in ("/../pyproject.toml", "/../../etc/passwd", "/sub/../../pyproject.toml"):
        status, body = _get(served, path)
        assert "200" not in status, f"{path} was served: {status}"
        assert b"[project]" not in body


def test_directory_listings_are_refused(served):
    status, body = _get(served, "/sub/")
    assert "200" not in status, status
    assert b"page.html" not in body, "a directory listing was returned"


def test_binds_to_localhost_only():
    """The bind address is a constant, and it is checked here so a change is deliberate."""
    src = SERVE.read_text(encoding="utf-8")
    assert '("127.0.0.1", port)' in src
    assert "0.0.0.0" not in src
