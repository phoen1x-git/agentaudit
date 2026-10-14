#!/usr/bin/env python
"""Serve a round directory on localhost so you can read it in a browser.

    python app/serve.py out/round-my-round
    python app/serve.py out/round-my-round --port 8000 --no-browser

This is the middle ground between "open the HTML file" and "build a desktop app": it starts a
plain static file server over one directory and prints the URL. There is no upload, no
telemetry and no external request -- the page is the same `index.html` you already have.

Safety notes, because this serves a directory:

* it binds to **127.0.0.1 only**, never to a routable interface;
* it serves **one directory**, the round you name, and refuses anything outside it;
* directory listings are off, so only the files in that round are reachable.

If a round has no `index.html`, it is generated first.
"""
from __future__ import annotations

import argparse
import functools
import http.server
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Static files from one directory, with a few things switched off."""

    def list_directory(self, path):  # noqa: D102 - inherited
        self.send_error(403, "directory listing is disabled")
        return None

    def log_message(self, fmt, *args):  # keep the console readable
        pass


def _free_port(preferred: int) -> int:
    if preferred:
        return preferred
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ensure_index(rd: Path) -> None:
    if (rd / "index.html").exists():
        return
    if not (rd / "findings.tsv").exists():
        raise SystemExit(f"{rd} has no findings.tsv; run a scan first")
    print("[serve] no index.html yet; generating it")
    subprocess.run([sys.executable, str(ROOT / "app" / "make_index.py"), str(rd)], check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="serve a round directory on localhost")
    ap.add_argument("round_dir", help="a round directory, e.g. out/round-my-round")
    ap.add_argument("--port", type=int, default=0, help="port (default: pick a free one)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    a = ap.parse_args()

    rd = Path(a.round_dir).resolve()
    if not rd.is_dir():
        raise SystemExit(f"not a directory: {rd}")
    ensure_index(rd)

    port = _free_port(a.port)
    handler = functools.partial(_Handler, directory=str(rd))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}/index.html"

    print(f"[serve] {rd}")
    print(f"[serve] {url}")
    print("[serve] localhost only; Ctrl-C to stop")

    if not a.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve] stopped")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
