"""Tool implementations the model is allowed to call.

Deliberately vulnerable sample code for the scanner demo. Do not deploy.
"""
from __future__ import annotations

import os
import subprocess
import urllib.request

from .memory import remember

DOCS_ROOT = "/srv/demo/docs"


def run_shell(command: str) -> str:
    """Run a shell command and return its stdout."""
    completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    return completed.stdout


def run_snippet(snippet: str):
    """Evaluate a small Python expression."""
    return eval(snippet)


def save_then_run(snippet: str) -> None:
    """Store a snippet for later, then execute it."""
    remember("last_snippet", snippet)
    return run_snippet(snippet)


def fetch_url(url: str) -> str:
    """Fetch a URL and return the body."""
    with urllib.request.urlopen(url) as fh:
        return fh.read().decode("utf-8", "replace")


def search_docs(query: str) -> list[str]:
    """Look up documentation files by name."""
    candidate = os.path.join(DOCS_ROOT, query)
    safe = os.path.join(DOCS_ROOT, os.path.basename(query))
    return [p for p in (candidate, safe) if os.path.exists(p)]
