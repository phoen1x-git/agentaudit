"""A tiny agent service.

Deliberately vulnerable sample code for the scanner demo. Do not deploy.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI

from .auth import require_user
from .tools import fetch_url, run_shell, search_docs

app = FastAPI(title="demo-agent")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/run")
def run_command(cmd: str):
    """Run a shell command. No auth, no whitelist, no sandbox."""
    return {"output": run_shell(cmd)}


@app.get("/docs/search")
def search(q: str, user=Depends(require_user)):
    """Search the local documentation. Requires a signed-in user."""
    return {"results": search_docs(q)}


@app.post("/fetch")
def fetch(url: str, user=Depends(require_user)):
    """Fetch a URL on the user's behalf."""
    return {"body": fetch_url(url)}
