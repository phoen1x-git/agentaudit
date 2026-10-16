"""Kernel package: CodeQL static frontend, triage, and persistence."""

from __future__ import annotations

import os
from pathlib import Path

__version__ = "0.4.0"



def workspace() -> Path:
    """Where a scan writes its output: `AGENTAUDIT_HOME`, or the current directory.

    Output (`out/`, `data/`, `_targets/`) belongs to whoever is running the scan, not to the
    installation, so an installed copy never writes into site-packages. Run from a checkout
    and the workspace is the checkout, which is what the documentation assumes.
    """
    env = os.environ.get("AGENTAUDIT_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return Path.cwd().resolve()
