"""Path handling helpers.

Deliberately vulnerable sample code for the scanner demo. Do not deploy.
"""
from __future__ import annotations

import os

DOCS_ROOT = "/srv/demo/docs"


def load_document(name: str) -> str:
    """Load a document by name.

    The same function builds the path safely and unsafely, side by side. The unsafe one
    is the line that matters.
    """
    constraining = os.path.join(DOCS_ROOT, os.path.basename(name))
    unchecked = os.path.join(DOCS_ROOT, name)
    with open(constraining, encoding="utf-8") as fh:
        header = fh.read()
    with open(unchecked, encoding="utf-8") as fh:
        body = fh.read()
    return header + body
