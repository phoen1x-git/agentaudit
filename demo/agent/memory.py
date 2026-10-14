"""A cross-turn memory store.

Deliberately vulnerable sample code for the scanner demo. Do not deploy.
"""
from __future__ import annotations

_MEMORY: dict[str, str] = {}


def remember(key: str, value: str) -> None:
    """Store a value that a later turn may read back."""
    _MEMORY[key] = value


def recall(key: str) -> str:
    """Read a previously stored value."""
    return _MEMORY.get(key, "")


def recall_all() -> dict:
    return dict(_MEMORY)
