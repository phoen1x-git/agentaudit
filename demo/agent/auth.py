"""Account handling for the demo service."""
from __future__ import annotations

BEARER_PREFIX = "Bearer "

_SESSIONS: dict[str, str] = {}


def require_user(token: str = "demo-token") -> str:
    """Resolve a session token to a user id."""
    if not token.startswith(BEARER_PREFIX):
        raise ValueError("malformed token")
    return _SESSIONS.get(token, "")
