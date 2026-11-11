"""Per-operation request limits, including client retries and unknown-cost failures.

Currency limits use the local price table and conservative byte-based reservations.
They are an accounting bound, not a provider billing guarantee.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import math

_CURRENT = ContextVar("audit_request_budget", default=None)


class RequestBudgetExceeded(RuntimeError):
    def __init__(self, reason, attempts=None):
        super().__init__(reason)
        self.attempts = attempts or []


def usage_cost(response, prices):
    usage = response.get("usage") or {}
    hits = usage.get("prompt_cache_hit_tokens") or 0
    total = usage.get("prompt_tokens", 0)
    misses = usage.get("prompt_cache_miss_tokens", max(0, total - hits))
    output = usage.get("completion_tokens", 0)
    for value in (hits, total, misses, output):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid token usage")
    return misses * prices["input_miss"] + hits * prices["input_hit"] + output * prices["output"]


@dataclass
class RequestBudget:
    max_calls: int = 12
    max_cny: float = 1.0
    max_tokens_per_call: int = 12000
    attempts: int = 0
    accounted_cny: float = 0.0
    known_cny: float = 0.0
    unknown_cost_attempts: int = 0
    stopped: str = ""
    _open: dict = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        for name in ("max_calls", "max_tokens_per_call"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.max_cny, bool) or not math.isfinite(self.max_cny) or self.max_cny <= 0:
            raise ValueError("max_cny must be finite and positive")

    def __enter__(self):
        if _CURRENT.get() is not None:
            raise ValueError("nested request budgets are not supported")
        self._token = _CURRENT.set(self)
        return self

    def __exit__(self, *args):
        _CURRENT.reset(self._token)

    def reserve(self, payload, prices):
        reason = ""
        tokens = payload["max_tokens"]
        input_bytes = len(json.dumps(payload["messages"], ensure_ascii=False).encode("utf-8"))
        reserve = (input_bytes + 1024) * prices["input_miss"] + tokens * prices["output"]
        if self.attempts >= self.max_calls:
            reason = "model request-count budget exhausted (retries included)"
        elif tokens > self.max_tokens_per_call:
            reason = "model per-request token budget exceeded"
        elif self.accounted_cny + reserve > self.max_cny:
            reason = "model estimated-cost budget exhausted (next request reserved before dispatch)"
        if reason:
            self.stopped = reason
            raise RequestBudgetExceeded(reason)
        self.attempts += 1
        self.accounted_cny += reserve
        self._open[self.attempts] = reserve
        return self.attempts

    def finish(self, ticket, response, prices):
        reservation = self._open.get(ticket)
        if reservation is None:
            return
        if not response.get("usage"):
            self.finish_unknown(ticket)
            return
        try:
            cost = usage_cost(response, prices)
        except (ValueError, TypeError):
            self.finish_unknown(ticket)
            return
        self._open.pop(ticket)
        self.accounted_cny += cost - reservation
        self.known_cny += cost

    def finish_unknown(self, ticket):
        if ticket in self._open:
            self._open.pop(ticket)
            # Retain the full reservation when billing information is unavailable.
            self.unknown_cost_attempts += 1

    def summary(self):
        return {"max_calls": self.max_calls, "max_cny": self.max_cny,
                "max_tokens_per_call": self.max_tokens_per_call, "network_attempts": self.attempts,
                "accounted_cny": round(self.accounted_cny, 8), "known_cny": round(self.known_cny, 8),
                "unknown_cost_attempts": self.unknown_cost_attempts, "stop_reason": self.stopped,
                "cost_basis": "local estimated prices; byte-based pre-dispatch reservation; not provider billing"}


def current_budget():
    return _CURRENT.get()
