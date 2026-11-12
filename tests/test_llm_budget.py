"""Request limits are enforced below all transport, JSON and judge retries."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import urllib.error

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import llm_judge as LJ  # noqa: E402
from core.llm_budget import RequestBudget, RequestBudgetExceeded, current_budget, usage_cost  # noqa: E402

LC = LJ.LC


@pytest.fixture
def transport(tmp_path, monkeypatch):
    monkeypatch.setattr(LC, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(LC, "LOG_PATH", str(tmp_path / "usage.jsonl"))
    monkeypatch.setattr(LC, "read_key", lambda: "test-key")
    monkeypatch.setattr(LC, "USAGE", LC.Usage())
    monkeypatch.setattr(LC, "_RUN_CNY", 0)
    monkeypatch.setattr(LC, "_CONSEC_FAIL", 0)
    monkeypatch.setattr(LC.time, "sleep", lambda _: None)
    return monkeypatch


def response(text, finish="stop", usage=None):
    return {"choices": [{"message": {"content": text}, "finish_reason": finish}],
            "model": "mock", "usage": usage or {"prompt_tokens": 10, "completion_tokens": 10}}


class Reply:
    def __init__(self, value):
        self.value = value
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self):
        return json.dumps(self.value).encode("utf-8")


def test_http_failures_consume_attempts_and_reserve_unknown_cost(transport):
    calls = []
    def fail(*args, **kw):
        calls.append(kw)
        raise urllib.error.URLError("test unavailable")
    transport.setattr(LC.urllib.request, "urlopen", fail)
    with RequestBudget(max_calls=2) as budget:
        with pytest.raises(RequestBudgetExceeded):
            LC.chat("system", "user", retries=3, use_cache=False)
    assert len(calls) == budget.attempts == 2
    assert budget.unknown_cost_attempts == 2 and budget.accounted_cny > 0
    assert current_budget() is None


def test_truncation_retry_cannot_bypass_network_cap(transport):
    calls = []
    def truncated(*args, **kw):
        calls.append(kw)
        return Reply(response("partial", "length"))
    transport.setattr(LC.urllib.request, "urlopen", truncated)
    with RequestBudget(max_calls=1) as budget:
        with pytest.raises(RequestBudgetExceeded) as err:
            LC.ask_json("system", "user", strict=True)
    assert len(calls) == LC.USAGE.calls == 1
    assert len(err.value.attempts) == 1 and budget.known_cny > 0


def test_invalid_json_retry_cannot_bypass_cap(transport):
    calls = []
    def invalid(*args, **kw):
        calls.append(kw)
        return Reply(response("not JSON"))
    transport.setattr(LC.urllib.request, "urlopen", invalid)
    with RequestBudget(max_calls=1):
        with pytest.raises(RequestBudgetExceeded) as err:
            LC.ask_json("system", "user", strict=True)
    assert len(calls) == 1 and err.value.attempts[0]["raw_text"] == "not JSON"


@pytest.mark.parametrize("kwargs", [{"max_cny": 0.000001}, {"max_tokens_per_call": 10}])
def test_cost_or_token_reservation_prevents_dispatch(transport, kwargs):
    transport.setattr(LC.urllib.request, "urlopen", lambda *a, **k: pytest.fail("must not dispatch"))
    with RequestBudget(**kwargs) as budget:
        with pytest.raises(RequestBudgetExceeded):
            LC.chat("system", "user", max_tokens=100, use_cache=False)
    assert budget.attempts == 0


def test_local_cache_hit_does_not_consume_network_budget(transport):
    transport.setattr(LC.urllib.request, "urlopen", lambda *a, **k: Reply(response('{"ok": 1}')))
    LC.chat("system", "user")
    with RequestBudget(max_calls=1) as budget:
        LC.chat("system", "user")
        LC.chat("system", "user")
    assert budget.attempts == 0 and LC.USAGE.hit_cache == 2


def test_cache_hit_and_miss_tokens_are_not_double_charged():
    r = {"usage": {"prompt_tokens": 100, "prompt_cache_hit_tokens": 80, "completion_tokens": 4}}
    expected = 20 * LC.PRICE["input_miss"] + 80 * LC.PRICE["input_hit"] + 4 * LC.PRICE["output"]
    assert usage_cost(r, LC.PRICE) == pytest.approx(expected)
    assert LC._last_cny(r) == pytest.approx(expected)


@pytest.mark.parametrize("kwargs", [{"max_calls": 0}, {"max_calls": 1.5}, {"max_cny": float("nan")},
                                    {"max_cny": float("inf")}, {"max_tokens_per_call": -1}])
def test_invalid_limits_are_rejected(kwargs):
    with pytest.raises(ValueError):
        RequestBudget(**kwargs)
