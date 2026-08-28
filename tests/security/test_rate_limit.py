"""
core.security.rate_limit() must actually wait out the configured interval
between two calls for the same tool. Uses a fully controlled fake clock —
no real sleeping, so this test stays fast and deterministic.
"""

from __future__ import annotations

import core.security as security


def test_second_call_within_interval_sleeps_for_remaining_time(monkeypatch):
    monkeypatch.setitem(security.RATE_LIMITS, "unittool", 5.0)
    monkeypatch.setattr(security, "_last_call_time", {})

    fake_time = {"t": 1000.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: fake_time["t"])

    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        fake_time["t"] += seconds

    monkeypatch.setattr(security.time, "sleep", fake_sleep)

    # First call ever for this tool: nothing to wait on.
    security.rate_limit("unittool")
    assert sleep_calls == []

    # Immediately calling again (fake clock hasn't advanced) must wait out
    # the full configured interval.
    security.rate_limit("unittool")
    assert sleep_calls == [5.0]


def test_call_after_interval_has_elapsed_does_not_sleep(monkeypatch):
    monkeypatch.setitem(security.RATE_LIMITS, "unittool", 5.0)
    monkeypatch.setattr(security, "_last_call_time", {})

    fake_time = {"t": 1000.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: fake_time["t"])

    sleep_calls: list[float] = []
    monkeypatch.setattr(security.time, "sleep", lambda s: sleep_calls.append(s))

    security.rate_limit("unittool")
    fake_time["t"] += 10.0  # well past the 5s interval
    security.rate_limit("unittool")

    assert sleep_calls == []


def test_unknown_tool_uses_default_interval(monkeypatch):
    monkeypatch.setattr(security, "_last_call_time", {})
    fake_time = {"t": 1000.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: fake_time["t"])
    sleep_calls: list[float] = []
    monkeypatch.setattr(security.time, "sleep", lambda s: sleep_calls.append(s))

    assert "definitely-not-a-configured-tool" not in security.RATE_LIMITS
    security.rate_limit("definitely-not-a-configured-tool")
    security.rate_limit("definitely-not-a-configured-tool")

    assert sleep_calls == [2.0]  # the documented default
