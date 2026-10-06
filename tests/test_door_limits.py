from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reproof.door_asgi import TRIAGE_PATH, dispatch
from reproof.door_limits import (
    LEASE_SECONDS,
    Limits,
    PublicBudget,
    begin,
    client_ip,
    finish,
    load_limits,
)

API_SENTINEL = "SENTINEL-API-KEY-VALUE-XYZ"
PROJECT_SENTINEL = "SENTINEL-PROJECT-ID-VALUE-XYZ"
WHEN = datetime(2026, 10, 5, 15, 0, tzinfo=UTC)
REUSE = 3600


def test_limits_file_is_positive() -> None:
    limits = load_limits()
    assert limits.in_flight_per_visitor == 1
    assert limits.per_ip_per_hour == 8
    assert limits.global_per_day == 60
    assert limits.tavily_credits_per_day == 100
    assert limits.public_reuse_seconds == 3600


def test_limits_require_a_positive_tavily_cap(tmp_path: Path) -> None:
    path = tmp_path / "limits.json"
    base = {
        "in_flight_per_visitor": 1,
        "per_ip_per_hour": 8,
        "global_per_day": 60,
        "public_reuse_seconds": 3600,
    }
    path.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(KeyError):
        load_limits(path)
    path.write_text(json.dumps({**base, "tavily_credits_per_day": 0}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_limits(path)


def _budget(store: Path, cap: int, clock: list[datetime]) -> PublicBudget:
    limits = Limits(
        in_flight_per_visitor=1,
        per_ip_per_hour=8,
        global_per_day=60,
        tavily_credits_per_day=cap,
        public_reuse_seconds=3600,
    )
    return PublicBudget(store=store, limits=limits, clock=lambda: clock[0])


def test_tavily_reservations_stop_at_the_daily_cap(tmp_path: Path) -> None:
    clock = [WHEN]
    budget = _budget(tmp_path / "limits.json", 10, clock)
    assert budget.reserve(5) == "2026-10-05"
    assert budget.reserve(5) == "2026-10-05"
    assert budget.reserve(5) is None
    clock[0] = WHEN + timedelta(days=1)
    assert budget.reserve(5) == "2026-10-06"


def test_settle_swaps_the_hold_for_the_credits_spent(tmp_path: Path) -> None:
    clock = [WHEN]
    budget = _budget(tmp_path / "limits.json", 10, clock)
    day = budget.reserve(5)
    assert day is not None
    budget.settle(day, reserved=5, spent=2, key="k", status=None)
    assert budget.reserve(8) == day
    assert budget.reserve(1) is None


def test_unknown_spend_keeps_the_whole_hold(tmp_path: Path) -> None:
    clock = [WHEN]
    budget = _budget(tmp_path / "limits.json", 10, clock)
    day = budget.reserve(5)
    assert day is not None
    budget.settle(day, reserved=5, spent=None, key="k", status=None)
    assert budget.reserve(6) is None
    assert budget.reserve(5) == day


def test_a_kept_lookup_is_reused_only_inside_the_window(tmp_path: Path) -> None:
    clock = [WHEN]
    store = tmp_path / "limits.json"
    budget = _budget(store, 10, clock)
    assert budget.reuse("k") is None
    day = budget.reserve(5)
    assert day is not None
    budget.settle(day, reserved=5, spent=4, key="k", status={"state": "NO_PUBLIC_FINDINGS"})
    budget.settle(day, reserved=0, spent=0, key="other", status=None)
    assert budget.reuse("other") is None
    clock[0] = WHEN + timedelta(seconds=REUSE - 1)
    reused = budget.reuse("k")
    assert reused is not None
    stored, at = reused
    assert stored == {"state": "NO_PUBLIC_FINDINGS"}
    assert at == WHEN.isoformat()
    clock[0] = WHEN + timedelta(seconds=REUSE + 1)
    assert budget.reuse("k") is None
    clock[0] = WHEN - timedelta(seconds=1)
    assert budget.reuse("k") is None


def test_one_triage_at_a_time_and_the_lease_expires(tmp_path: Path) -> None:
    store = tmp_path / "limits.json"
    first = begin("visitor-1234567890abcd", "203.0.113.8", WHEN, store)
    assert first.allowed
    second = begin(first.visitor_id, "203.0.113.8", WHEN, store)
    assert second.allowed is False
    assert second.status == 429
    assert "already running" in second.error
    finish(first.visitor_id, store)
    third = begin(first.visitor_id, "203.0.113.9", WHEN, store)
    assert third.allowed
    finish(third.visitor_id, store)
    stale = WHEN + timedelta(seconds=LEASE_SECONDS + 1)
    # Leave this visitor in flight, then let the lease expire.
    held = begin("visitor-held-1234567890", "203.0.113.10", WHEN, store)
    assert held.allowed
    resumed = begin(held.visitor_id, "203.0.113.10", stale, store)
    assert resumed.allowed


def test_hourly_and_daily_caps_refuse_without_a_card(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NEBIUS_API_KEY", API_SENTINEL)
    monkeypatch.setenv("NEBIUS_PROJECT_ID", PROJECT_SENTINEL)
    store = tmp_path / "limits.json"
    limits = load_limits()
    visitor = "visitor-hourly-1234567890"
    for index in range(limits.per_ip_per_hour):
        decision = begin(visitor if index else None, "198.51.100.4", WHEN, store)
        assert decision.allowed
        finish(decision.visitor_id, store)
        visitor = decision.visitor_id
    blocked = begin(visitor, "198.51.100.4", WHEN, store)
    assert blocked.allowed is False
    assert "hourly" in blocked.error

    status, content_type, parts = dispatch(
        "POST",
        TRIAGE_PATH,
        b'{"arvo_id": 1}',
        visitor=visitor,
        ip="198.51.100.4",
        limits_path=store,
        now=WHEN,
    )
    raw = b"".join(parts)
    assert status == 429
    assert content_type.startswith("application/json")
    payload = json.loads(raw)
    assert payload["limits"]["per_ip_per_hour"] == 8
    assert "verdict" not in payload
    assert API_SENTINEL.encode() not in raw
    assert PROJECT_SENTINEL.encode() not in raw

    daily = tmp_path / "daily.json"
    day_visitor = "visitor-daily-1234567890"
    for index in range(limits.global_per_day):
        decision = begin(day_visitor, f"192.0.2.{index % 200}", WHEN, daily)
        assert decision.allowed
        finish(decision.visitor_id, daily)
    refused = begin(day_visitor, "192.0.2.201", WHEN, daily)
    assert refused.allowed is False
    assert "daily" in refused.error


def test_client_ip_prefers_platform_header_then_last_hop() -> None:
    assert client_ip({"x-vercel-forwarded-for": "203.0.113.5, 10.0.0.1"}, "127.0.0.1") == (
        "203.0.113.5"
    )
    assert client_ip({"x-forwarded-for": "1.1.1.1, 198.51.100.9"}, None) == "198.51.100.9"
    assert client_ip({}, "127.0.0.1") == "127.0.0.1"
    assert client_ip({}, None) == "unknown"
