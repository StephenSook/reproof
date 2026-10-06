"""Caps for one judge door. The count file is local to this process.

On Vercel, function instances do not share a disk, so a count on one instance
is not a count on another. There is no shared store in this package.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from reproof.door_data import ASSETS_DIR

LIMITS_FILE = ASSETS_DIR / "limits.json"
VISITOR_COOKIE = "reproof_visitor"
LEASE_SECONDS = 180
_LOCK_WAIT_SECONDS = 5.0
_STALE_LOCK_SECONDS = 30.0


@dataclass(frozen=True)
class Limits:
    in_flight_per_visitor: int
    per_ip_per_hour: int
    global_per_day: int
    tavily_credits_per_day: int
    public_reuse_seconds: int

    def public(self) -> dict[str, int]:
        return {
            "in_flight_per_visitor": self.in_flight_per_visitor,
            "per_ip_per_hour": self.per_ip_per_hour,
            "global_per_day": self.global_per_day,
            "tavily_credits_per_day": self.tavily_credits_per_day,
            "public_reuse_seconds": self.public_reuse_seconds,
        }


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class PublicBudget:
    """Tavily spend on one door instance.

    A lookup for the same measured crash is reused for `limits.public_reuse_seconds`. A new
    lookup first reserves its worst-case credits against the UTC day's cap, then
    the reservation is replaced by the credits Tavily reported.
    """

    store: Path
    limits: Limits
    clock: Callable[[], datetime] = field(default=_utc_now)

    def reuse(self, key: str) -> tuple[dict[str, Any], str] | None:
        now = self.clock().astimezone(UTC)

        def read(data: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
            entry = data.get("public", {}).get(key)
            if not isinstance(entry, dict) or not isinstance(entry.get("status"), dict):
                return None
            try:
                at = datetime.fromisoformat(str(entry.get("at", "")))
            except ValueError:
                return None
            if at > now or now - at > timedelta(seconds=self.limits.public_reuse_seconds):
                return None
            return entry["status"], at.isoformat()

        result: tuple[dict[str, Any], str] | None = _update(self.store, read)
        return result

    def reserve(self, credits: int) -> str | None:
        """Hold `credits` against today's cap. Return the day key, or None when it is spent."""

        day = self.clock().astimezone(UTC).strftime("%Y-%m-%d")

        def mutate(data: dict[str, Any]) -> str | None:
            spent = data.setdefault("tavily_days", {})
            used = int(spent.get(day, 0))
            if used + credits > self.limits.tavily_credits_per_day:
                return None
            spent[day] = used + credits
            return day

        result: str | None = _update(self.store, mutate)
        return result

    def settle(
        self,
        day: str,
        *,
        reserved: int,
        spent: int | None,
        key: str,
        status: dict[str, Any] | None,
    ) -> None:
        """Swap the reservation for the credits spent. `spent=None` keeps the whole hold."""

        now = self.clock().astimezone(UTC)

        def mutate(data: dict[str, Any]) -> None:
            days = data.setdefault("tavily_days", {})
            if spent is not None:
                days[day] = max(0, int(days.get(day, 0)) - reserved + spent)
            oldest = (now - timedelta(days=2)).strftime("%Y-%m-%d")
            for old in [name for name in days if name < oldest]:
                del days[old]
            public = data.setdefault("public", {})
            if status is not None:
                public[key] = {"at": now.isoformat(), "status": status}
            cutoff = now - timedelta(seconds=self.limits.public_reuse_seconds)
            for name in list(public):
                entry = public[name]
                try:
                    stale = datetime.fromisoformat(str(entry.get("at", ""))) < cutoff
                except (AttributeError, ValueError):
                    stale = True
                if stale:
                    del public[name]

        _update(self.store, mutate)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    status: int
    error: str
    visitor_id: str
    minted: bool


def load_limits(path: Path | None = None) -> Limits:
    raw = json.loads((path or LIMITS_FILE).read_text(encoding="utf-8"))
    flight = int(raw["in_flight_per_visitor"])
    hourly = int(raw["per_ip_per_hour"])
    daily = int(raw["global_per_day"])
    tavily = int(raw["tavily_credits_per_day"])
    reuse = int(raw["public_reuse_seconds"])
    if flight < 1 or hourly < 1 or daily < 1 or tavily < 1 or reuse < 1:
        raise ValueError("door limits must be positive")
    return Limits(
        in_flight_per_visitor=flight,
        per_ip_per_hour=hourly,
        global_per_day=daily,
        tavily_credits_per_day=tavily,
        public_reuse_seconds=reuse,
    )


def default_store_path() -> Path:
    configured = os.environ.get("REPROOF_LIMITS_PATH", "").strip()
    if configured:
        return Path(configured)
    return Path(".cache") / "reproof" / "door-limits.json"


def client_ip(headers: dict[str, str], peer: str | None) -> str:
    """Prefer the platform header, then the last forwarded hop, then the socket."""

    vercel = headers.get("x-vercel-forwarded-for", "").strip()
    if vercel:
        first = vercel.split(",")[0].strip()
        if first:
            return first
    forwarded = headers.get("x-forwarded-for", "").strip()
    if forwarded:
        hops = [part.strip() for part in forwarded.split(",") if part.strip()]
        if hops:
            return hops[-1]
    cleaned = (peer or "").strip()
    return cleaned or "unknown"


def visitor_from_cookie(header: str | None) -> str | None:
    if not header:
        return None
    for part in header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name == VISITOR_COOKIE and _valid_visitor(value):
            return value
    return None


def cookie_header(visitor_id: str, secure: bool) -> str:
    pieces = [
        f"{VISITOR_COOKIE}={visitor_id}",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=31536000",
    ]
    if secure:
        pieces.append("Secure")
    return "; ".join(pieces)


def begin(
    visitor: str | None,
    ip: str,
    now: datetime,
    store: Path,
    *,
    limits: Limits | None = None,
) -> Decision:
    """Count one started triage, including a cheap NEEDS_INFO, or refuse it."""

    active = limits or load_limits()
    minted = not _valid_visitor(visitor)
    visitor_id = uuid.uuid4().hex if minted else str(visitor)
    stamp = now.astimezone(UTC)
    hour_key = f"{ip}|{stamp.strftime('%Y-%m-%dT%H')}"
    day_key = stamp.strftime("%Y-%m-%d")

    def mutate(data: dict[str, Any]) -> Decision:
        visitors = data.setdefault("visitors", {})
        hours = data.setdefault("hours", {})
        days = data.setdefault("days", {})
        current = visitors.get(visitor_id) or {}
        if current.get("in_flight"):
            started = datetime.fromisoformat(str(current["started"]))
            if stamp - started < timedelta(seconds=LEASE_SECONDS):
                return Decision(
                    False,
                    429,
                    "A triage is already running for this browser.",
                    visitor_id,
                    minted,
                )
        if int(hours.get(hour_key, 0)) >= active.per_ip_per_hour:
            return Decision(
                False,
                429,
                "This address has reached the hourly triage limit.",
                visitor_id,
                minted,
            )
        if int(days.get(day_key, 0)) >= active.global_per_day:
            return Decision(
                False,
                429,
                "The daily triage limit has been reached.",
                visitor_id,
                minted,
            )
        hours[hour_key] = int(hours.get(hour_key, 0)) + 1
        days[day_key] = int(days.get(day_key, 0)) + 1
        visitors[visitor_id] = {"in_flight": True, "started": stamp.isoformat()}
        return Decision(True, 200, "", visitor_id, minted)

    return _update(store, mutate)


def finish(visitor_id: str, store: Path) -> None:
    def mutate(data: dict[str, Any]) -> None:
        current = data.setdefault("visitors", {}).get(visitor_id)
        if isinstance(current, dict):
            current["in_flight"] = False

    _update(store, mutate)


def _valid_visitor(value: str | None) -> bool:
    if not value or not 16 <= len(value) <= 64:
        return False
    return all(character.isalnum() or character in "_-" for character in value)


def _empty_store() -> dict[str, Any]:
    return {"visitors": {}, "hours": {}, "days": {}}


def _update(store: Path, mutate: Callable[[dict[str, Any]], Any]) -> Any:
    store.parent.mkdir(parents=True, exist_ok=True)
    lock_path = store.with_suffix(".lock")
    fd = _acquire_lock(lock_path)
    try:
        if store.exists():
            raw = store.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else _empty_store()
        else:
            data = _empty_store()
        if not isinstance(data, dict):
            data = _empty_store()
        result = mutate(data)
        store.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return result
    finally:
        os.close(fd)
        lock_path.unlink(missing_ok=True)


def _acquire_lock(lock_path: Path) -> int:
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            return os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
            except FileNotFoundError:
                continue
            if age > _STALE_LOCK_SECONDS:
                with contextlib.suppress(FileNotFoundError):
                    lock_path.unlink()
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("door limit lock is held") from None
            time.sleep(0.02)
