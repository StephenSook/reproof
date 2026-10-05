from __future__ import annotations

import asyncio
import json
from pathlib import Path

from reproof.door_asgi import HEALTH_PATH, TRIAGE_PATH, app, dispatch

ROOT = Path(__file__).resolve().parents[1]
API_SENTINEL = "SENTINEL-API-KEY-VALUE-XYZ"
PROJECT_SENTINEL = "SENTINEL-PROJECT-ID-VALUE-XYZ"


def _body(parts) -> bytes:
    return b"".join(parts)


def _store(tmp_path: Path) -> Path:
    return tmp_path / "limits.json"


def test_health_and_unknown_task_omit_credential_values(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NEBIUS_API_KEY", API_SENTINEL)
    monkeypatch.setenv("NEBIUS_PROJECT_ID", PROJECT_SENTINEL)
    status, content_type, parts = dispatch("GET", HEALTH_PATH, b"", limits_path=_store(tmp_path))
    health = _body(parts)
    assert status == 200
    assert content_type.startswith("application/json")
    assert json.loads(health) == {"ok": True}

    status, content_type, parts = dispatch(
        "POST",
        TRIAGE_PATH,
        b'{"arvo_id": 1}',
        limits_path=_store(tmp_path),
    )
    raw = _body(parts)
    assert status == 200
    assert content_type.startswith("application/x-ndjson")
    events = [json.loads(line) for line in raw.decode().splitlines() if line]
    result = next(event["result"] for event in events if event["type"] == "result")
    assert result["verdict"] == "NEEDS_INFO"
    assert result["card"] is None
    assert "not in the committed judge catalog" in result["reason"]
    rendered = health + raw
    assert API_SENTINEL.encode() not in rendered
    assert PROJECT_SENTINEL.encode() not in rendered
    assert b"NEBIUS_API_KEY" not in rendered
    assert b"NEBIUS_PROJECT_ID" not in rendered


def test_triage_rejects_a_bad_body(tmp_path: Path) -> None:
    status, _content_type, parts = dispatch(
        "POST",
        TRIAGE_PATH,
        b"{}",
        limits_path=_store(tmp_path),
    )
    assert status == 400
    assert json.loads(_body(parts))["error"] == "body must be a JSON object with arvo_id"
    status, _content_type, parts = dispatch(
        "POST",
        TRIAGE_PATH,
        b'{"arvo_id": true}',
        limits_path=_store(tmp_path),
    )
    assert status == 400
    huge = b'{"arvo_id": 1, "pad": "' + (b"x" * 70000) + b'"}'
    status, _content_type, parts = dispatch("POST", TRIAGE_PATH, huge, limits_path=_store(tmp_path))
    assert status == 413


def test_asgi_app_streams_needs_info(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NEBIUS_API_KEY", API_SENTINEL)
    monkeypatch.setenv("NEBIUS_PROJECT_ID", PROJECT_SENTINEL)
    monkeypatch.setenv("REPROOF_LIMITS_PATH", str(_store(tmp_path)))
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b'{"arvo_id": 1}', "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    asyncio.run(
        app(
            {"type": "http", "method": "POST", "path": TRIAGE_PATH},
            receive,
            send,
        )
    )
    assert sent[0]["status"] == 200
    raw = b"".join(bytes(message["body"]) for message in sent[1:] if message.get("body"))
    events = [json.loads(line) for line in raw.decode().splitlines() if line]
    assert events[-1]["type"] == "result"
    assert events[-1]["result"]["verdict"] == "NEEDS_INFO"
    assert API_SENTINEL.encode() not in raw
    assert PROJECT_SENTINEL.encode() not in raw


def test_vercel_entrypoint_matches_and_duration_fits_hobby() -> None:
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    triage = config["services"]["triage"]
    assert triage["entrypoint"] == "reproof.door_asgi:app"
    assert 'entrypoint = "reproof.door_asgi:app"' in pyproject
    duration = triage["functions"]["reproof/door_asgi.py"]["maxDuration"]
    sandbox = (ROOT / "reproof" / "sandbox.py").read_text(encoding="utf-8")
    assert "timeout=600" in sandbox
    assert duration <= 300
    assert duration < 600
    assert config["services"]["web"]["root"] == "web/"
    sources = [item["source"] for item in config["rewrites"]]
    assert sources[0] == "/api/triage"
    assert sources[-1] == "/(.*)"
