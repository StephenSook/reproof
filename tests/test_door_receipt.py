"""The recorded door triage stays byte-identical to the response it came from.

eval/results/door-42530604.ndjson is the raw body of one POST /api/triage to the deployed door,
written by scripts/record_door_triage.py. The .json beside it is what the web page reads.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from reproof.door import DoorResult, DoorStep

ROOT = Path(__file__).parents[1]
STEM = ROOT / "eval/results/door-42530604"
WEB_COPY = ROOT / "web/src/content/door-42530604.json"
EVENT_ORDER = [
    "claim:",
    "sandbox:vul",
    "sandbox:fix",
    "crash:",
    "duplicates:",
    "public_status:",
    "verdict:",
    "result",
]


def _receipt() -> dict[str, Any]:
    value = json.loads(STEM.with_suffix(".json").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _raw() -> bytes:
    return STEM.with_suffix(".ndjson").read_bytes()


def test_receipt_hash_and_events_match_the_raw_response() -> None:
    receipt = _receipt()
    raw = _raw()
    assert receipt["ndjson_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["ndjson_bytes"] == len(raw)
    lines = [json.loads(line) for line in raw.decode("utf-8").split("\n") if line.strip()]
    assert receipt["events"] == lines
    assert receipt["http_status"] == 200
    assert receipt["request_body"] == {"arvo_id": 42530604}
    assert receipt["url"] == "https://reproof-web.vercel.app/api/triage"


def test_web_copy_is_the_committed_receipt() -> None:
    assert WEB_COPY.read_bytes() == STEM.with_suffix(".json").read_bytes()


def test_receipt_is_a_complete_door_stream() -> None:
    events = _receipt()["events"]
    order = [
        f"{event['step']['step']}:{event['step'].get('kind') or ''}"
        if event["type"] == "step"
        else event["type"]
        for event in events
    ]
    assert order == EVENT_ORDER
    for event in events[:-1]:
        DoorStep.model_validate(event["step"])
    result = DoorResult.model_validate(events[-1]["result"])
    assert result.arvo_id == 42530604
    assert result.card is not None
    assert result.card.public_status is not None


def test_receipt_costs_and_credits_add_up() -> None:
    result = DoorResult.model_validate(_receipt()["events"][-1]["result"])
    card = result.card
    assert card is not None
    model = sum(call.cost_usd for call in card.model_calls)
    sandbox = sum(op.checkpoint_cost_usd + (op.cost_usd or 0.0) for op in card.sandbox_operations)
    assert abs(card.model_cost_usd - model) < 1e-8
    assert abs(card.sandbox_cost_usd - sandbox) < 1e-8
    assert abs(card.total_cost_usd - (model + sandbox)) < 1e-8
    status = card.public_status
    assert status is not None
    assert status.tavily_credits == sum(call.credits for call in status.tavily_calls)


def test_receipt_names_no_credential() -> None:
    text = _raw().decode("utf-8")
    for name in ("NEBIUS_API_KEY", "NEBIUS_PROJECT_ID", "TAVILY_API_KEY"):
        assert name not in text
