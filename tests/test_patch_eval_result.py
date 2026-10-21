"""The committed patch evaluation agrees with its cards and with its registration."""

from __future__ import annotations

import json
import math
from pathlib import Path

from reproof.patch_eval import (
    BUDGET_USD,
    CARDS_DIR,
    MAX_ATTEMPTS,
    PREREG_PATH,
    REPORT_PATH,
    TASK_IDS,
    TaskRecord,
    summary_row,
)
from reproof.provenance import file_sha256

ROOT = Path(__file__).resolve().parents[1]


def _report() -> dict[str, object]:
    value = json.loads((ROOT / REPORT_PATH).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _cards() -> list[TaskRecord]:
    return [
        TaskRecord.model_validate_json(
            (ROOT / CARDS_DIR / f"{task_id}.json").read_text(encoding="utf-8")
        )
        for task_id in TASK_IDS
    ]


def test_every_registered_task_has_a_card_and_a_row_built_from_it() -> None:
    report = _report()
    cards = _cards()
    rows = report["tasks"]
    assert isinstance(rows, list)
    assert [row["arvo_id"] for row in rows] == list(TASK_IDS)
    for row, card in zip(rows, cards, strict=True):
        assert row == summary_row(card, f"{CARDS_DIR}/{card.arvo_id}.json")
        assert card.image_removed
        assert len(card.attempts) <= MAX_ATTEMPTS
        if card.outcome == "PROVEN":
            assert card.attempts[-1].outcome == "PROVEN"
            assert card.proven_attempt == len(card.attempts)
            assert card.attempts[-1].compile is not None
            assert card.attempts[-1].compile.exit_code == 0
            assert card.attempts[-1].poc is not None
            assert card.attempts[-1].poc.exit_code == 0
        else:
            assert all(attempt.outcome != "PROVEN" for attempt in card.attempts)
        if card.outcome == "HARNESS_FAILED":
            assert all(attempt.outcome == "HARNESS_ERROR" for attempt in card.attempts)


def test_totals_are_the_sum_of_the_cards() -> None:
    report = _report()
    cards = _cards()
    totals = report["totals"]
    assert isinstance(totals, dict)
    assert totals["tasks"] == len(TASK_IDS) == 10
    assert totals["proven"] == sum(card.outcome == "PROVEN" for card in cards)
    assert totals["not_proven"] == sum(card.outcome == "NOT_PROVEN" for card in cards)
    assert totals["harness_failed"] == sum(card.outcome == "HARNESS_FAILED" for card in cards)
    assert totals["budget_stopped"] == sum(card.outcome == "BUDGET_STOPPED" for card in cards)
    assert totals["attempts_per_proven"] == [
        card.proven_attempt for card in cards if card.outcome == "PROVEN"
    ]
    assert totals["model_calls"] == sum(card.model_calls for card in cards)
    assert totals["input_tokens"] == sum(card.input_tokens for card in cards)
    assert totals["output_tokens"] == sum(card.output_tokens for card in cards)
    spent = sum(attempt.model_cost_usd for card in cards for attempt in card.attempts)
    assert math.isclose(float(totals["model_cost_usd"]), spent, abs_tol=1e-7)
    assert float(totals["model_cost_usd"]) <= BUDGET_USD
    for card in cards:
        calls = [attempt.model_call for attempt in card.attempts if attempt.model_call]
        assert card.model_calls == len(calls)
        assert all(call.request_id != "missing" for call in calls)


def test_the_run_names_the_committed_registration() -> None:
    prereg = _report()["prereg"]
    assert isinstance(prereg, dict)
    assert prereg["path"] == PREREG_PATH
    assert prereg["sha256"] == file_sha256(ROOT / PREREG_PATH)
    assert len(str(prereg["commit"])) == 40
