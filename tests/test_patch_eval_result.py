"""Each committed patch evaluation run agrees with its cards and with its registration."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from reproof.patch_eval import (
    BUDGET_USD,
    MAX_ATTEMPTS,
    RUN1,
    RUN2,
    TASK_IDS,
    RunPaths,
    TaskRecord,
    summary_row,
)
from reproof.provenance import file_sha256

ROOT = Path(__file__).resolve().parents[1]
RUNS = pytest.mark.parametrize("run", [RUN1, RUN2], ids=["run1", "run2"])


def _report(run: RunPaths) -> dict[str, object]:
    value = json.loads((ROOT / run.report).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _cards(run: RunPaths) -> list[TaskRecord]:
    return [
        TaskRecord.model_validate_json(
            (ROOT / run.cards / f"{task_id}.json").read_text(encoding="utf-8")
        )
        for task_id in TASK_IDS
    ]


@RUNS
def test_every_registered_task_has_a_card_and_a_row_built_from_it(run: RunPaths) -> None:
    report = _report(run)
    cards = _cards(run)
    rows = report["tasks"]
    assert isinstance(rows, list)
    assert [row["arvo_id"] for row in rows] == list(TASK_IDS)
    for row, card in zip(rows, cards, strict=True):
        assert row == summary_row(card, f"{run.cards}/{card.arvo_id}.json")
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


@RUNS
def test_totals_are_the_sum_of_the_cards(run: RunPaths) -> None:
    report = _report(run)
    cards = _cards(run)
    totals = report["totals"]
    assert isinstance(totals, dict)
    assert totals["tasks"] == len(TASK_IDS) == 10
    assert totals["recorded"] == len(cards)
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
    assert math.isclose(
        float(totals["wall_seconds"]), sum(card.wall_seconds for card in cards), abs_tol=1e-3
    )
    for card in cards:
        calls = [attempt.model_call for attempt in card.attempts if attempt.model_call]
        assert card.model_calls == len(calls)
        assert card.input_tokens == sum(call.input_tokens for call in calls)
        assert card.output_tokens == sum(call.output_tokens for call in calls)
        assert all(call.request_id != "missing" for call in calls)


@RUNS
def test_the_run_names_the_committed_registration(run: RunPaths) -> None:
    prereg = _report(run)["prereg"]
    assert isinstance(prereg, dict)
    assert prereg["path"] == run.prereg
    assert prereg["sha256"] == file_sha256(ROOT / run.prereg)
    assert len(str(prereg["commit"])) == 40


def test_run_2_compiled_every_attempt_in_a_container_from_its_snapshot() -> None:
    run1 = _report(RUN1)["prereg"]
    run2 = _report(RUN2)["prereg"]
    assert isinstance(run1, dict) and isinstance(run2, dict)
    assert run2["commit"] != run1["commit"]
    for card in _cards(RUN2):
        if card.control_compile is None:
            continue
        assert card.snapshot_image.startswith("sha256:")
        if any(attempt.compile is not None for attempt in card.attempts):
            # The source was read from a clean container, and each attempt after one that ran a
            # compile needed a new one.
            assert card.clean_containers >= 1
    # Run 1's cards predate the snapshot and say so by leaving the run-2 fields empty.
    assert all(
        card.snapshot_image == "" and card.clean_containers == 0 and card.frame_notes == []
        for card in _cards(RUN1)
    )
