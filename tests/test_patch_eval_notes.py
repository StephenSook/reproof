"""The notes on each patch evaluation run are recomputed from that run's committed cards."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reproof.patch_eval import RUN1, RUN2, RunPaths

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("run", [RUN1, RUN2], ids=["run1", "run2"])
def test_the_notes_are_recomputed_from_the_cards(run: RunPaths) -> None:
    from eval import annotate_patch_eval as notes

    notes_path, method = notes.NOTES[run]
    committed = json.loads((ROOT / notes_path).read_text(encoding="utf-8"))
    assert committed == notes.build_notes(ROOT, run)
    assert committed["method"] == method
    totals = committed["totals"]
    assert (
        totals["attempts"]
        == json.loads((ROOT / run.report).read_text(encoding="utf-8"))["totals"]["model_calls"]
    )
    # Every blocked attempt is a COMPILE_FAILED whose control compile passed.
    for task in committed["tasks"]:
        for attempt in task["blocked_attempts"]:
            assert task["attempt_outcomes"][attempt - 1] == "COMPILE_FAILED"
        assert bool(task["blocked_attempts"]) == bool(task["blocking_line"])
