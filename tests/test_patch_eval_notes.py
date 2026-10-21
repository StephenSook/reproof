"""The post-hoc notes on the patch evaluation are recomputed from the committed cards."""

from __future__ import annotations

import json
from pathlib import Path

from reproof.patch_eval import REPORT_PATH

ROOT = Path(__file__).resolve().parents[1]


def test_the_post_hoc_notes_are_recomputed_from_the_cards() -> None:
    from eval import annotate_patch_eval as notes

    committed = json.loads((ROOT / notes.NOTES_PATH).read_text(encoding="utf-8"))
    assert committed == notes.build_notes(ROOT)
    totals = committed["totals"]
    assert (
        totals["attempts"]
        == json.loads((ROOT / REPORT_PATH).read_text(encoding="utf-8"))["totals"]["model_calls"]
    )
    # Every blocked attempt is a COMPILE_FAILED whose control compile passed.
    for task in committed["tasks"]:
        for attempt in task["blocked_attempts"]:
            assert task["attempt_outcomes"][attempt - 1] == "COMPILE_FAILED"
        assert bool(task["blocked_attempts"]) == bool(task["blocking_line"])
