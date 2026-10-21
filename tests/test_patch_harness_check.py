"""The committed no-model harness check covers every registered image and adds up."""

from __future__ import annotations

import json
from pathlib import Path

from reproof.patch_eval import TASK_IDS

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "eval/results/patch-harness-check.json"


def test_the_check_ran_every_image_without_a_model_and_its_totals_add_up() -> None:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    tasks = receipt["tasks"]
    assert receipt["model_calls"] == 0
    assert receipt["code"]["uncommitted"] == ""
    assert [task["arvo_id"] for task in tasks] == list(TASK_IDS)
    totals = receipt["totals"]
    assert totals["images"] == totals["checked"] == len(TASK_IDS)
    assert totals["ok"] == sum(task["result"] == "OK" for task in tasks)
    assert totals["images_removed"] == sum(bool(task["image_removed"]) for task in tasks)
    attempts = [attempt for task in tasks for attempt in task.get("attempts", [])]
    assert totals["attempt_compiles"] == len(attempts)
    assert totals["attempt_compiles_that_built"] == sum(
        attempt["compile"] is not None and attempt["compile"]["exit_code"] == 0
        for attempt in attempts
    )
    for task in tasks:
        if task["result"] != "OK":
            # A failure is recorded with its reason, never left blank.
            assert task["result"].startswith("FAILED: ")
            continue
        assert task["control_compile"]["exit_code"] == 0
        assert task["snapshot_image"].startswith("sha256:")
        assert len(task["attempts"]) == 2
        for attempt in task["attempts"]:
            # A no-op edit: nothing changed, the tree rebuilt, and the bug still crashed.
            assert attempt["diff"] == ""
            assert attempt["compile"]["exit_code"] == 0
            assert attempt["outcome"] == "STILL_CRASHES"
            assert attempt["poc_crash_type"] == task["baseline_crash_type"]
