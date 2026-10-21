"""Post-hoc notes on the registered patch evaluation. They explain the result, never change it.

Written after the run, from the committed cards only. An attempt is counted as blocked by the
image's build script when its compile failed, the control compile of the untouched tree in the
same container exited 0, and the attempt's compile log has a line
``mkdir: cannot create directory '<path>': File exists``. That line means the build script makes a
directory with plain ``mkdir``, so the second run of the script in one container stops there,
whatever the edit was. The harness's control compile was always the first run.

Usage: uv run python eval/annotate_patch_eval.py
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from reproof.patch_eval import CARDS_DIR, REPORT_PATH, TASK_IDS, TaskRecord
from reproof.provenance import file_sha256

ROOT = Path(__file__).resolve().parents[1]
NOTES_PATH = "eval/results/patch-eval-notes.json"
BLOCKING = re.compile(r"^mkdir: cannot create directory '[^']+': File exists$", re.MULTILINE)
METHOD = (
    "Post-hoc, written after the run and not part of the registration. An attempt is blocked by "
    "the build script when its compile failed, the control compile of the untouched tree in the "
    "same container exited 0, and the attempt's compile log has a line \"mkdir: cannot create "
    "directory '<path>': File exists\". The build script makes that directory with plain mkdir, "
    "so its second run in one container stops there whatever the edit was."
)


def blocking_line(card: TaskRecord, attempt_index: int) -> str:
    attempt = card.attempts[attempt_index]
    control = card.control_compile
    if attempt.outcome != "COMPILE_FAILED" or attempt.compile is None:
        return ""
    if control is None or control.exit_code != 0:
        return ""
    match = BLOCKING.search(attempt.compile.output_tail)
    return match.group(0) if match else ""


def task_note(card: TaskRecord) -> dict[str, Any]:
    lines = [blocking_line(card, index) for index in range(len(card.attempts))]
    blocked = [attempt.attempt for attempt, line in zip(card.attempts, lines, strict=True) if line]
    built = [
        attempt.attempt
        for attempt in card.attempts
        if attempt.compile is not None and attempt.compile.exit_code == 0
    ]
    return {
        "arvo_id": card.arvo_id,
        "project": card.project,
        "outcome": card.outcome,
        "attempt_outcomes": [attempt.outcome for attempt in card.attempts],
        "blocked_attempts": blocked,
        "blocking_line": next((line for line in lines if line), ""),
        "built_attempts": built,
    }


def build_notes(root: Path = ROOT) -> dict[str, Any]:
    cards = [
        TaskRecord.model_validate_json(
            (root / CARDS_DIR / f"{task_id}.json").read_text(encoding="utf-8")
        )
        for task_id in TASK_IDS
    ]
    tasks = [task_note(card) for card in cards]
    outcomes = Counter(outcome for task in tasks for outcome in task["attempt_outcomes"])
    return {
        "schema_version": "1",
        "method": METHOD,
        "source": {REPORT_PATH: file_sha256(root / REPORT_PATH)},
        "tasks": tasks,
        "totals": {
            "attempts": sum(outcomes.values()),
            "attempt_outcomes": dict(sorted(outcomes.items())),
            "blocked_attempts": sum(len(task["blocked_attempts"]) for task in tasks),
            "tasks_with_blocked_attempts": sum(bool(task["blocked_attempts"]) for task in tasks),
            "attempts_that_built": sum(len(task["built_attempts"]) for task in tasks),
            "tasks_where_an_edit_built": sum(bool(task["built_attempts"]) for task in tasks),
        },
    }


def main() -> int:
    notes = build_notes()
    path = ROOT / NOTES_PATH
    path.write_text(
        json.dumps(notes, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(notes["totals"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
