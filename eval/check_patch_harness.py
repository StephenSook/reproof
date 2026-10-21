"""No-model check of the run-2 patch harness: every image compiles again after its control build.

For each of the 10 registered images this runs the harness exactly as a scored task does up to
the first model call (``prepare_harness``, the run-1 harness checks, ``build_source``), then runs
the attempt path twice (``apply_and_prove``) with a no-op edit: one exact-text edit whose new text
equals its old text, in the file of the first chosen frame. Both attempts must rebuild and the
stored PoC must still crash the unpatched code. When the image has a seed corpus, the fuzz target
then runs over it in the last attempt's container. No model is called; nothing leaves the
container, and the container, the snapshot and the image are removed after each task.

Usage: uv run python eval/check_patch_harness.py
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reproof.patch_eval import (
    CARDS_DIR,
    TASK_IDS,
    DockerTask,
    PatchEdit,
    PatchProposal,
    StepRun,
    TaskRecord,
    _crash_fields,
    _decode,
    _seeds_clean,
    _task_inputs,
    _write_json,
    apply_and_prove,
    build_source,
    host_free_bytes,
    prepare_harness,
    step_run,
)
from reproof.provenance import source_sha256

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_PATH = "eval/results/patch-harness-check.json"
NOTES_PATH = "eval/results/patch-eval-notes.json"
NOOP_ATTEMPTS = 2
RECEIPT_TAIL_LINES = 20
MIN_FREE_BYTES = 1_500_000_000
METHOD = (
    "No model call. Per image: the run-2 harness up to the first model call (baseline PoC, seed "
    "corpus unpacked, docker commit as the snapshot, control compile, PoC and seeds in that "
    "container, source read from a fresh container), then the attempt path (apply_and_prove) "
    "twice with a no-op edit whose new text equals its old text in the first chosen frame's "
    "file. Each attempt starts from a fresh container from the snapshot. OK means both attempt "
    "compiles exited 0 and the stored PoC still crashed with the baseline's crash type."
)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _short(run: StepRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    data = run.model_dump()
    data["output_tail"] = "\n".join(run.output_tail.splitlines()[-RECEIPT_TAIL_LINES:])
    return data


def noop_edit(path: str, text: str, line: int) -> tuple[PatchEdit, list[int]] | None:
    """The frame line, grown downwards until it occurs once in the file, as a no-op edit."""

    lines = text.split("\n")
    start = max(0, line - 1)
    for end in range(start + 1, min(len(lines), start + 40) + 1):
        block = "\n".join(lines[start:end])
        if block.strip() and text.count(block) == 1:
            return PatchEdit(path=path, old_text=block, new_text=block), [start + 1, end]
    return None


def check_task(task_id: int, run1: TaskRecord, blocked: list[int]) -> dict[str, Any]:
    started = time.perf_counter()
    task = _task_inputs()[task_id]
    docker = DockerTask(task_id)
    fields: dict[str, Any] = {}
    entry: dict[str, Any] = {
        "arvo_id": task_id,
        "project": task.project,
        "image": docker.image,
        "host_free_bytes_at_start": host_free_bytes(),
        "run1_seed_count": run1.seed_count,
        "run1_attempt_outcomes": [attempt.outcome for attempt in run1.attempts],
        "run1_blocked_attempts": blocked,
        "result": "",
    }
    try:
        prepared = prepare_harness(docker, fields)
        entry.update(
            {
                key: fields.get(key)
                for key in (
                    "image_digest",
                    "workdir",
                    "fuzz_target",
                    "seed_count",
                    "seed_note",
                    "snapshot_image",
                )
            }
        )
        if prepared is None:
            entry["result"] = f"FAILED: {fields.get('detail', 'harness setup failed')}"
            return entry
        workspace, harness = prepared
        baseline_type, _, _ = _crash_fields(harness.baseline)
        control_type, _, _ = _crash_fields(harness.control_poc)
        entry.update(
            baseline_crash_type=baseline_type,
            control_compile=_short(step_run("arvo compile", harness.control_compile)),
            control_poc_crash_type=control_type,
            control_seeds=(
                _short(step_run("fuzz target over the seed corpus", harness.control_seeds))
                if harness.control_seeds is not None
                else None
            ),
            control_seeds_clean=_seeds_clean(harness.control_seeds),
        )
        if not baseline_type or harness.control_compile.exit_code != 0 or not control_type:
            entry["result"] = "FAILED: the control build did not reproduce the crash"
            return entry
        frames, notes, source = build_source(workspace, harness)
        entry.update(
            frames=[frame.model_dump() for frame in frames],
            frame_notes=notes,
            source_chars=len(source),
            run1_frames=[(frame.path, frame.line) for frame in run1.frames],
        )
        texts: dict[str, str | None] = {}

        def original(path: str) -> str | None:
            if path not in texts:
                data = workspace.read(path)
                texts[path] = None if data is None else _decode(data)
            return texts[path]

        proposal: PatchProposal | None = None
        if frames:
            text = original(frames[0].path)
            made = noop_edit(frames[0].path, text, frames[0].line) if text else None
            if made is not None:
                edit, line_range = made
                proposal = PatchProposal(rationale="no-op harness check", edits=[edit])
                entry["noop_edit"] = {"path": edit.path, "lines": line_range}
        if proposal is None:
            entry["result"] = "FAILED: no frame to build a no-op edit from"
            return entry
        attempts: list[dict[str, Any]] = []
        for _ in range(NOOP_ATTEMPTS):
            outcome, detail, measured = apply_and_prove(
                proposal, workspace, original, entry["control_seeds_clean"]
            )
            attempts.append(
                {
                    "outcome": outcome,
                    "detail": detail[:600],
                    "diff": measured.get("diff", ""),
                    "compile": _short(measured.get("compile")),
                    "poc": _short(measured.get("poc")),
                    "poc_crash_type": measured.get("poc_crash_type", ""),
                }
            )
        entry["attempts"] = attempts
        seeds = workspace.seeds() if workspace.seed_count > 0 else None
        entry["attempt_seeds"] = (
            _short(step_run("fuzz target over the seed corpus", seeds)) if seeds else None
        )
        entry["attempt_seeds_clean"] = _seeds_clean(seeds) if seeds else None
        entry["clean_containers"] = workspace.clean_containers
        problems = [
            f"attempt {number}: {item['outcome']}"
            for number, item in enumerate(attempts, start=1)
            if item["outcome"] != "STILL_CRASHES"
            or item["poc_crash_type"] != baseline_type
            or item["diff"]
        ]
        entry["result"] = "OK" if not problems else "FAILED: " + "; ".join(problems)
        return entry
    except Exception as error:
        entry["result"] = f"FAILED: harness error: {type(error).__name__}: {error}"[:600]
        return entry
    finally:
        entry["image_removed"] = docker.remove()
        entry["wall_seconds"] = round(time.perf_counter() - started, 3)


def main() -> int:
    notes = json.loads((ROOT / NOTES_PATH).read_text(encoding="utf-8"))
    blocked = {row["arvo_id"]: row["blocked_attempts"] for row in notes["tasks"]}
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "method": METHOD,
        "code": {
            "head": _git("rev-parse", "HEAD"),
            "uncommitted": _git("status", "--porcelain", "--", "reproof", "eval"),
            "source_sha256": source_sha256(),
        },
        "model_calls": 0,
        "started_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "tasks": [],
    }
    for task_id in TASK_IDS:
        free = host_free_bytes()
        if free is not None and free < MIN_FREE_BYTES:
            raise SystemExit(f"stopped before ARVO {task_id}: {free} bytes of memory free")
        run1 = TaskRecord.model_validate_json(
            (ROOT / CARDS_DIR / f"{task_id}.json").read_text(encoding="utf-8")
        )
        entry = check_task(task_id, run1, blocked[task_id])
        receipt["tasks"].append(entry)
        tasks = receipt["tasks"]
        receipt["finished_at_utc"] = datetime.now(UTC).isoformat(timespec="seconds")
        receipt["totals"] = {
            "images": len(TASK_IDS),
            "checked": len(tasks),
            "ok": sum(task["result"] == "OK" for task in tasks),
            "attempt_compiles": sum(len(task.get("attempts", [])) for task in tasks),
            "attempt_compiles_that_built": sum(
                1
                for task in tasks
                for attempt in task.get("attempts", [])
                if attempt["compile"] and attempt["compile"]["exit_code"] == 0
            ),
            "images_removed": sum(bool(task.get("image_removed")) for task in tasks),
        }
        _write_json(ROOT / RECEIPT_PATH, receipt)
        print(
            f"ARVO {task_id} {entry['result']} wall={entry['wall_seconds']} "
            f"containers={entry.get('clean_containers')} removed={entry['image_removed']}",
            flush=True,
        )
    print(json.dumps(receipt["totals"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
