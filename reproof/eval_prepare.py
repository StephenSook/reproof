"""Resumable Docker image preparation for the ARVO eval-100 run."""

from __future__ import annotations

import json
import math
import os
import subprocess
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from reproof.arvo import ArvoRepository, ArvoTask
from reproof.eval100 import (
    ARVO10_PROJECTS,
    Eval100InputPaths,
    Eval100PopulationRow,
    Eval100Selection,
    default_eval100_inputs,
    select_eval100,
)
from reproof.slice import extract_runtime_slice, load_cached_runtime_slice

PrepareFailureReason = Literal["pull_error", "slice_exception", "tag_not_removed"]
PrepareStatus = Literal["in_progress", "prepared", "failed"]
ImageKind = Literal["vul", "fix"]
IMAGE_KINDS: tuple[ImageKind, ImageKind] = ("vul", "fix")
DEFAULT_LEDGER = Path("eval/results/eval100_prep.json")


class TaskRepository(Protocol):
    def get(self, local_id: int) -> ArvoTask: ...


SliceExtractor = Callable[[int, str, str, Path], dict[str, Any]]
CacheLoader = Callable[..., dict[str, Any] | None]


class PullError(RuntimeError):
    pass


class SliceError(RuntimeError):
    pass


class TagNotRemovedError(RuntimeError):
    pass


@dataclass(slots=True)
class PreparedImage:
    kind: ImageKind
    image: str
    hub_compressed_bytes: int
    pull_seconds: float
    slice_seconds: float
    slice_bytes: int
    reused_cached_slice: bool
    docker_image_deleted: bool


@dataclass(slots=True)
class PrepareFailure:
    arvo_id: int
    project: str
    kind: ImageKind
    reason: PrepareFailureReason
    error_type: str
    error: str


@dataclass(slots=True)
class PrepareAttempt:
    draw_index: int
    arvo_id: int
    project: str
    status: PrepareStatus
    images: list[PreparedImage] = field(default_factory=list)
    failure: PrepareFailure | None = None


@dataclass(frozen=True, slots=True)
class PrepareSkip:
    draw_index: int
    arvo_id: int
    project: str
    reason: Literal["hub_tag_missing", "over_size_cap", "project_cap"]


@dataclass(slots=True)
class Eval100PrepLedger:
    prereg_sha256: str
    population_fixture_sha256: str
    input_sha256: dict[str, str]
    draw_seed: int
    target_prepared: int
    next_draw_index: int = 0
    attempted: list[PrepareAttempt] = field(default_factory=list)
    prepared: list[int] = field(default_factory=list)
    skipped: list[PrepareSkip] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        failures: dict[str, list[dict[str, Any]]] = {
            "pull_error": [],
            "slice_exception": [],
            "tag_not_removed": [],
        }
        for attempt in self.attempted:
            if attempt.failure is not None:
                failures[attempt.failure.reason].append(asdict(attempt.failure))
        return {
            "schema_version": "1.0",
            "prereg_sha256": self.prereg_sha256,
            "population_fixture_sha256": self.population_fixture_sha256,
            "input_sha256": self.input_sha256,
            "draw_seed": self.draw_seed,
            "target_prepared": self.target_prepared,
            "next_draw_index": self.next_draw_index,
            "attempted": [asdict(attempt) for attempt in self.attempted],
            "prepared": self.prepared,
            "failed_by_reason": failures,
            "skipped": [asdict(item) for item in self.skipped],
        }

    def model_dump_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.model_dump(), indent=indent)


class DockerClient:
    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=False, capture_output=True, text=True)

    @staticmethod
    def _missing(result: subprocess.CompletedProcess[str]) -> bool:
        message = f"{result.stdout}\n{result.stderr}".lower()
        return result.returncode != 0 and (
            "no such image" in message or "no such object" in message
        )

    def pull(self, image: str) -> None:
        result = self._run(["docker", "pull", image])
        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        if output:
            print(output)
        if result.returncode != 0:
            raise PullError(f"docker pull {image} failed with exit {result.returncode}: {output}")

    def ensure_tag_absent(self, image: str) -> None:
        inspection = self._run(["docker", "image", "inspect", image])
        if self._missing(inspection):
            return
        if inspection.returncode != 0:
            raise TagNotRemovedError(
                f"could not inspect {image}: exit {inspection.returncode}: "
                f"{inspection.stderr.strip()}"
            )
        deletion = self._run(["docker", "image", "rm", image])
        if deletion.returncode != 0:
            raise TagNotRemovedError(
                f"could not remove {image}: exit {deletion.returncode}: {deletion.stderr.strip()}"
            )
        remaining = self._run(["docker", "image", "inspect", image])
        if not self._missing(remaining):
            raise TagNotRemovedError(f"Docker image tag still exists after deletion: {image}")


def _atomic_write(path: Path, ledger: Eval100PrepLedger) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        ledger.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _non_negative_float(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{label} must be a number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} must be a number") from error
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return parsed


def _non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _load_image(raw: object) -> PreparedImage:
    if not isinstance(raw, dict):
        raise ValueError("ledger image row must be an object")
    kind = raw.get("kind")
    if kind not in {"vul", "fix"}:
        raise ValueError("ledger image kind must be vul or fix")
    image = raw.get("image")
    if not isinstance(image, str) or not image:
        raise ValueError("ledger image name must be a non-empty string")
    if raw.get("docker_image_deleted") is not True:
        raise ValueError("ledger image must record a deleted Docker tag")
    return PreparedImage(
        kind=kind,
        image=image,
        hub_compressed_bytes=_positive_int(raw.get("hub_compressed_bytes"), "hub_compressed_bytes"),
        pull_seconds=_non_negative_float(raw.get("pull_seconds"), "pull_seconds"),
        slice_seconds=_non_negative_float(raw.get("slice_seconds"), "slice_seconds"),
        slice_bytes=_positive_int(raw.get("slice_bytes"), "slice_bytes"),
        reused_cached_slice=raw.get("reused_cached_slice") is True,
        docker_image_deleted=raw.get("docker_image_deleted") is True,
    )


def _load_failure(raw: object) -> PrepareFailure | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("ledger failure must be an object or null")
    reason = raw.get("reason")
    kind = raw.get("kind")
    if reason not in {"pull_error", "slice_exception", "tag_not_removed"}:
        raise ValueError("ledger failure reason is invalid")
    if kind not in {"vul", "fix"}:
        raise ValueError("ledger failure kind is invalid")
    project = _non_empty_string(raw.get("project"), "ledger failure project")
    error_type = _non_empty_string(raw.get("error_type"), "ledger failure error_type")
    error_text = _non_empty_string(raw.get("error"), "ledger failure error")
    return PrepareFailure(
        arvo_id=_positive_int(raw.get("arvo_id"), "failure arvo_id"),
        project=project,
        kind=kind,
        reason=reason,
        error_type=error_type,
        error=error_text,
    )


def _load_attempt(raw: object) -> PrepareAttempt:
    if not isinstance(raw, dict) or not isinstance(raw.get("images"), list):
        raise ValueError("ledger attempt is invalid")
    status = raw.get("status")
    if status not in {"in_progress", "prepared", "failed"}:
        raise ValueError("ledger attempt status is invalid")
    project = raw.get("project")
    if not isinstance(project, str) or not project:
        raise ValueError("ledger attempt project must be a non-empty string")
    return PrepareAttempt(
        draw_index=_positive_int(raw.get("draw_index"), "attempt draw_index"),
        arvo_id=_positive_int(raw.get("arvo_id"), "attempt arvo_id"),
        project=project,
        status=status,
        images=[_load_image(item) for item in raw["images"]],
        failure=_load_failure(raw.get("failure")),
    )


def _load_skip(raw: object) -> PrepareSkip:
    if not isinstance(raw, dict):
        raise ValueError("ledger skip row must be an object")
    reason = raw.get("reason")
    if reason not in {"hub_tag_missing", "over_size_cap", "project_cap"}:
        raise ValueError("ledger skip reason is invalid")
    project = raw.get("project")
    if not isinstance(project, str) or not project:
        raise ValueError("ledger skip project must be a non-empty string")
    return PrepareSkip(
        draw_index=_positive_int(raw.get("draw_index"), "skip draw_index"),
        arvo_id=_positive_int(raw.get("arvo_id"), "skip arvo_id"),
        project=project,
        reason=reason,
    )


def _load_ledger(path: Path, selection: Eval100Selection) -> Eval100PrepLedger:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != "1.0":
        raise ValueError("prepare ledger schema_version must be 1.0")
    attempted_raw = raw.get("attempted")
    prepared_raw = raw.get("prepared")
    skipped_raw = raw.get("skipped")
    if (
        not isinstance(attempted_raw, list)
        or not isinstance(prepared_raw, list)
        or not isinstance(skipped_raw, list)
    ):
        raise ValueError("prepare ledger arrays are invalid")
    input_sha256 = raw.get("input_sha256")
    if not isinstance(input_sha256, dict):
        raise ValueError("prepare ledger input_sha256 must be an object")
    ledger = Eval100PrepLedger(
        prereg_sha256=str(raw.get("prereg_sha256", "")),
        population_fixture_sha256=str(raw.get("population_fixture_sha256", "")),
        input_sha256=dict(input_sha256),
        draw_seed=_positive_int(raw.get("draw_seed"), "draw_seed"),
        target_prepared=_positive_int(raw.get("target_prepared"), "target_prepared"),
        next_draw_index=_positive_int(raw.get("next_draw_index"), "next_draw_index"),
        attempted=[_load_attempt(item) for item in attempted_raw],
        prepared=[_positive_int(item, "prepared ARVO ID") for item in prepared_raw],
        skipped=[_load_skip(item) for item in skipped_raw],
    )
    expected_identity = (
        selection.prereg_sha256,
        selection.fixture_sha256,
        selection.expected_input_sha256,
        selection.seed,
        selection.target_new_tasks,
    )
    actual_identity = (
        ledger.prereg_sha256,
        ledger.population_fixture_sha256,
        ledger.input_sha256,
        ledger.draw_seed,
        ledger.target_prepared,
    )
    if actual_identity != expected_identity:
        raise ValueError("prepare ledger does not match the registered selection")
    if len(set(ledger.prepared)) != len(ledger.prepared):
        raise ValueError("prepare ledger contains duplicate prepared IDs")
    if ledger.next_draw_index > len(selection.draw_order):
        raise ValueError("prepare ledger next draw index is out of range")
    if ledger.prepared != [item.arvo_id for item in ledger.attempted if item.status == "prepared"]:
        raise ValueError("prepare ledger prepared IDs do not match successful attempts")
    attempted_indices = [item.draw_index for item in ledger.attempted]
    if len(set(attempted_indices)) != len(attempted_indices):
        raise ValueError("prepare ledger contains duplicate attempted draw indices")
    for attempt in ledger.attempted:
        if attempt.draw_index >= len(selection.draw_order):
            raise ValueError("prepare attempt draw index is out of range")
        if selection.draw_order[attempt.draw_index] != attempt.arvo_id:
            raise ValueError("prepare attempt does not match the registered draw order")
        row = selection.population_by_id[attempt.arvo_id]
        if attempt.project != row.project:
            raise ValueError("prepare attempt project differs from the population fixture")
        if attempt.status == "prepared" and (
            [image.kind for image in attempt.images] != ["vul", "fix"]
            or attempt.failure is not None
        ):
            raise ValueError("prepared attempt must have both images and no failure")
        if attempt.status == "failed" and attempt.failure is None:
            raise ValueError("failed attempt must contain a failure row")
        if attempt.status == "in_progress" and attempt.failure is not None:
            raise ValueError("in-progress attempt cannot contain a failure row")
        if attempt.failure is not None and (
            attempt.failure.arvo_id != attempt.arvo_id or attempt.failure.project != attempt.project
        ):
            raise ValueError("prepare failure does not match its attempt")
    skipped_indices: set[int] = set()
    for item in ledger.skipped:
        if item.draw_index >= len(selection.draw_order):
            raise ValueError("prepare skip draw index is out of range")
        if item.draw_index in skipped_indices:
            raise ValueError("prepare ledger contains duplicate skipped draw indices")
        skipped_indices.add(item.draw_index)
        if selection.draw_order[item.draw_index] != item.arvo_id:
            raise ValueError("prepare skip does not match the registered draw order")
        if item.project != selection.population_by_id[item.arvo_id].project:
            raise ValueError("prepare skip project differs from the population fixture")
    completed_attempt_indices = {
        item.draw_index for item in ledger.attempted if item.status != "in_progress"
    }
    in_progress_indices = {
        item.draw_index for item in ledger.attempted if item.status == "in_progress"
    }
    if any(index > ledger.next_draw_index for index in in_progress_indices):
        raise ValueError("prepare ledger has an invalid in-progress draw position")
    if sum(index == ledger.next_draw_index for index in in_progress_indices) > 1:
        raise ValueError("prepare ledger has duplicate current in-progress attempts")
    repairing_indices = {index for index in in_progress_indices if index < ledger.next_draw_index}
    processed_indices = completed_attempt_indices | skipped_indices | repairing_indices
    if processed_indices != set(range(ledger.next_draw_index)):
        raise ValueError("prepare ledger processed draw positions are not contiguous")
    if completed_attempt_indices & skipped_indices:
        raise ValueError("prepare ledger draw position is both attempted and skipped")
    expected_failures = Eval100PrepLedger(
        prereg_sha256=ledger.prereg_sha256,
        population_fixture_sha256=ledger.population_fixture_sha256,
        input_sha256=ledger.input_sha256,
        draw_seed=ledger.draw_seed,
        target_prepared=ledger.target_prepared,
        attempted=ledger.attempted,
    ).model_dump()["failed_by_reason"]
    if raw.get("failed_by_reason") != expected_failures:
        raise ValueError("prepare ledger failed_by_reason does not match attempted failures")
    return ledger


def _manifest_bytes(manifest: dict[str, Any]) -> int:
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("runtime slice manifest contains no files")
    total = 0
    for record in files.values():
        if not isinstance(record, dict):
            raise ValueError("runtime slice manifest file row is invalid")
        patched = record.get("patched")
        if not isinstance(patched, dict):
            raise ValueError("runtime slice manifest file row lacks patched measurements")
        total += _positive_int(patched.get("bytes"), "slice file bytes")
    return total


def _prepare_image(
    task: ArvoTask,
    row: Eval100PopulationRow,
    kind: ImageKind,
    *,
    slices_root: Path,
    docker: DockerClient,
    slice_extractor: SliceExtractor,
    cache_loader: CacheLoader,
    clock: Callable[[], float],
) -> PreparedImage:
    image = f"n132/arvo:{task.local_id}-{kind}"
    destination = slices_root.resolve() / f"{task.local_id}-{kind}"
    compressed_bytes = row.vul_bytes if kind == "vul" else row.fix_bytes
    if compressed_bytes is None:
        raise ValueError(f"{task.local_id}-{kind} has no registered Hub size")
    try:
        cached = cache_loader(
            destination,
            task_id=task.local_id,
            kind=kind,
            image=image,
            fuzz_target=task.fuzz_target,
        )
    except Exception as error:
        raise SliceError(str(error)) from error
    if cached is not None:
        try:
            slice_bytes = _manifest_bytes(cached)
        except ValueError as error:
            raise SliceError(str(error)) from error
        docker.ensure_tag_absent(image)
        return PreparedImage(
            kind=kind,
            image=image,
            hub_compressed_bytes=compressed_bytes,
            pull_seconds=0.0,
            slice_seconds=0.0,
            slice_bytes=slice_bytes,
            reused_cached_slice=True,
            docker_image_deleted=True,
        )

    failure: BaseException | None = None
    manifest: dict[str, Any] | None = None
    pull_started = clock()
    try:
        docker.pull(image)
    except BaseException as error:
        failure = error if not isinstance(error, Exception) else PullError(str(error))
    pull_seconds = round(clock() - pull_started, 6)
    slice_seconds = 0.0
    if failure is None:
        slice_started = clock()
        try:
            manifest = slice_extractor(task.local_id, kind, task.fuzz_target, slices_root)
        except BaseException as error:
            failure = error if not isinstance(error, Exception) else SliceError(str(error))
        slice_seconds = round(clock() - slice_started, 6)
    try:
        docker.ensure_tag_absent(image)
    except Exception as cleanup_error:
        prior = f"; prior error: {type(failure).__name__}: {failure}" if failure else ""
        raise TagNotRemovedError(f"{cleanup_error}{prior}") from cleanup_error
    if failure is not None:
        raise failure
    if manifest is None:
        raise AssertionError("slice extraction returned no manifest")
    try:
        slice_bytes = _manifest_bytes(manifest)
    except ValueError as error:
        raise SliceError(str(error)) from error
    return PreparedImage(
        kind=kind,
        image=image,
        hub_compressed_bytes=compressed_bytes,
        pull_seconds=pull_seconds,
        slice_seconds=slice_seconds,
        slice_bytes=slice_bytes,
        reused_cached_slice=False,
        docker_image_deleted=True,
    )


def _failure_reason(error: Exception) -> PrepareFailureReason:
    if isinstance(error, TagNotRemovedError):
        return "tag_not_removed"
    if isinstance(error, PullError):
        return "pull_error"
    return "slice_exception"


def _new_ledger(selection: Eval100Selection) -> Eval100PrepLedger:
    return Eval100PrepLedger(
        prereg_sha256=selection.prereg_sha256,
        population_fixture_sha256=selection.fixture_sha256,
        input_sha256=selection.expected_input_sha256,
        draw_seed=selection.seed,
        target_prepared=selection.target_new_tasks,
    )


def _record_prepare_failure(
    attempt: PrepareAttempt,
    task_id: int,
    project: str,
    error: PullError | SliceError | TagNotRemovedError,
) -> None:
    failed_kind: ImageKind = "fix" if [image.kind for image in attempt.images] == ["vul"] else "vul"
    attempt.status = "failed"
    attempt.failure = PrepareFailure(
        arvo_id=task_id,
        project=project,
        kind=failed_kind,
        reason=_failure_reason(error),
        error_type=type(error).__name__,
        error=str(error),
    )


def _prepared_prefix_length(
    attempt: PrepareAttempt,
    task: ArvoTask,
    *,
    slices_root: Path,
    cache_loader: CacheLoader,
) -> int:
    valid = 0
    for image in attempt.images:
        cached = cache_loader(
            slices_root.resolve() / f"{task.local_id}-{image.kind}",
            task_id=task.local_id,
            kind=image.kind,
            image=image.image,
            fuzz_target=task.fuzz_target,
        )
        if cached is None:
            break
        try:
            if _manifest_bytes(cached) != image.slice_bytes:
                break
        except ValueError:
            break
        valid += 1
    return valid


def load_eval100_prep_ledger(
    ledger_path: Path,
    selection: Eval100Selection,
) -> Eval100PrepLedger:
    """Load a completed or partial ledger against its exact registered selection."""
    return _load_ledger(ledger_path, selection)


def run_eval_prepare(
    prereg: Path,
    ledger_path: Path = DEFAULT_LEDGER,
    *,
    inputs: Eval100InputPaths | None = None,
    repository: TaskRepository | None = None,
    slices_root: Path = Path("slices"),
    docker: DockerClient | None = None,
    slice_extractor: SliceExtractor = extract_runtime_slice,
    cache_loader: CacheLoader = load_cached_runtime_slice,
    clock: Callable[[], float] = time.perf_counter,
    stop_after_prepared: int | None = None,
) -> Eval100PrepLedger:
    """Prepare registered images in draw order and persist after every state change."""
    actual_inputs = inputs or default_eval100_inputs()
    selection = select_eval100(prereg, inputs=actual_inputs)
    repo = repository or ArvoRepository(actual_inputs.arvo_database)
    docker_client = docker or DockerClient()
    ledger = (
        _load_ledger(ledger_path, selection) if ledger_path.is_file() else _new_ledger(selection)
    )
    if stop_after_prepared is not None and stop_after_prepared < 0:
        raise ValueError("stop_after_prepared must be non-negative")
    stop_at = min(
        selection.target_new_tasks,
        stop_after_prepared if stop_after_prepared is not None else selection.target_new_tasks,
    )
    by_id = selection.population_by_id

    # A persisted row is only prepared while both recorded slice artifacts still
    # validate. Repair a missing or changed suffix before honoring the row.
    for attempt in ledger.attempted:
        is_interrupted_repair = (
            attempt.status == "in_progress" and attempt.draw_index < ledger.next_draw_index
        )
        if attempt.status != "prepared" and not is_interrupted_repair:
            continue
        task = repo.get(attempt.arvo_id)
        prefix = _prepared_prefix_length(
            attempt,
            task,
            slices_root=slices_root,
            cache_loader=cache_loader,
        )
        if attempt.status == "prepared" and prefix == len(attempt.images):
            continue
        attempt.status = "in_progress"
        attempt.failure = None
        del attempt.images[prefix:]
        ledger.prepared = [item.arvo_id for item in ledger.attempted if item.status == "prepared"]
        _atomic_write(ledger_path, ledger)
        try:
            for kind in IMAGE_KINDS:
                if kind in [image.kind for image in attempt.images]:
                    continue
                attempt.images.append(
                    _prepare_image(
                        task,
                        by_id[attempt.arvo_id],
                        kind,
                        slices_root=slices_root,
                        docker=docker_client,
                        slice_extractor=slice_extractor,
                        cache_loader=cache_loader,
                        clock=clock,
                    )
                )
                _atomic_write(ledger_path, ledger)
        except (PullError, SliceError, TagNotRemovedError) as error:
            _record_prepare_failure(attempt, attempt.arvo_id, attempt.project, error)
        else:
            attempt.status = "prepared"
        ledger.prepared = [item.arvo_id for item in ledger.attempted if item.status == "prepared"]
        _atomic_write(ledger_path, ledger)

    project_counts = Counter(ARVO10_PROJECTS[task_id] for task_id in selection.historical_arvo_ids)
    for task_id in ledger.prepared:
        project_counts[by_id[task_id].project] += 1
    attempts_by_index = {attempt.draw_index: attempt for attempt in ledger.attempted}

    while len(ledger.prepared) < stop_at and ledger.next_draw_index < len(selection.draw_order):
        draw_index = ledger.next_draw_index
        task_id = selection.draw_order[draw_index]
        row = by_id[task_id]
        existing = attempts_by_index.get(draw_index)
        if existing is None:
            if project_counts[row.project] >= selection.project_cap:
                ledger.skipped.append(PrepareSkip(draw_index, task_id, row.project, "project_cap"))
                ledger.next_draw_index += 1
                _atomic_write(ledger_path, ledger)
                continue
            if row.vul_bytes is None or row.fix_bytes is None:
                ledger.skipped.append(
                    PrepareSkip(draw_index, task_id, row.project, "hub_tag_missing")
                )
                ledger.next_draw_index += 1
                _atomic_write(ledger_path, ledger)
                continue
            if max(row.vul_bytes, row.fix_bytes) > selection.size_cap_bytes:
                ledger.skipped.append(
                    PrepareSkip(draw_index, task_id, row.project, "over_size_cap")
                )
                ledger.next_draw_index += 1
                _atomic_write(ledger_path, ledger)
                continue
            task = repo.get(task_id)
            if task.project != row.project:
                raise ValueError(f"ARVO task {task_id} project differs from the population fixture")
            attempt = PrepareAttempt(draw_index, task_id, row.project, "in_progress")
            ledger.attempted.append(attempt)
            attempts_by_index[draw_index] = attempt
            _atomic_write(ledger_path, ledger)
        else:
            attempt = existing
            if attempt.status != "in_progress":
                raise ValueError("next draw position is not an in-progress attempt")
            task = repo.get(task_id)

        recorded_kinds = [image.kind for image in attempt.images]
        if recorded_kinds not in ([], ["vul"], ["vul", "fix"]):
            raise ValueError("in-progress attempt has an invalid image sequence")
        try:
            for kind in IMAGE_KINDS:
                if kind in recorded_kinds:
                    image = next(item for item in attempt.images if item.kind == kind)
                    try:
                        cached = cache_loader(
                            slices_root.resolve() / f"{task_id}-{kind}",
                            task_id=task_id,
                            kind=kind,
                            image=image.image,
                            fuzz_target=task.fuzz_target,
                        )
                    except Exception as error:
                        raise SliceError(str(error)) from error
                    if cached is None or _manifest_bytes(cached) != image.slice_bytes:
                        raise ValueError(
                            f"recorded {task_id}-{kind} slice is missing or differs from the ledger"
                        )
                    continue
                prepared_image = _prepare_image(
                    task,
                    row,
                    kind,
                    slices_root=slices_root,
                    docker=docker_client,
                    slice_extractor=slice_extractor,
                    cache_loader=cache_loader,
                    clock=clock,
                )
                attempt.images.append(prepared_image)
                _atomic_write(ledger_path, ledger)
        except (PullError, SliceError, TagNotRemovedError) as error:
            _record_prepare_failure(attempt, task_id, row.project, error)
            ledger.next_draw_index += 1
            _atomic_write(ledger_path, ledger)
            continue
        attempt.status = "prepared"
        ledger.prepared.append(task_id)
        project_counts[row.project] += 1
        ledger.next_draw_index += 1
        _atomic_write(ledger_path, ledger)

    return ledger
