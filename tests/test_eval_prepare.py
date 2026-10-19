from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import reproof.eval_prepare as prepare_module
from reproof.cli import build_parser
from reproof.eval100 import (
    Eval100InputPaths,
    Eval100PopulationRow,
    Eval100Selection,
)
from reproof.eval_prepare import DockerClient, run_eval_prepare


def _manifest(size: int) -> dict[str, Any]:
    return {
        "files": {
            "/out/target": {
                "patched": {"bytes": size, "sha256": "0" * 64},
            }
        }
    }


def _selection(tmp_path: Path, rows: list[Eval100PopulationRow]) -> Eval100Selection:
    return Eval100Selection(
        prereg_path=tmp_path / "prereg.json",
        prereg_sha256="a" * 64,
        fixture_path=tmp_path / "fixture.tsv",
        fixture_sha256="b" * 64,
        expected_input_sha256={
            "arvo_database": "c" * 64,
            "osv_archive": "d" * 64,
            "monorail_mapping": "e" * 64,
        },
        seed=20261019,
        size_cap_bytes=100,
        project_cap=1,
        target_new_tasks=1,
        historical_arvo_ids=(),
        draw_order=tuple(row.arvo_id for row in rows),
        population=tuple(rows),
        selected_new_arvo_ids=(rows[0].arvo_id,),
        skipped={},
        walked=1,
    )


def _row(task_id: int, project: str = "alpha") -> Eval100PopulationRow:
    return Eval100PopulationRow(
        arvo_id=task_id,
        project=project,
        crash_type="Heap-buffer-overflow READ 1",
        family="Heap-buffer-overflow",
        vul_bytes=10,
        fix_bytes=11,
        vul_last_updated="2026-10-19T00:00:00Z",
        fix_last_updated="2026-10-19T00:00:00Z",
        fetch_date="2026-10-19",
    )


class FakeDocker(DockerClient):
    def __init__(self, events: list[str], *, fail_pull: set[str] | None = None) -> None:
        self.events = events
        self.fail_pull = fail_pull or set()
        self.present: set[str] = set()
        self.refuse_remove: set[str] = set()

    def pull(self, image: str) -> None:
        self.events.append(f"pull:{image}")
        if image in self.fail_pull:
            raise prepare_module.PullError("scripted pull failure")
        self.present.add(image)

    def ensure_tag_absent(self, image: str) -> None:
        self.events.append(f"untag:{image}")
        if image in self.refuse_remove:
            raise prepare_module.TagNotRemovedError("scripted tag remains")
        self.present.discard(image)


class FakeRepository:
    def __init__(self, rows: list[Eval100PopulationRow]) -> None:
        self.rows = {row.arvo_id: row for row in rows}

    def get(self, task_id: int) -> Any:
        row = self.rows[task_id]
        return SimpleNamespace(local_id=task_id, project=row.project, fuzz_target="target")


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    rows: list[Eval100PopulationRow],
    docker: FakeDocker,
    extractor: Any,
    *,
    cache_loader: Any | None = None,
    clock: Any | None = None,
    ledger: Path | None = None,
) -> Any:
    selection = _selection(tmp_path, rows)
    monkeypatch.setattr(prepare_module, "select_eval100", lambda *_args, **_kwargs: selection)
    inputs = Eval100InputPaths(tmp_path / "db", tmp_path / "osv", tmp_path / "mapping")
    return run_eval_prepare(
        selection.prereg_path,
        ledger or tmp_path / "ledger.json",
        inputs=inputs,
        repository=FakeRepository(rows),
        slices_root=tmp_path / "slices",
        docker=docker,
        slice_extractor=extractor,
        cache_loader=cache_loader or (lambda *_args, **_kwargs: None),
        clock=clock
        or iter(
            [0.0, 1.0, 1.0, 3.0, 3.0, 4.5, 4.5, 7.5] + [float(value) for value in range(8, 100)]
        ).__next__,
    )


def test_prepare_processes_each_image_fully_and_records_measurements(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    docker = FakeDocker(events)

    def extract(task_id: int, kind: str, _target: str, _root: Path) -> dict[str, Any]:
        events.append(f"slice:{task_id}-{kind}")
        return _manifest(12 if kind == "vul" else 14)

    ledger = _run(monkeypatch, tmp_path, [_row(1)], docker, extract)
    assert events == [
        "pull:n132/arvo:1-vul",
        "slice:1-vul",
        "untag:n132/arvo:1-vul",
        "pull:n132/arvo:1-fix",
        "slice:1-fix",
        "untag:n132/arvo:1-fix",
    ]
    assert ledger.prepared == [1]
    assert [image.hub_compressed_bytes for image in ledger.attempted[0].images] == [10, 11]
    assert [image.pull_seconds for image in ledger.attempted[0].images] == [1.0, 1.5]
    assert [image.slice_seconds for image in ledger.attempted[0].images] == [2.0, 3.0]
    assert [image.slice_bytes for image in ledger.attempted[0].images] == [12, 14]


def test_pull_failure_is_recorded_and_does_not_consume_the_project_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1), _row(2)]
    events: list[str] = []
    docker = FakeDocker(events, fail_pull={"n132/arvo:1-vul"})
    ledger = _run(monkeypatch, tmp_path, rows, docker, lambda *_args: _manifest(4))
    assert ledger.prepared == [2]
    assert ledger.attempted[0].failure is not None
    assert ledger.attempted[0].failure.reason == "pull_error"
    assert ledger.model_dump()["failed_by_reason"]["pull_error"][0]["arvo_id"] == 1


def test_slice_failure_still_removes_the_tag_and_walks_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1), _row(2, "beta")]
    events: list[str] = []
    docker = FakeDocker(events)

    def extract(task_id: int, _kind: str, _target: str, _root: Path) -> dict[str, Any]:
        if task_id == 1:
            raise RuntimeError("scripted slice failure")
        return _manifest(4)

    ledger = _run(monkeypatch, tmp_path, rows, docker, extract)
    assert "untag:n132/arvo:1-vul" in events
    assert ledger.attempted[0].failure is not None
    assert ledger.attempted[0].failure.reason == "slice_exception"
    assert ledger.prepared == [2]


def test_tag_removal_failure_prevents_preparation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    docker = FakeDocker(events)
    docker.refuse_remove.add("n132/arvo:1-vul")
    ledger = _run(monkeypatch, tmp_path, [_row(1)], docker, lambda *_args: _manifest(4))
    assert ledger.prepared == []
    assert ledger.attempted[0].failure is not None
    assert ledger.attempted[0].failure.reason == "tag_not_removed"


def test_resume_validates_the_first_image_without_repeating_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1)]
    ledger_path = tmp_path / "ledger.json"
    events: list[str] = []
    first_docker = FakeDocker(events)

    def interrupted(_task_id: int, kind: str, _target: str, _root: Path) -> dict[str, Any]:
        if kind == "fix":
            raise KeyboardInterrupt
        return _manifest(12)

    with pytest.raises(KeyboardInterrupt):
        _run(
            monkeypatch,
            tmp_path,
            rows,
            first_docker,
            interrupted,
            ledger=ledger_path,
        )
    saved = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert [row["kind"] for row in saved["attempted"][0]["images"]] == ["vul"]
    assert "untag:n132/arvo:1-fix" in events

    second_events: list[str] = []
    second_docker = FakeDocker(second_events)

    def cached(_path: Path, **kwargs: Any) -> dict[str, Any] | None:
        return _manifest(12) if kwargs["kind"] == "vul" else None

    resumed = _run(
        monkeypatch,
        tmp_path,
        rows,
        second_docker,
        lambda *_args: _manifest(14),
        cache_loader=cached,
        ledger=ledger_path,
    )
    assert resumed.prepared == [1]
    assert all("1-vul" not in event for event in second_events)
    assert second_events[0] == "pull:n132/arvo:1-fix"


def test_fully_prepared_task_is_not_repeated_on_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1)]
    ledger_path = tmp_path / "ledger.json"
    _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker([]),
        lambda *_args: _manifest(4),
        ledger=ledger_path,
    )
    events: list[str] = []
    resumed = _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker(events),
        lambda *_args: pytest.fail("prepared task was sliced again"),
        cache_loader=lambda *_args, **_kwargs: _manifest(4),
        ledger=ledger_path,
    )
    assert resumed.prepared == [1]
    assert events == []
    assert not ledger_path.with_suffix(".json.tmp").exists()


def test_resume_repairs_a_missing_slice_before_honoring_prepared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1)]
    ledger_path = tmp_path / "ledger.json"
    _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker([]),
        lambda *_args: _manifest(4),
        ledger=ledger_path,
    )
    events: list[str] = []
    resumed = _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker(events),
        lambda *_args: _manifest(4),
        cache_loader=lambda *_args, **_kwargs: None,
        ledger=ledger_path,
    )
    assert resumed.prepared == [1]
    assert events == [
        "pull:n132/arvo:1-vul",
        "untag:n132/arvo:1-vul",
        "pull:n132/arvo:1-fix",
        "untag:n132/arvo:1-fix",
    ]


def test_interrupted_slice_repair_resumes_from_its_valid_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1)]
    ledger_path = tmp_path / "ledger.json"
    _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker([]),
        lambda *_args: _manifest(4),
        ledger=ledger_path,
    )

    def interrupted(_task_id: int, kind: str, _target: str, _root: Path) -> dict[str, Any]:
        if kind == "fix":
            raise KeyboardInterrupt
        return _manifest(4)

    with pytest.raises(KeyboardInterrupt):
        _run(
            monkeypatch,
            tmp_path,
            rows,
            FakeDocker([]),
            interrupted,
            cache_loader=lambda *_args, **_kwargs: None,
            ledger=ledger_path,
        )
    saved = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert saved["attempted"][0]["status"] == "in_progress"
    assert [row["kind"] for row in saved["attempted"][0]["images"]] == ["vul"]

    events: list[str] = []

    def cached(_path: Path, **kwargs: Any) -> dict[str, Any] | None:
        return _manifest(4) if kwargs["kind"] == "vul" else None

    resumed = _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker(events),
        lambda *_args: _manifest(4),
        cache_loader=cached,
        ledger=ledger_path,
    )
    assert resumed.prepared == [1]
    assert events == ["pull:n132/arvo:1-fix", "untag:n132/arvo:1-fix"]


def test_resume_finalizes_two_images_persisted_before_status_update(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1)]
    ledger_path = tmp_path / "ledger.json"
    original_write = prepare_module._atomic_write

    def interrupt_after_second_image(path: Path, ledger: Any) -> None:
        original_write(path, ledger)
        attempt = ledger.attempted[0] if ledger.attempted else None
        if attempt is not None and attempt.status == "in_progress" and len(attempt.images) == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(prepare_module, "_atomic_write", interrupt_after_second_image)
    with pytest.raises(KeyboardInterrupt):
        _run(
            monkeypatch,
            tmp_path,
            rows,
            FakeDocker([]),
            lambda *_args: _manifest(4),
            ledger=ledger_path,
        )
    saved = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert saved["attempted"][0]["status"] == "in_progress"
    assert [row["kind"] for row in saved["attempted"][0]["images"]] == ["vul", "fix"]

    monkeypatch.setattr(prepare_module, "_atomic_write", original_write)
    events: list[str] = []
    resumed = _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker(events),
        lambda *_args: pytest.fail("persisted slices were repeated"),
        cache_loader=lambda *_args, **_kwargs: _manifest(4),
        ledger=ledger_path,
    )
    assert resumed.prepared == [1]
    assert events == []


def test_cached_slice_still_removes_a_matching_docker_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    docker = FakeDocker(events)

    def cached(_path: Path, **_kwargs: Any) -> dict[str, Any]:
        return _manifest(4)

    ledger = _run(
        monkeypatch,
        tmp_path,
        [_row(1)],
        docker,
        lambda *_args: pytest.fail("cached task was sliced again"),
        cache_loader=cached,
    )
    assert ledger.prepared == [1]
    assert events == ["untag:n132/arvo:1-vul", "untag:n132/arvo:1-fix"]
    assert all(image.reused_cached_slice for image in ledger.attempted[0].images)


def test_resume_refuses_a_ledger_from_another_preregistration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1)]
    ledger_path = tmp_path / "ledger.json"
    docker = FakeDocker([])
    _run(monkeypatch, tmp_path, rows, docker, lambda *_args: _manifest(4), ledger=ledger_path)
    raw = json.loads(ledger_path.read_text(encoding="utf-8"))
    raw["prereg_sha256"] = "f" * 64
    ledger_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match the registered selection"):
        _run(
            monkeypatch,
            tmp_path,
            rows,
            FakeDocker([]),
            lambda *_args: _manifest(4),
            ledger=ledger_path,
        )


def test_resume_refuses_noncontiguous_draw_positions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rows = [_row(1), _row(2, "beta")]
    ledger_path = tmp_path / "ledger.json"
    _run(
        monkeypatch,
        tmp_path,
        rows,
        FakeDocker([]),
        lambda *_args: _manifest(4),
        ledger=ledger_path,
    )
    raw = json.loads(ledger_path.read_text(encoding="utf-8"))
    raw["next_draw_index"] = 2
    ledger_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="not contiguous"):
        _run(
            monkeypatch,
            tmp_path,
            rows,
            FakeDocker([]),
            lambda *_args: _manifest(4),
            ledger=ledger_path,
        )


def test_cli_parses_the_bounded_prepare_command() -> None:
    args = build_parser().parse_args(
        [
            "eval-prepare",
            "--prereg",
            "eval/eval100_prereg.json",
            "--ledger",
            "eval/results/eval100_prep.json",
            "--stop-after-prepared",
            "2",
        ]
    )
    assert args.command == "eval-prepare"
    assert args.stop_after_prepared == 2
