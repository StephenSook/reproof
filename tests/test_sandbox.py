from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from contree_sdk.sdk.exceptions import NotFoundError

from reproof.sandbox import (
    CheckpointError,
    CheckpointRegistry,
    SandboxPairError,
    SandboxRunner,
    manifest_digest,
)


def test_checkpoint_registry_round_trip(tmp_path: Path) -> None:
    registry = CheckpointRegistry(tmp_path / "checkpoints.json")
    value = {"1:vul:hash": {"checkpoint_uuid": "uuid", "tag": "tag"}}
    registry.write(value)
    assert registry.read() == value


def test_manifest_digest_changes_with_manifest(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text('{"value":1}', encoding="utf-8")
    first = manifest_digest(tmp_path)
    (tmp_path / "manifest.json").write_text('{"value":2}', encoding="utf-8")
    assert manifest_digest(tmp_path) != first


def test_checkpoint_cache_does_not_hide_transport_failure(tmp_path: Path) -> None:
    slice_dir = tmp_path / "slice"
    slice_dir.mkdir()
    (slice_dir / "manifest.json").write_text('{"files":{}}', encoding="utf-8")
    digest = manifest_digest(slice_dir)
    registry = CheckpointRegistry(tmp_path / "checkpoints.json")
    registry.write(
        {
            f"1:vul:{digest}": {
                "checkpoint_uuid": "checkpoint-test",
                "create_operation_uuid": "operation-test",
            }
        }
    )

    class FailingImages:
        def use(self, _reference: str, *, strict: bool) -> None:
            assert strict
            raise RuntimeError("transport failed")

    class FailingClient:
        images = FailingImages()

    runner = SandboxRunner(client=FailingClient(), registry=registry)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="transport failed"):
        runner.ensure_checkpoint(1, "vul", slice_dir)
    assert registry.read()[f"1:vul:{digest}"]["checkpoint_uuid"] == "checkpoint-test"


def test_stale_checkpoint_cleanup_failure_preserves_cached_ids(tmp_path: Path) -> None:
    slice_dir = tmp_path / "slice"
    slice_dir.mkdir()
    (slice_dir / "manifest.json").write_text('{"files":{}}', encoding="utf-8")
    digest = manifest_digest(slice_dir)
    key = f"1:vul:{digest}"

    class FailingRegistry:
        def read(self) -> dict[str, dict[str, object]]:
            return {
                key: {
                    "checkpoint_uuid": "checkpoint-stale",
                    "create_operation_uuid": "checkpoint-operation-stale",
                }
            }

        def write(self, _value: dict[str, dict[str, object]]) -> None:
            raise OSError("disk full")

    class MissingImages:
        def use(self, _reference: str, *, strict: bool) -> None:
            assert strict
            error = NotFoundError(error="missing")
            error.request_id = "request-lookup"
            raise error

    runner = SandboxRunner(
        client=SimpleNamespace(images=MissingImages()),
        registry=FailingRegistry(),  # type: ignore[arg-type]
    )
    with pytest.raises(CheckpointError, match="registry cleanup failed") as captured:
        runner.ensure_checkpoint(1, "vul", slice_dir)

    error = captured.value
    assert error.checkpoint_operation_uuids == {"vul": "checkpoint-operation-stale"}
    assert error.checkpoint_uuids == {"vul": "checkpoint-stale"}
    assert error.request_ids == ["request-lookup"]


def test_pair_error_exposes_all_recovered_ids() -> None:
    error = SandboxPairError(
        "failed",
        operation_uuids={"vul": "operation-vul", "fix": "operation-fix"},
        checkpoint_uuids={"vul": "checkpoint-vul", "fix": "checkpoint-fix"},
        checkpoint_operation_uuids={
            "vul": "checkpoint-operation-vul",
            "fix": "checkpoint-operation-fix",
        },
        request_ids=["request-vul", "request-fix"],
    )
    assert error.operation_uuids == {
        "vul": "operation-vul",
        "fix": "operation-fix",
    }
    assert error.checkpoint_uuids["fix"] == "checkpoint-fix"
    assert error.checkpoint_operation_uuids["vul"] == "checkpoint-operation-vul"
    assert error.request_id == "request-vul"
    assert error.request_ids == ["request-vul", "request-fix"]


def test_checkpoint_error_exposes_creation_operation() -> None:
    error = CheckpointError(
        "failed",
        kind="vul",
        operation_uuid="checkpoint-operation-vul",
        checkpoint_uuid="checkpoint-vul",
        request_id="request-vul",
    )
    assert error.operation_uuid == "checkpoint-operation-vul"
    assert error.checkpoint_operation_uuids == {"vul": "checkpoint-operation-vul"}
    assert error.checkpoint_uuids == {"vul": "checkpoint-vul"}
    assert error.request_ids == ["request-vul"]


def test_checkpoint_registry_failure_preserves_creation_ids(tmp_path: Path) -> None:
    slice_dir = tmp_path / "slice"
    slice_dir.mkdir()
    (slice_dir / "manifest.json").write_text('{"files":{}}', encoding="utf-8")

    class FailingRegistry:
        def read(self) -> dict[str, object]:
            return {}

        def write(self, _value: dict[str, object]) -> None:
            raise OSError("disk full")

    class Internal:
        async def _start_operation(self, _request: object) -> str:
            return "checkpoint-operation-vul"

    class Checkpoint:
        uuid = "checkpoint-vul"
        result = SimpleNamespace(cost=0.25)

        def tag_as(self, _tag: str) -> Checkpoint:
            return self

    class Base:
        client = Internal()

        def apply_files(self, _files: dict[str, object]) -> Checkpoint:
            asyncio.run(self.client._start_operation(object()))
            return Checkpoint()

    class Images:
        def use(self, _reference: str, *, strict: bool) -> Base:
            assert strict
            return Base()

    runner = SandboxRunner(
        client=SimpleNamespace(images=Images()),
        registry=FailingRegistry(),  # type: ignore[arg-type]
    )
    with pytest.raises(CheckpointError, match="registry persistence failed") as captured:
        runner.ensure_checkpoint(1, "vul", slice_dir)

    error = captured.value
    assert error.operation_uuid == "checkpoint-operation-vul"
    assert error.checkpoint_uuids == {"vul": "checkpoint-vul"}


def test_parallel_failure_collects_both_branch_ids() -> None:
    class WaitError(RuntimeError):
        def __init__(self, kind: str) -> None:
            super().__init__(f"{kind} failed")
            self.operation_uuid = f"operation-{kind}"
            self.request_id = f"request-{kind}"

    class Prepared:
        def __init__(self, kind: str) -> None:
            self.kind = kind

        def wait(self) -> None:
            raise WaitError(self.kind)

    class Internal:
        async def _start_operation(self, _request: object) -> str:
            return "unused"

    class Checkpoint:
        def __init__(self, kind: str, internal: Internal) -> None:
            self.kind = kind
            self.uuid = f"checkpoint-{kind}"
            self.client = internal

        def run(self, *_args: object, **_kwargs: object) -> Prepared:
            return Prepared(self.kind)

    internal = Internal()
    vulnerable = Checkpoint("vul", internal)
    fixed = Checkpoint("fix", internal)
    runner = SandboxRunner(client=SimpleNamespace())  # type: ignore[arg-type]
    runner.checkpoint_metadata = {
        "checkpoint-vul": {"operation_uuid": "checkpoint-operation-vul"},
        "checkpoint-fix": {"operation_uuid": "checkpoint-operation-fix"},
    }

    with pytest.raises(SandboxPairError) as captured:
        runner.run_pair(1, vulnerable, fixed)

    error = captured.value
    assert error.operation_uuids == {
        "vul": "operation-vul",
        "fix": "operation-fix",
    }
    assert error.checkpoint_operation_uuids == {
        "vul": "checkpoint-operation-vul",
        "fix": "checkpoint-operation-fix",
    }
    assert set(error.request_ids) == {"request-vul", "request-fix"}
