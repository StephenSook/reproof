from __future__ import annotations

from pathlib import Path

import pytest

from reproof.sandbox import CheckpointRegistry, SandboxPairError, SandboxRunner, manifest_digest


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


def test_pair_error_exposes_all_recovered_ids() -> None:
    error = SandboxPairError(
        "failed",
        operation_uuids={"vul": "operation-vul", "fix": "operation-fix"},
        checkpoint_uuids={"vul": "checkpoint-vul", "fix": "checkpoint-fix"},
        request_id="request-test",
    )
    assert error.operation_uuids == {
        "vul": "operation-vul",
        "fix": "operation-fix",
    }
    assert error.checkpoint_uuids["fix"] == "checkpoint-fix"
    assert error.request_id == "request-test"
