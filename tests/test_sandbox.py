from __future__ import annotations

from pathlib import Path

from reproof.sandbox import CheckpointRegistry, manifest_digest


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
