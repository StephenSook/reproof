from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

import reproof.slice as slice_module
from reproof.slice import (
    _ensure_image_tag_removed,
    elf_interpreter,
    measure,
    patch_interpreter,
    validated_cached_manifest,
)


def test_pt_interp_patch_preserves_size_and_changes_only_interpreter(tmp_path: Path) -> None:
    source = Path(__file__).parent / "fixtures" / "elf_interp_fixture"
    binary = tmp_path / "fixture"
    binary.write_bytes(source.read_bytes())
    before = measure(binary)
    old = elf_interpreter(binary)

    reported_old, reported_new = patch_interpreter(binary, "/arvo/ld.so")

    after = measure(binary)
    assert reported_old == old
    assert reported_new == "/arvo/ld.so"
    assert elf_interpreter(binary) == "/arvo/ld.so"
    assert before.bytes == after.bytes
    assert before.sha256 != after.sha256
    assert old.encode() + b"\0" not in binary.read_bytes()


def test_cached_slice_requires_matching_bytes_and_deleted_image_tag(tmp_path: Path) -> None:
    payload = tmp_path / "out" / "target"
    payload.parent.mkdir()
    payload.write_bytes(b"measured bytes")
    record = asdict(measure(payload))
    manifest = {
        "task_id": 1,
        "kind": "vul",
        "image": "n132/arvo:1-vul",
        "fuzz_target": "target",
        "docker_image_deleted": True,
        "files": {
            "/out/target": {
                "relative_path": "out/target",
                "patched": record,
            }
        },
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    arguments = {
        "task_id": 1,
        "kind": "vul",
        "image": "n132/arvo:1-vul",
        "fuzz_target": "target",
    }
    assert validated_cached_manifest(tmp_path, **arguments) == manifest

    payload.write_bytes(b"changed bytes")
    assert validated_cached_manifest(tmp_path, **arguments) is None

    payload.write_bytes(b"measured bytes")
    manifest["docker_image_deleted"] = False
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert validated_cached_manifest(tmp_path, **arguments) == manifest


def test_image_tag_state_is_only_clean_after_absence_is_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest = {"docker_image_deleted": False}
    responses = iter(
        [
            SimpleNamespace(returncode=0, stdout="present", stderr=""),
            SimpleNamespace(returncode=0, stdout="removed", stderr=""),
            SimpleNamespace(returncode=0, stdout="still present", stderr=""),
        ]
    )
    monkeypatch.setattr(slice_module, "_run", lambda *_args, **_kwargs: next(responses))

    with pytest.raises(RuntimeError, match="still exists"):
        _ensure_image_tag_removed("n132/arvo:1-vul", manifest, manifest_path)

    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert saved["docker_image_deleted"] is False
    assert saved["docker_image_delete_error"]["stderr"] == "image tag still exists"
