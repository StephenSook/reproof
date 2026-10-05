from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from reproof.slice import elf_interpreter, measure, patch_interpreter, validated_cached_manifest


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
    assert validated_cached_manifest(tmp_path, **arguments) is None
