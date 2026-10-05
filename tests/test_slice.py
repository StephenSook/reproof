from __future__ import annotations

from pathlib import Path

from reproof.slice import elf_interpreter, measure, patch_interpreter


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
