from __future__ import annotations

from pathlib import Path

from reproof.provenance import derivation_source_sha256


def test_derivation_hash_changes_with_refresh_program(tmp_path: Path) -> None:
    original = Path("scripts/refresh_eval_cards.py").read_bytes()
    first = tmp_path / "refresh-first.py"
    second = tmp_path / "refresh-second.py"
    first.write_bytes(original)
    second.write_bytes(original + b"\n# changed test copy\n")
    assert derivation_source_sha256(first) != derivation_source_sha256(second)
