from __future__ import annotations

from pathlib import Path

from reproof.crash import DIRTY_FIX_DETAIL, ambiguous_vulnerable_detail
from reproof.provenance import derivation_source_sha256
from scripts.refresh_eval_cards import merge_generated_details


def test_derivation_hash_changes_with_refresh_program(tmp_path: Path) -> None:
    original = Path("scripts/refresh_eval_cards.py").read_bytes()
    first = tmp_path / "refresh-first.py"
    second = tmp_path / "refresh-second.py"
    first.write_bytes(original)
    second.write_bytes(original + b"\n# changed test copy\n")
    assert derivation_source_sha256(first) != derivation_source_sha256(second)


def test_refresh_generated_details_are_idempotent_and_replace_stale_values() -> None:
    stale_missing = ambiguous_vulnerable_detail(17)
    stale_recognized = ambiguous_vulnerable_detail(1, "AddressSanitizer")
    current = ambiguous_vulnerable_detail(2, "ThreadSanitizer")
    details = [
        "affected version is missing",
        stale_missing,
        stale_recognized,
        stale_recognized,
        DIRTY_FIX_DETAIL,
    ]

    first = merge_generated_details(details, current, fixed_clean=False)
    second = merge_generated_details(first, current, fixed_clean=False)

    assert first == ["affected version is missing", current, DIRTY_FIX_DETAIL]
    assert second == first
