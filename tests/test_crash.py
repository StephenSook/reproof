from __future__ import annotations

from pathlib import Path

import pytest

from reproof.crash import looks_clean, parse_crash, sanitizer_excerpt

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("name", "crash_type", "state"),
    [
        (
            "42530604-vul.txt",
            "Heap-buffer-overflow WRITE 1",
            ("decToString", "decNumberToString", "jvp_literal_number_literal"),
        ),
        (
            "42507851-vul.txt",
            "Heap-buffer-overflow READ 2",
            ("strtol", "parse_primitive", "plist_from_json"),
        ),
        (
            "42496387-vul.txt",
            "Heap-use-after-free READ 8",
            ("ForEachModule", "Runtime_Release", "m3_FreeRuntime"),
        ),
    ],
)
def test_parse_spike_logs(name: str, crash_type: str, state: tuple[str, ...]) -> None:
    parsed = parse_crash((FIXTURES / name).read_text(encoding="utf-8"))
    assert parsed.crash_type == crash_type
    assert parsed.state == state
    assert "ERROR: AddressSanitizer" in sanitizer_excerpt(parsed)


def test_inline_group_uses_same_program_counter() -> None:
    parsed = parse_crash((FIXTURES / "42530604-vul.txt").read_text(encoding="utf-8"))
    assert "jv_number_get_literal" in parsed.inline_groups["jvp_literal_number_literal"]
    assert "jv_dump_term" not in parsed.inline_groups["jvp_literal_number_literal"]


def test_clean_result_requires_zero_exit_and_no_sanitizer() -> None:
    assert looks_clean(0, "ordinary output")
    assert not looks_clean(1, "ordinary output")
    assert not looks_clean(0, "ERROR: AddressSanitizer: failure")
