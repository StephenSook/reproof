from __future__ import annotations

from dataclasses import replace
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
    assert parsed.sanitizer_kind == "AddressSanitizer"
    assert parsed.crashed
    assert "ERROR: AddressSanitizer" in sanitizer_excerpt(parsed)


def test_inline_group_uses_same_program_counter() -> None:
    parsed = parse_crash((FIXTURES / "42530604-vul.txt").read_text(encoding="utf-8"))
    assert "jv_number_get_literal" in parsed.inline_groups["jvp_literal_number_literal"]
    assert "jv_dump_term" not in parsed.inline_groups["jvp_literal_number_literal"]


def test_clean_result_requires_zero_exit_and_no_sanitizer() -> None:
    assert looks_clean(0, "ordinary output")
    assert not looks_clean(1, "ordinary output")
    assert not looks_clean(0, "ERROR: AddressSanitizer: failure")
    assert not looks_clean(0, "WARNING: MemorySanitizer: use-of-uninitialized-value")
    assert not looks_clean(0, "demo.c:4:2: runtime error: signed integer overflow")


def test_unknown_clusterfuzz_type_is_still_a_measured_sanitizer_crash() -> None:
    log = """==1==ERROR: AddressSanitizer: unknown-crash on address 0x1
    #0 0x1234 in process_line /src/demo.c:3:2
SUMMARY: AddressSanitizer: unknown-crash /src/demo.c:3 in process_line
"""
    parsed = replace(parse_crash(log), crash_type="UNKNOWN")
    assert parsed.crash_type == "UNKNOWN"
    assert parsed.state == ("process_line",)
    assert parsed.sanitizer_kind == "AddressSanitizer"
    assert parsed.crashed


def test_memory_sanitizer_warning_is_a_measured_crash() -> None:
    log = """==7==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x1234 in DisassociateAlphaRegion /src/demo.c:3:2
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/demo.c:3
"""
    parsed = parse_crash(log)
    assert parsed.crash_type == "Use-of-uninitialized-value"
    assert parsed.state == ("DisassociateAlphaRegion",)
    assert parsed.sanitizer_kind == "MemorySanitizer"
    assert parsed.crashed
    assert sanitizer_excerpt(parsed).startswith("==7==WARNING: MemorySanitizer")
