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


def test_thread_sanitizer_warning_is_a_measured_crash() -> None:
    log = """WARNING: ThreadSanitizer: data race (pid=7)
  Write of size 4 at 0x1234 by thread T1:
    #0 0x1234 in update_counter /src/demo.c:3:2
SUMMARY: ThreadSanitizer: data race /src/demo.c:3 in update_counter
"""
    parsed = parse_crash(log)
    assert parsed.state == ("update_counter",)
    assert parsed.sanitizer_kind == "ThreadSanitizer"
    assert parsed.crashed
    assert sanitizer_excerpt(parsed).startswith("WARNING: ThreadSanitizer")


def test_undefined_behavior_runtime_error_is_a_measured_crash() -> None:
    log = """/src/demo.c:4:2: runtime error: signed integer overflow
    #0 0x1234 in multiply /src/demo.c:4:2
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/demo.c:4:2 in multiply
"""
    parsed = parse_crash(log)
    assert parsed.state == ("multiply",)
    assert parsed.sanitizer_kind == "UndefinedBehaviorSanitizer"
    assert parsed.crashed
    assert "runtime error: signed integer overflow" in sanitizer_excerpt(parsed)


def test_excerpt_starts_at_matching_sanitizer_header() -> None:
    log = (
        "WARNING: unrelated dependency warning\n"
        + ("x" * 9000)
        + "\n==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
        + "    #0 0x1234 in target /src/demo.c:3:2\n"
        + "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/demo.c:3 in target\n"
    )
    parsed = parse_crash(log)
    excerpt = sanitizer_excerpt(parsed)
    assert excerpt.startswith("==1==ERROR: AddressSanitizer")
    assert "#0 0x1234 in target" in excerpt


@pytest.mark.parametrize(
    "header",
    [
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
        "==1==WARNING: MemorySanitizer: use-of-uninitialized-value",
        "WARNING: ThreadSanitizer: data race (pid=1)",
        "/src/demo.c:4:2: runtime error: signed integer overflow",
    ],
)
def test_header_only_sanitizer_is_not_a_conclusive_crash(header: str) -> None:
    parsed = parse_crash(header)
    assert parsed.state in {(), ("NULL",)}
    assert parsed.sanitizer_kind is not None
    assert not parsed.crashed
    assert sanitizer_excerpt(parsed) == ""


@pytest.mark.parametrize(
    "log",
    [
        """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1234 (/out/fuzzer+0x1234)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/out/fuzzer+0x1234)
""",
        """WARNING: ThreadSanitizer: data race (pid=7)
  Write of size 4 at 0x1234 by thread T1:
    #0 update_counter /src/demo.c:3 (demo+0x1234)
SUMMARY: ThreadSanitizer: data race /src/demo.c:3 in update_counter
""",
    ],
)
def test_clusterfuzz_real_frame_formats_are_conclusive(log: str) -> None:
    parsed = parse_crash(log)
    assert parsed.state
    assert parsed.state != ("NULL",)
    assert parsed.sanitizer_kind is not None
    assert parsed.crashed
    assert "#0" in sanitizer_excerpt(parsed)
