"""Parse sanitizer output with the same ClusterFuzz library used by OSS-Fuzz."""

from __future__ import annotations

import collections
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from clusterfuzz import stacktraces  # type: ignore[import-untyped]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
FRAME_WITH_IN = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?P<pc>0x[0-9a-f]+)\s+in\s+"
    r"(?P<function>.+?)\s+(?:/|\(|[A-Za-z]:)"
)
FRAME_MODULE_OFFSET = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?P<pc>0x[0-9a-f]+)\s+"
    r"\((?P<function>[^+()\s]+)\+0x[0-9a-f]+\)"
)
FRAME_SYMBOL_PATH = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?P<function>\S(?:.*?\S)?)\s+"
    r"(?P<path>(?:[A-Za-z]:)?[/\\]\S+?):\d+(?::\d+)?(?:\s+\(|$)"
)
SANITIZER_ERROR = re.compile(
    r"(?:ERROR|WARNING):\s+(?P<header>AddressSanitizer|LeakSanitizer|MemorySanitizer|"
    r"ThreadSanitizer|UndefinedBehaviorSanitizer)|(?P<ubsan>runtime error:)"
)
DIRTY_FIX_DETAIL = "The fixed build did not exit cleanly; inspect its captured stdout and stderr."
AMBIGUOUS_VULNERABLE_DETAIL_PREFIXES = (
    "The vulnerable build did not produce a recognized sanitizer trace",
    "The vulnerable build produced a recognized ",
)


def ambiguous_vulnerable_detail(
    exit_code: int,
    sanitizer_kind: str | None = None,
    has_usable_frames: bool = False,
) -> str:
    if sanitizer_kind is not None and has_usable_frames:
        return (
            f"The vulnerable build produced a recognized {sanitizer_kind} report with usable "
            f"crash frames, but the sandbox exit code was {exit_code}; inspect its captured "
            "stderr."
        )
    if sanitizer_kind is not None:
        return (
            f"The vulnerable build produced a recognized {sanitizer_kind} report but no usable "
            f"resolved crash frames (exit code {exit_code}); inspect its captured stdout and "
            "stderr."
        )
    return (
        "The vulnerable build did not produce a recognized sanitizer trace and did not "
        f"complete cleanly (exit code {exit_code}); inspect its captured stdout and stderr."
    )


@dataclass(frozen=True, slots=True)
class CrashSignature:
    crash_type: str
    state: tuple[str, ...]
    inline_groups: Mapping[str, frozenset[str]]
    cleaned_log: str
    sanitizer_report: str
    sanitizer_kind: str | None

    @property
    def crashed(self) -> bool:
        return (
            bool(self.state)
            and self.state != ("NULL",)
            and bool(self.inline_groups)
            and self.sanitizer_kind is not None
        )


def is_conclusive_crash(exit_code: int, signature: CrashSignature) -> bool:
    return exit_code != 0 and signature.crashed


def _sanitizer_kind(log: str) -> str | None:
    match = SANITIZER_ERROR.search(log)
    if match is None:
        return None
    return match.group("header") or "UndefinedBehaviorSanitizer"


def _frames(log: str) -> list[tuple[str, str, str]]:
    frames: list[tuple[str, str, str]] = []
    first_stack_seen = False
    for line in log.splitlines():
        match = FRAME_WITH_IN.match(line) or FRAME_MODULE_OFFSET.match(line)
        if match is not None:
            if match.group("index") == "0":
                if first_stack_seen:
                    break
                first_stack_seen = True
            function = re.sub(r"\(.*", "", match.group("function")).strip()
            frames.append((match.group("index"), match.group("pc"), function))
            continue
        match = FRAME_SYMBOL_PATH.match(line)
        if match is not None:
            if match.group("index") == "0":
                if first_stack_seen:
                    break
                first_stack_seen = True
            function = re.sub(r"\(.*", "", match.group("function")).strip()
            frames.append((match.group("index"), f"frame:{match.group('index')}", function))
    return frames


def _sanitizer_segments(log: str) -> list[str]:
    lines = log.splitlines()
    starts = sorted({log[: match.start()].count("\n") for match in SANITIZER_ERROR.finditer(log)})
    segments: list[str] = []
    for position, start in enumerate(starts):
        limit = starts[position + 1] if position + 1 < len(starts) else len(lines)
        end = next(
            (index + 1 for index in range(start, limit) if lines[index].startswith("SUMMARY:")),
            min(limit, start + 80),
        )
        segments.append("\n".join(lines[start:end]))
    return segments


def _inline_groups(frames: list[tuple[str, str, str]]) -> Mapping[str, frozenset[str]]:
    by_pc: dict[str, list[str]] = collections.defaultdict(list)
    first_stack_seen = False
    for index, pc, function in frames:
        if index == "0":
            if first_stack_seen:
                break
            first_stack_seen = True
        by_pc[pc].append(function)
    groups: dict[str, frozenset[str]] = {}
    for functions in by_pc.values():
        siblings = frozenset(functions)
        for function in functions:
            groups[function] = siblings
    return MappingProxyType(groups)


def parse_crash(log: str) -> CrashSignature:
    cleaned = ANSI.sub("", log)
    parser = stacktraces.StackParser(
        symbolized=True,
        detect_ooms_and_hangs=True,
        include_ubsan=True,
    )
    segments = _sanitizer_segments(cleaned)
    for segment in segments:
        parsed = parser.parse(segment)
        crash_type = " ".join(parsed.crash_type.split())
        state = tuple(line.strip() for line in parsed.crash_state.splitlines() if line.strip())
        frames = _frames(segment)
        inline_groups = _inline_groups(frames)
        if frames and (state == ("NULL",) or not any(frame in inline_groups for frame in state)):
            state = tuple(function for _, _, function in frames[:3])
        signature = CrashSignature(
            crash_type=crash_type,
            state=state,
            inline_groups=inline_groups,
            cleaned_log=cleaned,
            sanitizer_report=segment,
            sanitizer_kind=_sanitizer_kind(segment),
        )
        if signature.crashed:
            return signature

    parsed = parser.parse(cleaned)
    crash_type = " ".join(parsed.crash_type.split())
    state = tuple(line.strip() for line in parsed.crash_state.splitlines() if line.strip())
    report = segments[0] if segments else ""
    return CrashSignature(
        crash_type=crash_type,
        state=state,
        inline_groups=MappingProxyType({}),
        cleaned_log=cleaned,
        sanitizer_report=report,
        sanitizer_kind=_sanitizer_kind(report),
    )


def sanitizer_excerpt(signature: CrashSignature, max_chars: int = 8000) -> str:
    if not signature.crashed:
        return ""
    excerpt = signature.sanitizer_report
    if len(excerpt) <= max_chars:
        return excerpt
    return excerpt[: max_chars - 24] + "\n[excerpt truncated]\n"


def looks_clean(exit_code: int, combined_output: str) -> bool:
    return exit_code == 0 and not SANITIZER_ERROR.search(ANSI.sub("", combined_output))
