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


def ambiguous_vulnerable_detail(exit_code: int, sanitizer_kind: str | None = None) -> str:
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
    sanitizer_kind: str | None

    @property
    def crashed(self) -> bool:
        return bool(self.state) and self.state != ("NULL",) and self.sanitizer_kind is not None


def _sanitizer_kind(log: str) -> str | None:
    match = SANITIZER_ERROR.search(log)
    if match is None:
        return None
    return match.group("header") or "UndefinedBehaviorSanitizer"


def _frames(log: str) -> list[tuple[str, str, str]]:
    frames: list[tuple[str, str, str]] = []
    for line in log.splitlines():
        match = FRAME_WITH_IN.match(line) or FRAME_MODULE_OFFSET.match(line)
        if match is not None:
            function = re.sub(r"\(.*", "", match.group("function")).strip()
            frames.append((match.group("index"), match.group("pc"), function))
            continue
        match = FRAME_SYMBOL_PATH.match(line)
        if match is not None:
            function = re.sub(r"\(.*", "", match.group("function")).strip()
            frames.append((match.group("index"), f"frame:{match.group('index')}", function))
    return frames


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
    parsed = parser.parse(cleaned)
    crash_type = " ".join(parsed.crash_type.split())
    state = tuple(line.strip() for line in parsed.crash_state.splitlines() if line.strip())
    frames = _frames(cleaned)
    if state == ("NULL",) and frames:
        state = tuple(function for _, _, function in frames[:3])
    return CrashSignature(
        crash_type=crash_type,
        state=state,
        inline_groups=_inline_groups(frames),
        cleaned_log=cleaned,
        sanitizer_kind=_sanitizer_kind(cleaned),
    )


def sanitizer_excerpt(signature: CrashSignature, max_chars: int = 8000) -> str:
    if not signature.crashed:
        return ""
    lines = signature.cleaned_log.splitlines()
    sanitizer_match = SANITIZER_ERROR.search(signature.cleaned_log)
    if sanitizer_match is None:
        return ""
    start = signature.cleaned_log[: sanitizer_match.start()].count("\n")
    end = next(
        (index + 1 for index in range(start, len(lines)) if lines[index].startswith("SUMMARY:")),
        min(len(lines), start + 80),
    )
    excerpt = "\n".join(lines[start:end])
    if len(excerpt) <= max_chars:
        return excerpt
    return excerpt[: max_chars - 24] + "\n[excerpt truncated]\n"


def looks_clean(exit_code: int, combined_output: str) -> bool:
    return exit_code == 0 and not SANITIZER_ERROR.search(ANSI.sub("", combined_output))
