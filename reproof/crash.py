"""Parse sanitizer output with the same ClusterFuzz library used by OSS-Fuzz."""

from __future__ import annotations

import collections
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from clusterfuzz import stacktraces  # type: ignore[import-untyped]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
FRAME = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-f]+)\s+in\s+(.+?)\s+(?:/|\(|[A-Za-z]:)", re.M)
SANITIZER_ERROR = re.compile(
    r"(?:ERROR|WARNING):\s+(?P<header>AddressSanitizer|LeakSanitizer|MemorySanitizer|"
    r"ThreadSanitizer|UndefinedBehaviorSanitizer)|(?P<ubsan>runtime error:)"
)
DIRTY_FIX_DETAIL = "The fixed build did not exit cleanly; inspect its captured stdout and stderr."


def ambiguous_vulnerable_detail(exit_code: int) -> str:
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
        return (
            bool(self.state)
            and self.state != ("NULL",)
            and bool(self.inline_groups)
            and self.sanitizer_kind is not None
        )


def _sanitizer_kind(log: str) -> str | None:
    match = SANITIZER_ERROR.search(log)
    if match is None:
        return None
    return match.group("header") or "UndefinedBehaviorSanitizer"


def _inline_groups(log: str) -> Mapping[str, frozenset[str]]:
    by_pc: dict[str, list[str]] = collections.defaultdict(list)
    first_stack_seen = False
    for match in FRAME.finditer(log):
        if match.group(1) == "0":
            if first_stack_seen:
                break
            first_stack_seen = True
        function = re.sub(r"\(.*", "", match.group(3)).strip()
        by_pc[match.group(2)].append(function)
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
    return CrashSignature(
        crash_type=crash_type,
        state=state,
        inline_groups=_inline_groups(cleaned),
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
