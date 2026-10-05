"""Index public OSS-Fuzz OSV records and return every matching crash state."""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import urllib.request
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reproof.crash import CrashSignature
from reproof.models import DuplicateCandidate

OSV_ALL_URL = "https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip"
ISSUE = re.compile(r"(?:issues/detail\?id=|issues\.oss-fuzz\.com/issues/)(\d+)")


@dataclass(frozen=True, slots=True)
class OsvRecord:
    id: str
    project: str
    summary: str
    details: str
    crash_type: str
    state: tuple[str, ...]
    issue_ids: frozenset[int]
    fixed_commits: tuple[str, ...]

    @property
    def report_text(self) -> str:
        return f"{self.summary}\n\n{self.details}".strip()


def default_cache_dir() -> Path:
    configured = os.getenv("REPROOF_CACHE_DIR")
    return (
        Path(configured).expanduser().resolve() if configured else Path(".cache/reproof").resolve()
    )


def default_mapping_path() -> Path:
    configured = os.getenv("REPROOF_OSS_FUZZ_MAPPING")
    if configured:
        return Path(configured).expanduser().resolve()
    app_root = Path(__file__).resolve().parents[1]
    candidates = (
        default_cache_dir() / "oss_fuzz_mappings.csv",
        app_root.parent / "spike" / "data" / "oss_fuzz_mappings.csv",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(
        "OSS-Fuzz issue mapping not found. Set REPROOF_OSS_FUZZ_MAPPING or place it at: " + searched
    )


def ensure_osv_archive(cache_dir: Path | None = None) -> Path:
    directory = (cache_dir or default_cache_dir()).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / "oss-fuzz-osv-all.zip"
    if archive.is_file() and zipfile.is_zipfile(archive):
        return archive
    temporary = archive.with_suffix(".zip.part")
    request = urllib.request.Request(OSV_ALL_URL, headers={"User-Agent": "reproof/0.1"})
    try:
        with (
            urllib.request.urlopen(request, timeout=120) as response,
            temporary.open("wb") as target,
        ):
            shutil.copyfileobj(response, target)
        if temporary.stat().st_size < 1_000_000 or not zipfile.is_zipfile(temporary):
            raise ValueError(
                f"OSV download failed content validation: {temporary.stat().st_size} bytes"
            )
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    return archive


def load_issue_mapping(path: Path | None = None) -> dict[int, int]:
    mapping: dict[int, int] = {}
    with (path or default_mapping_path()).open(encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream):
            if len(row) >= 2 and row[0].isdigit() and row[1].isdigit():
                mapping[int(row[0])] = int(row[1])
    if not mapping:
        raise ValueError("OSS-Fuzz issue mapping contained no numeric rows")
    return mapping


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def parse_osv_record(raw: dict[str, Any]) -> OsvRecord | None:
    details = str(raw.get("details", ""))
    type_match = re.search(r"Crash type:\s*(.+)", details)
    state_match = re.search(r"Crash state:\n(.*?)\n```", details, re.S)
    issue_ids = frozenset(
        int(value)
        for reference in raw.get("references", [])
        for value in ISSUE.findall(str(reference.get("url", "")))
    )
    affected = raw.get("affected") or []
    project = ""
    if affected:
        project = str(affected[0].get("package", {}).get("name", ""))
    if not project or not state_match or not issue_ids:
        return None
    fixed = _ordered_unique(
        str(event.get("fixed", ""))
        for item in affected
        for range_record in item.get("ranges", [])
        if range_record.get("type") == "GIT"
        for event in range_record.get("events", [])
        if event.get("fixed")
    )
    state = tuple(line.strip() for line in state_match.group(1).splitlines() if line.strip())
    return OsvRecord(
        id=str(raw["id"]),
        project=project,
        summary=str(raw.get("summary", "")),
        details=details,
        crash_type=type_match.group(1).strip() if type_match else "",
        state=state,
        issue_ids=issue_ids,
        fixed_commits=fixed,
    )


def frames_match(
    ours: tuple[str, ...],
    theirs: tuple[str, ...],
    inline_groups: dict[str, frozenset[str]] | None = None,
) -> bool:
    if not ours or len(ours) != len(theirs):
        return False
    for ours_frame, their_frame in zip(ours, theirs, strict=True):
        if ours_frame == their_frame:
            continue
        if inline_groups is None or their_frame not in inline_groups.get(ours_frame, frozenset()):
            return False
    return True


class OsvIndex:
    def __init__(
        self,
        records: Iterable[OsvRecord],
        old_to_new: dict[int, int] | None = None,
    ) -> None:
        self.records = tuple(records)
        self.old_to_new = old_to_new or {}
        new_to_old: dict[int, list[int]] = {}
        for old_id, new_id in self.old_to_new.items():
            new_to_old.setdefault(new_id, []).append(old_id)
        self.by_project: dict[str, list[OsvRecord]] = {}
        self.by_issue: dict[int, list[OsvRecord]] = {}
        for record in self.records:
            self.by_project.setdefault(record.project, []).append(record)
            for issue_id in record.issue_ids:
                aliases = {issue_id}
                if issue_id in self.old_to_new:
                    aliases.add(self.old_to_new[issue_id])
                aliases.update(new_to_old.get(issue_id, []))
                for alias in aliases:
                    bucket = self.by_issue.setdefault(alias, [])
                    if record not in bucket:
                        bucket.append(record)

    @classmethod
    def from_archive(
        cls,
        archive: Path | None = None,
        mapping: Path | None = None,
    ) -> OsvIndex:
        records: list[OsvRecord] = []
        with zipfile.ZipFile(archive or ensure_osv_archive()) as bundle:
            for name in bundle.namelist():
                parsed = parse_osv_record(json.loads(bundle.read(name)))
                if parsed is not None:
                    records.append(parsed)
        return cls(records, load_issue_mapping(mapping))

    def for_issue(self, issue_id: int) -> tuple[OsvRecord, ...]:
        return tuple(sorted(self.by_issue.get(issue_id, []), key=lambda record: record.id))

    def find_candidates(self, project: str, crash: CrashSignature) -> list[DuplicateCandidate]:
        if not crash.state:
            return []
        candidates: list[DuplicateCandidate] = []
        groups = dict(crash.inline_groups)
        for record in self.by_project.get(project, []):
            if frames_match(crash.state, record.state):
                match_kind = "exact"
            elif frames_match(crash.state, record.state, groups):
                match_kind = "inline_tolerant"
            else:
                continue
            candidates.append(
                DuplicateCandidate(
                    id=record.id,
                    summary=record.summary,
                    fixed_commits=list(record.fixed_commits),
                    match_kind=match_kind,
                )
            )
        return sorted(candidates, key=lambda candidate: candidate.id)
