"""Build the pinned ARVO eval-100 population fixture and preregistration."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sqlite3
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reproof.dup import OsvIndex

ARVO10_IDS = (
    42530604,
    42507851,
    42496387,
    42508524,
    42536108,
    42536112,
    42508390,
    42531297,
    42531223,
    42476752,
)
PINNED_SHA256 = {
    "arvo_database": "331184ca807c2f136f98dac9f1df94c893f4ee2fdf9329dca517ff88e72f97ce",
    "osv_archive": "bb40a3b2d1b5c612f172bc03e9164b05c105a724826bdb794ac60568b363d13c",
    "monorail_mapping": "1ad8f1a691565b502a93197bcd3d2411dcc61313106f2a6128a269bc160b1513",
}
SEED = 20261019
SIZE_CAP_BYTES = 1_500_000_000
PROJECT_CAP = 3
TARGET_NEW_TASKS = 90
FETCH_DATE = "2026-10-19"
MEMORY_SAFETY = re.compile(
    r"^(Heap-buffer-overflow|Stack-buffer-overflow|Global-buffer-overflow|"
    r"Heap-use-after-free|Stack-use-after-return|Stack-use-after-scope|"
    r"Heap-double-free|Container-overflow|Dynamic-stack-buffer-overflow|"
    r"Stack-buffer-underflow|Bad-free|Invalid-free|Use-after-poison|"
    r"Negative-size-param|Memcpy-param-overlap|Index-out-of-bounds|"
    r"Segv on unknown address|Null-dereference)"
)
HUB_TAG_URL = "https://hub.docker.com/v2/repositories/n132/arvo/tags/{tag}"
FIXTURE_FIELDS = (
    "arvo_id",
    "project",
    "crash_type",
    "family",
    "vul_bytes",
    "fix_bytes",
    "vul_last_updated",
    "fix_last_updated",
    "fetch_date",
)


@dataclass(frozen=True, slots=True)
class HubTag:
    size: int | None
    last_updated: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_pinned_inputs(arvo_db: Path, osv_archive: Path, mapping: Path) -> None:
    paths = {
        "arvo_database": arvo_db,
        "osv_archive": osv_archive,
        "monorail_mapping": mapping,
    }
    for name, path in paths.items():
        actual = _sha256(path)
        expected = PINNED_SHA256[name]
        if actual != expected:
            raise ValueError(f"{name} sha256 mismatch: expected {expected}, got {actual}")


def _family(crash_type: str) -> str:
    if crash_type.startswith("Segv on unknown address"):
        return "Segv"
    if crash_type.startswith("Null-dereference"):
        return "Null-dereference"
    return crash_type.split()[0] if crash_type else ""


def _eligible_rows(arvo_db: Path, osv_archive: Path, mapping: Path) -> list[dict[str, Any]]:
    index = OsvIndex.from_archive(osv_archive, mapping)
    with sqlite3.connect(arvo_db) as connection:
        rows = connection.execute(
            "select localId, project, crash_type, language, sanitizer, fuzz_engine, "
            "fuzz_target, crash_output from arvo order by localId"
        ).fetchall()
    eligible: list[dict[str, Any]] = []
    for task_id, project, crash_type, language, sanitizer, engine, target, output in rows:
        if sanitizer != "asan" or engine != "libfuzzer":
            continue
        if not (target and crash_type and output and language):
            continue
        if not any(record.project == project for record in index.for_issue(int(task_id))):
            continue
        if not MEMORY_SAFETY.match(str(crash_type)):
            continue
        if int(task_id) in ARVO10_IDS:
            continue
        eligible.append(
            {
                "arvo_id": int(task_id),
                "project": str(project),
                "crash_type": str(crash_type),
                "family": _family(str(crash_type)),
            }
        )
    if len(eligible) != 927:
        raise ValueError(f"eligible population changed: expected 927, got {len(eligible)}")
    return eligible


def _load_hub_cache(path: Path | None) -> dict[str, HubTag]:
    cache: dict[str, HubTag] = {}
    if path is None or not path.is_file():
        return cache
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"invalid Hub cache row {line_number}: expected 3 fields")
        tag, raw_size, updated = fields
        cache[tag] = HubTag(None if raw_size == "None" else int(raw_size), updated)
    return cache


def _fetch_hub_tag(tag: str, *, attempts: int = 3) -> HubTag:
    request = urllib.request.Request(
        HUB_TAG_URL.format(tag=tag),
        headers={"User-Agent": "reproof-eval100/1.0"},
    )
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.load(response)
            size = body.get("full_size")
            updated = body.get("last_updated")
            if not isinstance(size, int) or not isinstance(updated, str):
                raise ValueError(f"Docker Hub returned invalid metadata for {tag}")
            return HubTag(size=size, last_updated=updated)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return HubTag(size=None, last_updated=f"HTTP {error.code}")
            if attempt == attempts:
                raise RuntimeError(
                    f"Docker Hub fetch failed for {tag}: HTTP {error.code}"
                ) from error
        except (OSError, TimeoutError, ValueError) as error:
            if attempt == attempts:
                raise RuntimeError(
                    f"Docker Hub fetch failed for {tag}: {type(error).__name__}: {error}"
                ) from error
        time.sleep(attempt)
    raise AssertionError("unreachable")


def _hub_tag(tag: str, cache: dict[str, HubTag], delay_seconds: float) -> HubTag:
    cached = cache.get(tag)
    if cached is not None:
        return cached
    fetched = _fetch_hub_tag(tag)
    cache[tag] = fetched
    if delay_seconds:
        time.sleep(delay_seconds)
    return fetched


def _write_fixture(
    output: Path,
    population: list[dict[str, Any]],
    cache: dict[str, HubTag],
    delay_seconds: float,
) -> list[dict[str, Any]]:
    output.parent.mkdir(parents=True, exist_ok=True)
    enriched: list[dict[str, Any]] = []
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=FIXTURE_FIELDS, delimiter="\t", lineterminator="\n"
        )
        writer.writeheader()
        for position, row in enumerate(population, start=1):
            task_id = int(row["arvo_id"])
            vulnerable = _hub_tag(f"{task_id}-vul", cache, delay_seconds)
            fixed = _hub_tag(f"{task_id}-fix", cache, delay_seconds)
            enriched_row = {
                **row,
                "vul_bytes": vulnerable.size,
                "fix_bytes": fixed.size,
                "vul_last_updated": vulnerable.last_updated,
                "fix_last_updated": fixed.last_updated,
                "fetch_date": FETCH_DATE,
            }
            writer.writerow(
                {key: "" if value is None else value for key, value in enriched_row.items()}
            )
            enriched.append(enriched_row)
            if position % 50 == 0:
                print(f"fetched {position}/{len(population)} tasks", flush=True)
    return enriched


def _select(rows: list[dict[str, Any]]) -> tuple[list[int], dict[str, Any]]:
    by_id = {int(row["arvo_id"]): row for row in rows}
    order = sorted(by_id)
    random.Random(SEED).shuffle(order)
    historical_projects = Counter(
        {
            "jq": 3,
            "libplist": 3,
            "miniz": 2,
            "wasm3": 1,
            "libspng": 1,
        }
    )
    selected: list[int] = []
    skipped: Counter[str] = Counter()
    walked = 0
    for task_id in order:
        if len(selected) == TARGET_NEW_TASKS:
            break
        walked += 1
        row = by_id[task_id]
        project = str(row["project"])
        if historical_projects[project] >= PROJECT_CAP:
            skipped["project_cap"] += 1
            continue
        sizes = (row["vul_bytes"], row["fix_bytes"])
        if any(size is None for size in sizes):
            skipped["hub_tag_missing"] += 1
            continue
        if max(int(size) for size in sizes) > SIZE_CAP_BYTES:
            skipped["over_size_cap"] += 1
            continue
        selected.append(task_id)
        historical_projects[project] += 1
    if len(selected) != TARGET_NEW_TASKS:
        raise ValueError(f"selection produced {len(selected)} tasks, expected {TARGET_NEW_TASKS}")
    return selected, {
        "walked": walked,
        "accepted": len(selected),
        "skipped": dict(sorted(skipped.items())),
        "projects_in_new_draw": len({str(by_id[task_id]["project"]) for task_id in selected}),
        "max_tasks_per_project_combined": max(historical_projects.values()),
    }


def _write_prereg(
    output: Path,
    fixture: Path,
    selected: list[int],
    summary: dict[str, Any],
) -> None:
    prereg = {
        "schema_version": "1.0",
        "created": FETCH_DATE,
        "inputs": {
            "arvo_database": {"sha256": PINNED_SHA256["arvo_database"]},
            "osv_archive": {"sha256": PINNED_SHA256["osv_archive"]},
            "monorail_mapping": {"sha256": PINNED_SHA256["monorail_mapping"]},
            "population_fixture": {
                "path": fixture.as_posix(),
                "sha256": _sha256(fixture),
                "rows": 927,
            },
        },
        "population": {
            "exclude_arvo_ids": list(ARVO10_IDS),
            "criteria": [
                "sanitizer == asan",
                "fuzz_engine == libfuzzer",
                "required ARVO fields present",
                "same-project mapped OSV record in the pinned archive",
                "memory-safety or SEGV crash family",
            ],
        },
        "selection": {
            "seed": SEED,
            "shuffle": "random.Random(seed).shuffle(sorted(population_arvo_ids))",
            "size_cap_bytes": SIZE_CAP_BYTES,
            "project_cap_combined": PROJECT_CAP,
            "historical_arvo_ids": list(ARVO10_IDS),
            "target_new_tasks": TARGET_NEW_TASKS,
            "selected_arvo_ids": selected,
            "summary": summary,
        },
        "prepare": {
            "walk_order": "selection shuffle order",
            "continue_after_failure": True,
            "stop_after_prepared": TARGET_NEW_TASKS,
            "failure_reasons": ["pull_error", "slice_exception", "tag_not_removed"],
        },
        "run": {
            "exclude_after_prepare": False,
            "transport_retries": 1,
            "second_transport_failure": "RUN_FAILED",
        },
    }
    output.write_text(json.dumps(prereg, indent=2) + "\n", encoding="utf-8", newline="\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arvo-db", type=Path, required=True)
    parser.add_argument("--osv-archive", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path("eval/fixtures/arvo_population-2026-10-19.tsv"),
    )
    parser.add_argument("--prereg", type=Path, default=Path("eval/eval100_prereg.json"))
    parser.add_argument("--hub-cache", type=Path)
    parser.add_argument("--delay-seconds", type=float, default=0.3)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    _require_pinned_inputs(args.arvo_db, args.osv_archive, args.mapping)
    population = _eligible_rows(args.arvo_db, args.osv_archive, args.mapping)
    cache = _load_hub_cache(args.hub_cache)
    enriched = _write_fixture(args.fixture, population, cache, args.delay_seconds)
    selected, summary = _select(enriched)
    _write_prereg(args.prereg, args.fixture, selected, summary)
    print(json.dumps({"fixture_rows": len(enriched), "selection": summary}, indent=2))


if __name__ == "__main__":
    main()
