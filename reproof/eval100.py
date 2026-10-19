"""Pinned selection and preparation inputs for the ARVO eval-100 run."""

from __future__ import annotations

import csv
import json
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reproof.arvo import default_database_path
from reproof.dup import default_cache_dir, default_mapping_path
from reproof.provenance import file_sha256

DEFAULT_PREREG = Path("eval/eval100_prereg.json")
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
ARVO10_PROJECTS = {
    42530604: "jq",
    42507851: "libplist",
    42496387: "wasm3",
    42508524: "libplist",
    42536108: "miniz",
    42536112: "miniz",
    42508390: "libplist",
    42531297: "jq",
    42531223: "jq",
    42476752: "libspng",
}


@dataclass(frozen=True, slots=True)
class Eval100InputPaths:
    arvo_database: Path
    osv_archive: Path
    monorail_mapping: Path


@dataclass(frozen=True, slots=True)
class Eval100PopulationRow:
    arvo_id: int
    project: str
    crash_type: str
    family: str
    vul_bytes: int | None
    fix_bytes: int | None
    vul_last_updated: str
    fix_last_updated: str
    fetch_date: str


@dataclass(frozen=True, slots=True)
class Eval100Selection:
    prereg_path: Path
    prereg_sha256: str
    fixture_path: Path
    fixture_sha256: str
    expected_input_sha256: dict[str, str]
    seed: int
    size_cap_bytes: int
    project_cap: int
    target_new_tasks: int
    historical_arvo_ids: tuple[int, ...]
    draw_order: tuple[int, ...]
    population: tuple[Eval100PopulationRow, ...]
    selected_new_arvo_ids: tuple[int, ...]
    skipped: dict[str, int]
    walked: int

    @property
    def selected_arvo_ids(self) -> tuple[int, ...]:
        return self.historical_arvo_ids + self.selected_new_arvo_ids

    @property
    def population_by_id(self) -> dict[int, Eval100PopulationRow]:
        return {row.arvo_id: row for row in self.population}


def default_eval100_inputs() -> Eval100InputPaths:
    return Eval100InputPaths(
        arvo_database=default_database_path(),
        osv_archive=default_cache_dir() / "oss-fuzz-osv-all.zip",
        monorail_mapping=default_mapping_path(),
    )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} keys must be strings")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _integer_list(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    result = tuple(_positive_int(item, f"{label} item") for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} contains duplicate ARVO IDs")
    return result


def _sha256_value(record: dict[str, Any], label: str) -> str:
    value = record.get("sha256")
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label}.sha256 must be a 64-character string")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label}.sha256 must be hexadecimal") from error
    return value


def _resolve_fixture(prereg_path: Path, raw_path: object) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("inputs.population_fixture.path must be a non-empty string")
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate.resolve()
    beside_prereg = (prereg_path.parent / candidate).resolve()
    if beside_prereg.is_file():
        return beside_prereg
    repository_path = (Path(__file__).resolve().parents[1] / candidate).resolve()
    if repository_path.is_file():
        return repository_path
    return beside_prereg


def _optional_size(raw: str, label: str) -> int | None:
    if raw == "":
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{label} must be an integer or empty") from error
    if value <= 0:
        raise ValueError(f"{label} must be positive")
    return value


def _load_population(path: Path, expected_rows: int) -> tuple[Eval100PopulationRow, ...]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != FIXTURE_FIELDS:
            raise ValueError("population fixture header does not match the registered schema")
        rows: list[Eval100PopulationRow] = []
        for line_number, raw in enumerate(reader, start=2):
            try:
                task_id = int(raw["arvo_id"])
            except ValueError as error:
                raise ValueError(f"population row {line_number} has an invalid ARVO ID") from error
            if task_id <= 0:
                raise ValueError(f"population row {line_number} has a non-positive ARVO ID")
            for field in (
                "project",
                "crash_type",
                "family",
                "vul_last_updated",
                "fix_last_updated",
                "fetch_date",
            ):
                if not raw[field]:
                    raise ValueError(f"population row {line_number} has an empty {field}")
            rows.append(
                Eval100PopulationRow(
                    arvo_id=task_id,
                    project=raw["project"],
                    crash_type=raw["crash_type"],
                    family=raw["family"],
                    vul_bytes=_optional_size(raw["vul_bytes"], f"row {line_number} vul_bytes"),
                    fix_bytes=_optional_size(raw["fix_bytes"], f"row {line_number} fix_bytes"),
                    vul_last_updated=raw["vul_last_updated"],
                    fix_last_updated=raw["fix_last_updated"],
                    fetch_date=raw["fetch_date"],
                )
            )
    if len(rows) != expected_rows:
        raise ValueError(f"population fixture has {len(rows)} rows, expected {expected_rows}")
    ids = [row.arvo_id for row in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("population fixture contains duplicate ARVO IDs")
    if ids != sorted(ids):
        raise ValueError("population fixture must be sorted by ARVO ID")
    return tuple(rows)


def _draw(
    population: tuple[Eval100PopulationRow, ...],
    *,
    seed: int,
    size_cap_bytes: int,
    project_cap: int,
    target: int,
) -> tuple[tuple[int, ...], tuple[int, ...], dict[str, int], int, Counter[str]]:
    by_id = {row.arvo_id: row for row in population}
    order = sorted(by_id)
    random.Random(seed).shuffle(order)
    project_counts = Counter(ARVO10_PROJECTS.values())
    selected: list[int] = []
    skipped: Counter[str] = Counter()
    walked = 0
    for task_id in order:
        if len(selected) == target:
            break
        walked += 1
        row = by_id[task_id]
        if project_counts[row.project] >= project_cap:
            skipped["project_cap"] += 1
            continue
        if row.vul_bytes is None or row.fix_bytes is None:
            skipped["hub_tag_missing"] += 1
            continue
        if max(row.vul_bytes, row.fix_bytes) > size_cap_bytes:
            skipped["over_size_cap"] += 1
            continue
        selected.append(task_id)
        project_counts[row.project] += 1
    if len(selected) != target:
        raise ValueError(f"eval100 selection produced {len(selected)} tasks, expected {target}")
    return tuple(order), tuple(selected), dict(sorted(skipped.items())), walked, project_counts


def load_eval100_selection(prereg: Path = DEFAULT_PREREG) -> Eval100Selection:
    prereg_path = prereg.resolve()
    raw = _object(json.loads(prereg_path.read_text(encoding="utf-8")), "preregistration")
    if raw.get("schema_version") != "1.0":
        raise ValueError("eval100 preregistration schema_version must be 1.0")
    inputs = _object(raw.get("inputs"), "inputs")
    fixture_record = _object(inputs.get("population_fixture"), "inputs.population_fixture")
    fixture_path = _resolve_fixture(prereg_path, fixture_record.get("path"))
    fixture_hash = _sha256_value(fixture_record, "inputs.population_fixture")
    actual_fixture_hash = file_sha256(fixture_path)
    if actual_fixture_hash != fixture_hash:
        raise ValueError(
            "population fixture sha256 mismatch: "
            f"expected {fixture_hash}, got {actual_fixture_hash}"
        )
    expected_rows = _positive_int(fixture_record.get("rows"), "inputs.population_fixture.rows")
    population = _load_population(fixture_path, expected_rows)

    expected_input_sha256 = {
        name: _sha256_value(_object(inputs.get(name), f"inputs.{name}"), f"inputs.{name}")
        for name in ("arvo_database", "osv_archive", "monorail_mapping")
    }
    selection = _object(raw.get("selection"), "selection")
    seed = _positive_int(selection.get("seed"), "selection.seed")
    size_cap_bytes = _positive_int(selection.get("size_cap_bytes"), "selection.size_cap_bytes")
    project_cap = _positive_int(
        selection.get("project_cap_combined"), "selection.project_cap_combined"
    )
    target = _positive_int(selection.get("target_new_tasks"), "selection.target_new_tasks")
    historical = _integer_list(selection.get("historical_arvo_ids"), "historical_arvo_ids")
    if historical != tuple(ARVO10_PROJECTS):
        raise ValueError("historical_arvo_ids do not match the frozen arvo10 order")
    registered_ids = _integer_list(selection.get("selected_arvo_ids"), "selected_arvo_ids")
    order, selected, skipped, walked, project_counts = _draw(
        population,
        seed=seed,
        size_cap_bytes=size_cap_bytes,
        project_cap=project_cap,
        target=target,
    )
    if selected != registered_ids:
        raise ValueError("selected_arvo_ids do not match the fixture-derived draw")
    summary = _object(selection.get("summary"), "selection.summary")
    expected_summary = {
        "walked": walked,
        "accepted": len(selected),
        "skipped": skipped,
        "projects_in_new_draw": len(
            {row.project for row in population if row.arvo_id in set(selected)}
        ),
        "max_tasks_per_project_combined": max(project_counts.values()),
    }
    if summary != expected_summary:
        raise ValueError("selection.summary does not match the fixture-derived draw")
    return Eval100Selection(
        prereg_path=prereg_path,
        prereg_sha256=file_sha256(prereg_path),
        fixture_path=fixture_path,
        fixture_sha256=fixture_hash,
        expected_input_sha256=expected_input_sha256,
        seed=seed,
        size_cap_bytes=size_cap_bytes,
        project_cap=project_cap,
        target_new_tasks=target,
        historical_arvo_ids=historical,
        draw_order=order,
        population=population,
        selected_new_arvo_ids=selected,
        skipped=skipped,
        walked=walked,
    )


def _verify_external_inputs(selection: Eval100Selection, paths: Eval100InputPaths) -> None:
    named_paths = {
        "arvo_database": paths.arvo_database,
        "osv_archive": paths.osv_archive,
        "monorail_mapping": paths.monorail_mapping,
    }
    for name, path in named_paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"registered {name} input not found: {path}")
        actual = file_sha256(path)
        expected = selection.expected_input_sha256[name]
        if actual != expected:
            raise ValueError(f"{name} sha256 mismatch: expected {expected}, got {actual}")


def select_eval100(
    prereg: Path = DEFAULT_PREREG,
    *,
    inputs: Eval100InputPaths | None = None,
) -> Eval100Selection:
    """Return the registered draw after verifying the fixture and all source inputs."""
    selection = load_eval100_selection(prereg)
    _verify_external_inputs(selection, inputs or default_eval100_inputs())
    return selection
