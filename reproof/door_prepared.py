"""The eval-100 tasks the judge door offers beside the featured 10.

A prepared task is offered only when a committed eval-100 card completed from exactly the
ConTree checkpoint pair written here and its vulnerable build crashed. Every other task the
eval-100 run selected is listed under ``not_offered`` with the reason.

The builder reads the local ConTree checkpoint registry for the fields a card does not carry
(tag, creation cost and wall time). Each checkpoint UUID, its slice manifest hash, and its
creation operation are checked against the committed card before anything is written.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Any

from reproof.crash import parse_crash
from reproof.door_data import (
    ASSETS_DIR,
    SCHEMA_VERSION,
    ProjectIndex,
    _record_payload,
    _write_json,
    github_owner_repo,
    load_catalog,
    load_manifest,
    load_project_index,
)
from reproof.dup import (
    OsvIndex,
    OsvRecord,
    default_cache_dir,
    default_mapping_path,
    load_issue_mapping,
    parse_osv_record,
)
from reproof.models import Eval100Report, EvalRunFailure, EvalTaskResult, TriageCard, Verdict
from reproof.provenance import file_sha256, text_sha256

ROOT = Path(__file__).resolve().parents[1]
PREPARED_CATALOG = "prepared_catalog.json"
PREPARED_CHECKPOINTS = "prepared_checkpoints.json"
PREPARED_OSV = "prepared_osv_projects.json"
RUN2_PATH = "eval/results/eval100-run2.json"
RUN1_PATH = "eval/results/eval100.json"
OFFERED_VERDICTS = frozenset({Verdict.REPRODUCED, Verdict.DUPLICATE})
OFFER_RULE = (
    "Every eval-100 task outside the featured 10 whose committed run 2 card (or, when run 2 "
    "did not complete it, run 1 card) ran both builds from the ConTree checkpoint pair named "
    "here and measured a crash on the vulnerable build (verdict REPRODUCED or DUPLICATE). A "
    "task that run 2 completed without a crash is not offered, even if run 1 completed it."
)
NO_PAIR = "no_checkpoint_pair"
NEVER_COMPLETED = "never_completed"
NO_CRASH = "no_crash_measured"


def _read_report(path: Path) -> Eval100Report:
    return Eval100Report.model_validate_json(path.read_text(encoding="utf-8"))


def _raw_rows(path: Path) -> dict[int, dict[str, Any]]:
    """Task rows exactly as the eval file stores them, keyed by ARVO id."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    return {int(row["arvo_id"]): row for row in raw["tasks"]}


def _github_range(raw: dict[str, Any]) -> tuple[str, str]:
    """Owner and repository of the record's first github.com GIT range, as eval-100 used."""

    for affected in raw.get("affected") or []:
        for range_record in affected.get("ranges") or []:
            if range_record.get("type") != "GIT":
                continue
            owner, repo = github_owner_repo(str(range_record.get("repo") or ""))
            if owner and repo:
                return owner, repo
    return "", ""


def _registry_pair(registry: dict[str, Any], task_id: int) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for key, entry in registry.items():
        task, kind, digest = key.split(":")
        if int(task) != task_id or not isinstance(entry, dict):
            continue
        if kind in found:
            raise ValueError(f"checkpoint registry has two {kind} entries for ARVO {task_id}")
        if str(entry.get("manifest_sha256") or "") != digest:
            raise ValueError(f"checkpoint registry key {key} disagrees with its manifest hash")
        found[kind] = entry
    return found


# The step a run failure stopped at, read from its recorded error text.
_FAILURE_STAGES = (
    ("checkpoint creation failed", "checkpoint creation failed"),
    ("base image lookup failed", "base image lookup failed"),
    ("cached checkpoint lookup failed", "cached checkpoint lookup failed"),
    ("SandboxPairError", "the sandbox run failed"),
    ("APIConnectionError", "the claim call lost its connection"),
    ("APITimeoutError", "the claim call timed out"),
)


def _failure_note(failure: EvalRunFailure | None, run: str) -> str:
    if failure is None:
        return f"{run} did not attempt it"
    stage = next((text for marker, text in _FAILURE_STAGES if marker in failure.error), "")
    status = " with HTTP 500 from ConTree" if "status=500" in failure.error else ""
    return f"{run}: {stage or failure.error_type}{status}"


def _card(root: Path, row: EvalTaskResult) -> TriageCard:
    return TriageCard.model_validate_json((root / row.card_path).read_text(encoding="utf-8"))


def _checkpoint_block(entry: dict[str, Any], card: TriageCard, kind: str) -> dict[str, Any]:
    operation = next(item for item in card.sandbox_operations if item.kind == kind)
    uuid = str(entry.get("checkpoint_uuid") or "")
    if not uuid or uuid != operation.checkpoint_uuid:
        raise ValueError(
            f"ARVO {card.arvo_id} {kind} checkpoint {uuid} is not the one its card ran from "
            f"({operation.checkpoint_uuid})"
        )
    digest = str(entry["manifest_sha256"])
    if digest != card.slice_manifest_sha256[kind]:
        raise ValueError(f"ARVO {card.arvo_id} {kind} slice hash does not match its card")
    created = str(entry.get("create_operation_uuid") or "")
    if created != operation.checkpoint_operation_uuid:
        raise ValueError(
            f"ARVO {card.arvo_id} {kind} creation operation {created} is not the card's "
            f"{operation.checkpoint_operation_uuid}"
        )
    return {
        "checkpoint_uuid": uuid,
        "manifest_sha256": digest,
        "create_operation_uuid": created,
        "checkpoint_wall_seconds": float(entry.get("checkpoint_wall_seconds") or 0.0),
        "checkpoint_cost_usd": float(entry.get("checkpoint_cost_usd") or 0.0),
        "tag": str(entry.get("tag") or ""),
    }


def _not_offered(task_id: int, project: str, reason: str, detail: str) -> dict[str, Any]:
    return {"arvo_id": task_id, "project": project, "reason": reason, "detail": detail}


def _no_crash_detail(run: str, row: EvalTaskResult, card: TriageCard) -> str:
    vulnerable = next(item for item in card.sandbox_operations if item.kind == "vul")
    detail = (
        f"{run} completed it as {row.verdict.value}: the vulnerable build exited "
        f"{row.vulnerable_exit_code} and the fixed build exited {row.fixed_exit_code}, "
        "so no crash was measured"
    )
    if "ELFCLASS64" in vulnerable.stderr:
        detail += (
            ". The target is 32-bit and its runtime slice carried a 64-bit library "
            "(wrong ELF class: ELFCLASS64)"
        )
    return detail + "."


def merge_project_indexes(first: ProjectIndex, second: ProjectIndex) -> ProjectIndex:
    """One index over both record sets. Both must come from the same archive and mapping."""

    if (first.archive_sha256, first.mapping_sha256) != (
        second.archive_sha256,
        second.mapping_sha256,
    ):
        raise ValueError("project indexes come from different OSV archives or mappings")
    seen = {record.id for record in first.index.records}
    records = [*first.index.records, *(r for r in second.index.records if r.id not in seen)]
    aliases = {**first.index.old_to_new, **second.index.old_to_new}
    return ProjectIndex(
        index=OsvIndex(records, aliases),
        archive_sha256=first.archive_sha256,
        mapping_sha256=first.mapping_sha256,
        projects=tuple(sorted({*first.projects, *second.projects})),
    )


def build_prepared_assets(
    *,
    registry: Path,
    archive: Path,
    mapping: Path,
    run2: Path | None = None,
    run1: Path | None = None,
    output: Path = ASSETS_DIR,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Write the prepared catalog, checkpoint manifest, and OSV index. Raise on disagreement."""

    run2_path = run2 or root / RUN2_PATH
    run1_path = run1 or root / RUN1_PATH
    second = _read_report(run2_path)
    first = _read_report(run1_path)
    if second.selected_arvo_ids != first.selected_arvo_ids:
        raise ValueError("eval-100 runs 1 and 2 selected different tasks")
    archive_sha256 = file_sha256(archive)
    mapping_sha256 = file_sha256(mapping)
    for report in (first, second):
        if archive_sha256 != report.provenance.osv_archive_sha256:
            raise ValueError("OSV archive hash does not match eval-100 provenance")
        if mapping_sha256 != report.provenance.monorail_mapping_sha256:
            raise ValueError("OSS-Fuzz mapping hash does not match eval-100 provenance")

    featured = {int(row["arvo_id"]) for row in load_catalog(output / "catalog.json")["tasks"]}
    if set(second.historical_arvo_ids) != featured:
        raise ValueError("the featured catalog is not the eval-100 historical set")
    base_index = load_project_index(output / "osv_projects.json")

    registry_value = json.loads(registry.read_text(encoding="utf-8"))
    if not isinstance(registry_value, dict):
        raise ValueError("checkpoint registry must be a JSON object")

    runs = (("run 2", second, run2_path), ("run 1", first, run1_path))
    completed: dict[int, tuple[str, EvalTaskResult, Path]] = {}
    for label, report, path in runs:
        for task in report.tasks:
            completed.setdefault(task.arvo_id, (label, task, path))
    failures = {
        label: {failure.arvo_id: failure for failure in report.run_failed}
        for label, report, _ in runs
    }

    raw_by_id: dict[str, dict[str, Any]] = {}
    records_by_id: dict[str, OsvRecord] = {}
    with zipfile.ZipFile(archive) as bundle:
        for name in bundle.namelist():
            if not name.endswith(".json"):
                continue
            raw = json.loads(bundle.read(name))
            parsed = parse_osv_record(raw)
            if parsed is not None:
                raw_by_id[parsed.id] = raw
                records_by_id[parsed.id] = parsed

    offered: list[tuple[EvalTaskResult, TriageCard, str, Path]] = []
    not_offered: list[dict[str, Any]] = []
    for task_id in second.random_draw_arvo_ids:
        pair = _registry_pair(registry_value, task_id)
        found = completed.get(task_id)
        project = found[1].project if found else _project_of(second, first, task_id)
        if set(pair) != {"vul", "fix"}:
            missing = [kind for kind in ("vul", "fix") if kind not in pair]
            notes = "; ".join(
                _failure_note(failures[label].get(task_id), label) for label, *_ in runs
            )
            lead = (
                "Neither ConTree checkpoint was created"
                if len(missing) == 2
                else f"No {missing[0]} checkpoint was created"
            )
            not_offered.append(_not_offered(task_id, project, NO_PAIR, f"{lead} ({notes})."))
            continue
        if found is None:
            notes = "; ".join(
                _failure_note(failures[label].get(task_id), label) for label, *_ in runs
            )
            not_offered.append(
                _not_offered(
                    task_id,
                    project,
                    NEVER_COMPLETED,
                    f"Both checkpoints exist, but no run completed from them ({notes}).",
                )
            )
            continue
        label, row, path = found
        card = _card(root, row)
        if row.verdict not in OFFERED_VERDICTS:
            not_offered.append(
                _not_offered(task_id, project, NO_CRASH, _no_crash_detail(label, row, card))
            )
            continue
        offered.append((row, card, label, path))

    projects = sorted({row.project for row, *_ in offered} - set(base_index.projects))
    records = [record for record in records_by_id.values() if record.project in projects]
    issue_ids = {issue for record in records for issue in record.issue_ids}
    offered_ids = {row.arvo_id for row, *_ in offered}
    full_mapping = load_issue_mapping(mapping)
    aliases = [
        [old, new]
        for old, new in sorted(full_mapping.items())
        if old in issue_ids or new in issue_ids or old in offered_ids or new in offered_ids
    ]
    prepared_index = ProjectIndex(
        index=OsvIndex(records, {old: new for old, new in aliases}),
        archive_sha256=archive_sha256,
        mapping_sha256=mapping_sha256,
        projects=tuple(projects),
    )
    door_index = merge_project_indexes(base_index, prepared_index)

    catalog_rows: list[dict[str, Any]] = []
    manifest_rows: dict[str, Any] = {}
    for row, card, label, path in offered:
        osv_id = row.card_provenance.osv_record_id
        if osv_id is None or osv_id not in records_by_id:
            raise ValueError(f"ARVO {row.arvo_id} OSV record {osv_id} is not in the archive")
        record = records_by_id[osv_id]
        report_sha256 = text_sha256(record.report_text)
        if card.report_text != record.report_text or report_sha256 != (
            row.card_provenance.report_sha256
        ):
            raise ValueError(f"ARVO {row.arvo_id} report text does not match {osv_id}")
        excluded = sorted({item.id for item in door_index.index.for_issue(row.arvo_id)})
        if excluded != sorted(card.evidence.excluded_osv_ids) or osv_id not in excluded:
            raise ValueError(f"ARVO {row.arvo_id} excluded OSV ids {excluded} differ from its card")
        vulnerable = next(item for item in card.sandbox_operations if item.kind == "vul")
        candidates = [
            candidate.id
            for candidate in door_index.index.find_candidates(
                row.project, parse_crash(vulnerable.stderr), excluded_osv_ids=excluded
            )
        ]
        if candidates != list(row.duplicate_candidates):
            raise ValueError(
                f"ARVO {row.arvo_id} duplicate candidates {candidates} differ from "
                f"{list(row.duplicate_candidates)}"
            )
        pair = _registry_pair(registry_value, row.arvo_id)
        owner, repo = _github_range(raw_by_id[osv_id])
        manifest_rows[str(row.arvo_id)] = {
            "project": row.project,
            "osv_record_id": osv_id,
            "arvo_task_sha256": row.card_provenance.arvo_task_sha256,
            "vul": _checkpoint_block(pair["vul"], card, "vul"),
            "fix": _checkpoint_block(pair["fix"], card, "fix"),
        }
        recorded = _raw_rows(path)[row.arvo_id]
        catalog_rows.append(
            {
                "arvo_id": row.arvo_id,
                "project": row.project,
                "osv_record_id": osv_id,
                "report_source": card.report_source,
                "report_sha256": report_sha256,
                "report_text": record.report_text,
                "arvo_task_sha256": row.card_provenance.arvo_task_sha256,
                "crash_type": record.crash_type,
                "owner": owner,
                "repo": repo,
                "recorded_in": path.resolve().relative_to(root.resolve()).as_posix(),
                "recorded_run": label,
                "recorded": recorded,
            }
        )

    output.mkdir(parents=True, exist_ok=True)
    _write_json(
        output / PREPARED_CHECKPOINTS,
        {"schema_version": SCHEMA_VERSION, "retention_days": 180, "tasks": manifest_rows},
    )
    _write_json(
        output / PREPARED_CATALOG,
        {
            "schema_version": SCHEMA_VERSION,
            "offer_rule": OFFER_RULE,
            "sources": {
                RUN2_PATH: file_sha256(run2_path),
                RUN1_PATH: file_sha256(run1_path),
            },
            "tasks": catalog_rows,
            "not_offered": not_offered,
        },
    )
    _write_json(
        output / PREPARED_OSV,
        {
            "schema_version": SCHEMA_VERSION,
            "projects": projects,
            "archive_sha256": archive_sha256,
            "archive_bytes": archive.stat().st_size,
            "mapping_sha256": mapping_sha256,
            "record_count": len(records),
            "issue_alias_count": len(aliases),
            "records": [_record_payload(record) for record in records],
            "issue_aliases": aliases,
        },
    )
    return {
        "offered": len(catalog_rows),
        "not_offered": len(not_offered),
        "projects": len(projects),
        "osv_records": len(records),
        "issue_aliases": len(aliases),
    }


def _project_of(second: Eval100Report, first: Eval100Report, task_id: int) -> str:
    for report in (second, first):
        for failure in report.run_failed:
            if failure.arvo_id == task_id:
                return failure.project
    raise ValueError(f"ARVO {task_id} neither completed nor failed in eval-100")


def load_prepared_catalog(assets: Path = ASSETS_DIR) -> dict[str, Any]:
    value = json.loads((assets / PREPARED_CATALOG).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("tasks"), list):
        raise ValueError("prepared catalog must contain a task list")
    return value


def load_door_catalog(assets: Path = ASSETS_DIR) -> dict[str, Any]:
    """The featured 10 followed by every offered prepared task."""

    featured = load_catalog(assets / "catalog.json")
    prepared = load_prepared_catalog(assets)
    ids = [int(row["arvo_id"]) for row in [*featured["tasks"], *prepared["tasks"]]]
    if len(set(ids)) != len(ids):
        raise ValueError("a prepared task repeats a featured or prepared ARVO id")
    return {**featured, "tasks": [*featured["tasks"], *prepared["tasks"]]}


def load_door_manifest(assets: Path = ASSETS_DIR) -> dict[str, Any]:
    featured = load_manifest(assets / "checkpoints.json")
    prepared = load_manifest(assets / PREPARED_CHECKPOINTS)
    if set(featured["tasks"]) & set(prepared["tasks"]):
        raise ValueError("a prepared checkpoint row repeats a featured ARVO id")
    return {**featured, "tasks": {**featured["tasks"], **prepared["tasks"]}}


def load_door_project_index(assets: Path = ASSETS_DIR) -> ProjectIndex:
    return merge_project_indexes(
        load_project_index(assets / "osv_projects.json"),
        load_project_index(assets / PREPARED_OSV),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reproof.door_prepared")
    parser.add_argument("--registry", type=Path, default=default_cache_dir() / "checkpoints.json")
    parser.add_argument(
        "--archive", type=Path, default=default_cache_dir() / "oss-fuzz-osv-all.zip"
    )
    parser.add_argument("--mapping", type=Path)
    parser.add_argument("--output", type=Path, default=ASSETS_DIR)
    args = parser.parse_args(argv)
    summary = build_prepared_assets(
        registry=args.registry,
        archive=args.archive,
        mapping=args.mapping or default_mapping_path(),
        output=args.output,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
