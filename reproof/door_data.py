"""Build the committed checkpoint manifest and the per-project OSV index.

The judge server loads these files. It does not read the runtime slices or the full
OSS-Fuzz OSV zip.
"""

from __future__ import annotations

import argparse
import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reproof.crash import CrashSignature, parse_crash
from reproof.dup import OsvIndex, OsvRecord, load_issue_mapping, parse_osv_record
from reproof.models import EvalReport, TriageCard
from reproof.provenance import arvo_task_sha256, file_sha256, text_sha256
from reproof.sandbox import manifest_digest

DOOR_PROJECTS = ("jq", "libplist", "wasm3", "miniz", "libspng")
SCHEMA_VERSION = "1"
ASSETS_DIR = Path(__file__).resolve().parent / "assets"


@dataclass(frozen=True, slots=True)
class ProjectIndex:
    """OSV records for the measured projects, plus the archive they came from."""

    index: OsvIndex
    archive_sha256: str
    mapping_sha256: str
    projects: tuple[str, ...]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _record_payload(record: OsvRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "project": record.project,
        "summary": record.summary,
        "details": record.details,
        "crash_type": record.crash_type,
        "state": list(record.state),
        "issue_ids": sorted(record.issue_ids),
        "fixed_commits": list(record.fixed_commits),
    }


def _checkpoint_block(entry: dict[str, Any], digest: str) -> dict[str, Any]:
    uuid = str(entry.get("checkpoint_uuid") or "")
    if not uuid:
        raise ValueError(f"checkpoint registry entry for {digest} has no checkpoint_uuid")
    recorded = str(entry.get("manifest_sha256") or "")
    if recorded != digest:
        raise ValueError(f"checkpoint registry hash {recorded} does not match slice hash {digest}")
    return {
        "checkpoint_uuid": uuid,
        "manifest_sha256": digest,
        "create_operation_uuid": entry.get("create_operation_uuid"),
        "checkpoint_wall_seconds": float(entry.get("checkpoint_wall_seconds") or 0.0),
        "checkpoint_cost_usd": float(entry.get("checkpoint_cost_usd") or 0.0),
        "tag": str(entry.get("tag") or ""),
    }


def _registry_entry(
    registry: dict[str, Any],
    task_id: int,
    kind: str,
    digest: str,
) -> dict[str, Any]:
    key = f"{task_id}:{kind}:{digest}"
    entry = registry.get(key)
    if not isinstance(entry, dict):
        raise ValueError(f"checkpoint registry has no entry {key}")
    return entry


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = path or (ASSETS_DIR / "checkpoints.json")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("tasks"), dict):
        raise ValueError(f"checkpoint manifest must contain tasks: {manifest_path}")
    return value


def load_catalog(path: Path | None = None) -> dict[str, Any]:
    catalog_path = path or (ASSETS_DIR / "catalog.json")
    value = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("tasks"), list):
        raise ValueError(f"catalog must contain a task list: {catalog_path}")
    return value


def load_project_index(path: Path | None = None) -> ProjectIndex:
    index_path = path or (ASSETS_DIR / "osv_projects.json")
    raw = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"project OSV index must be an object: {index_path}")
    records: list[OsvRecord] = []
    for item in raw.get("records", []):
        parsed = parse_osv_record(
            {
                "id": item["id"],
                "summary": item.get("summary", ""),
                "details": item.get("details", ""),
                "references": [
                    {"url": f"https://issues.oss-fuzz.com/issues/{issue_id}"}
                    for issue_id in item.get("issue_ids", [])
                ],
                "affected": [
                    {
                        "package": {"name": item.get("project", "")},
                        "ranges": [
                            {
                                "type": "GIT",
                                "events": [
                                    {"fixed": commit} for commit in item.get("fixed_commits", [])
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        if parsed is None:
            raise ValueError(f"project index record {item.get('id')} did not parse")
        if list(parsed.state) != list(item.get("state", [])):
            raise ValueError(f"project index record {item.get('id')} changed crash state on load")
        records.append(parsed)
    aliases = {int(old): int(new) for old, new in raw.get("issue_aliases", [])}
    projects = tuple(raw.get("projects", []))
    return ProjectIndex(
        index=OsvIndex(records, aliases),
        archive_sha256=str(raw["archive_sha256"]),
        mapping_sha256=str(raw["mapping_sha256"]),
        projects=projects,
    )


def _signature_from_saved_card(card: TriageCard) -> CrashSignature:
    vulnerable = next(operation for operation in card.sandbox_operations if operation.kind == "vul")
    return parse_crash(vulnerable.stderr)


def build_door_assets(
    *,
    checkpoints: Path,
    archive: Path,
    mapping: Path,
    evaluation: Path,
    output: Path,
    arvo_db: Path | None = None,
    slices: Path | None = None,
    cards: Path | None = None,
) -> dict[str, Any]:
    """Write the manifest, catalog, and project index. Raise if a source disagrees."""

    report = EvalReport.model_validate_json(evaluation.read_text(encoding="utf-8"))
    unknown = sorted({task.project for task in report.tasks}.difference(DOOR_PROJECTS))
    if unknown:
        raise ValueError(f"eval projects are outside the door index: {', '.join(unknown)}")

    archive_sha256 = file_sha256(archive)
    if archive_sha256 != report.provenance.osv_archive_sha256:
        raise ValueError(
            "OSV archive hash does not match eval provenance: "
            f"{archive_sha256} != {report.provenance.osv_archive_sha256}"
        )
    mapping_sha256 = file_sha256(mapping)
    if mapping_sha256 != report.provenance.monorail_mapping_sha256:
        raise ValueError(
            "OSS-Fuzz mapping hash does not match eval provenance: "
            f"{mapping_sha256} != {report.provenance.monorail_mapping_sha256}"
        )

    registry = json.loads(checkpoints.read_text(encoding="utf-8"))
    if not isinstance(registry, dict):
        raise ValueError("checkpoint registry must be a JSON object")

    if arvo_db is not None:
        from reproof.arvo import ArvoRepository

        database_sha256 = file_sha256(arvo_db)
        if database_sha256 != report.provenance.arvo_database_sha256:
            raise ValueError(
                "ARVO database hash does not match eval provenance: "
                f"{database_sha256} != {report.provenance.arvo_database_sha256}"
            )
        repository = ArvoRepository(arvo_db)
    else:
        repository = None

    records: list[OsvRecord] = []
    with zipfile.ZipFile(archive) as bundle:
        for name in bundle.namelist():
            if not name.endswith(".json"):
                continue
            parsed = parse_osv_record(json.loads(bundle.read(name)))
            if parsed is not None and parsed.project in DOOR_PROJECTS:
                records.append(parsed)
    by_osv_id = {record.id: record for record in records}

    issue_ids = {issue_id for record in records for issue_id in record.issue_ids}
    task_ids = {task.arvo_id for task in report.tasks}
    full_mapping = load_issue_mapping(mapping)
    aliases = [
        [old, new]
        for old, new in sorted(full_mapping.items())
        if old in issue_ids or new in issue_ids or old in task_ids or new in task_ids
    ]
    project_index = OsvIndex(records, {old: new for old, new in aliases})

    manifest_tasks: dict[str, Any] = {}
    catalog_tasks: list[dict[str, Any]] = []
    for task in report.tasks:
        osv_id = task.card_provenance.osv_record_id
        if osv_id is None or osv_id not in by_osv_id:
            raise ValueError(f"ARVO {task.arvo_id} OSV record {osv_id} is not in the project index")
        chosen = by_osv_id[osv_id]
        report_sha256 = text_sha256(chosen.report_text)
        if report_sha256 != task.card_provenance.report_sha256:
            raise ValueError(f"ARVO {task.arvo_id} report hash does not match {osv_id}")
        excluded = {record.id for record in project_index.for_issue(task.arvo_id)}
        if osv_id not in excluded:
            raise ValueError(f"{osv_id} is not excluded for ARVO {task.arvo_id}")
        for candidate in task.duplicate_candidates:
            if candidate in excluded:
                raise ValueError(f"eval candidate {candidate} is an excluded id for {task.arvo_id}")

        if repository is not None:
            task_hash = arvo_task_sha256(repository.get(task.arvo_id))
            if task_hash != task.card_provenance.arvo_task_sha256:
                raise ValueError(f"ARVO {task.arvo_id} task hash does not match the eval card")

        kinds: dict[str, Any] = {}
        for kind in ("vul", "fix"):
            digest = task.slice_manifest_sha256[kind]
            entry = _registry_entry(registry, task.arvo_id, kind, digest)
            if slices is not None:
                slice_dir = slices / f"{task.arvo_id}-{kind}"
                if manifest_digest(slice_dir) != digest:
                    raise ValueError(f"slice manifest hash mismatch for {task.arvo_id} {kind}")
            kinds[kind] = _checkpoint_block(entry, digest)
        if cards is not None:
            card = TriageCard.model_validate_json(
                (cards / f"{task.arvo_id}.json").read_text(encoding="utf-8")
            )
            measured = _signature_from_saved_card(card)
            found = [
                candidate.id
                for candidate in project_index.find_candidates(
                    task.project,
                    measured,
                    excluded_osv_ids=sorted(excluded),
                )
            ]
            if found != list(task.duplicate_candidates):
                raise ValueError(
                    f"ARVO {task.arvo_id} duplicate candidates {found} "
                    f"do not match the eval {list(task.duplicate_candidates)}"
                )

        manifest_tasks[str(task.arvo_id)] = {
            "project": task.project,
            "osv_record_id": osv_id,
            "arvo_task_sha256": task.card_provenance.arvo_task_sha256,
            "vul": kinds["vul"],
            "fix": kinds["fix"],
        }
        catalog_tasks.append(
            {
                "arvo_id": task.arvo_id,
                "project": task.project,
                "osv_record_id": osv_id,
                "report_source": (
                    f"public OSS-Fuzz OSV report {osv_id}; this is not a private report"
                ),
                "report_sha256": report_sha256,
                "report_text": chosen.report_text,
                "arvo_task_sha256": task.card_provenance.arvo_task_sha256,
            }
        )

    output.mkdir(parents=True, exist_ok=True)
    _write_json(
        output / "checkpoints.json",
        {
            "schema_version": SCHEMA_VERSION,
            "retention_days": 180,
            "tasks": manifest_tasks,
        },
    )
    _write_json(
        output / "catalog.json",
        {
            "schema_version": SCHEMA_VERSION,
            "selection_rule": report.selection_rule,
            "tasks": catalog_tasks,
        },
    )
    _write_json(
        output / "osv_projects.json",
        {
            "schema_version": SCHEMA_VERSION,
            "projects": sorted(DOOR_PROJECTS),
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
        "tasks": len(catalog_tasks),
        "osv_records": len(records),
        "issue_aliases": len(aliases),
        "archive_sha256": archive_sha256,
        "mapping_sha256": mapping_sha256,
        "output": str(output),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reproof.door_data")
    parser.add_argument("--checkpoints", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--eval", type=Path, default=Path("eval/results/arvo10.json"))
    parser.add_argument("--output", type=Path, default=ASSETS_DIR)
    parser.add_argument("--arvo-db", type=Path)
    parser.add_argument("--slices", type=Path)
    parser.add_argument("--cards", type=Path)
    args = parser.parse_args(argv)
    summary = build_door_assets(
        checkpoints=args.checkpoints,
        archive=args.archive,
        mapping=args.mapping,
        evaluation=args.eval,
        output=args.output,
        arvo_db=args.arvo_db,
        slices=args.slices,
        cards=args.cards,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
