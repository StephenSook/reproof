"""Refresh derived eval fields from saved measurements without rerunning paid work."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from contree_sdk import ContreeSync

from reproof.arvo import ArvoRepository
from reproof.claims import compare_claim
from reproof.crash import looks_clean, parse_crash, sanitizer_excerpt
from reproof.dup import OsvIndex, default_mapping_path, ensure_osv_archive
from reproof.models import Claim, TriageCard, TriageProvenance
from reproof.provenance import (
    arvo_task_sha256,
    derivation_source_sha256,
    file_sha256,
    text_sha256,
)
from reproof.sandbox import CheckpointRegistry, manifest_digest
from reproof.triage import _verdict, write_card

CARDS = Path("eval/results/cards")
DIRTY_FIX_DETAIL = "The fixed build did not exit cleanly; inspect its captured stdout and stderr."


async def operation_measurement(client: ContreeSync, operation_id: str) -> tuple[float, float]:
    operation = await client._api.get_operation_status(operation_id)
    if str(operation.status) != "SUCCESS":
        raise RuntimeError(f"ConTree operation {operation_id} status is {operation.status}")
    result = operation.metadata.result
    if result is None or result.resources is None:
        raise RuntimeError(f"ConTree operation {operation_id} omitted resource measurements")
    return float(operation.duration), float(result.resources.cost)


def _claim_from_rows(raw: dict[str, Any]) -> Claim:
    rows = {row["field"]: row for row in raw["evidence"]["claim_vs_evidence"]}
    if set(rows) != {"bug_class", "functions"}:
        raise ValueError(f"card {raw['arvo_id']} lacks the two required comparison rows")
    claimed_functions = rows["functions"]["claimed"]
    if not isinstance(claimed_functions, list):
        raise ValueError(f"card {raw['arvo_id']} has a non-list claimed function value")
    return Claim(
        project=str(raw["project"]),
        bug_class=str(rows["bug_class"]["claimed"]),
        functions=[str(value) for value in claimed_functions],
        files=[],
        trigger="",
        poc_attached=True,
        affected_version="",
        missing_details=[],
    )


async def refresh(legacy_execution_source_sha256: str | None = None) -> None:
    client = ContreeSync()
    index = OsvIndex.from_archive()
    repository = ArvoRepository()
    registry_store = CheckpointRegistry()
    registry = registry_store.read()
    measurements: dict[str, tuple[float, float]] = {}

    for path in sorted(CARDS.glob("*.json")):
        if not path.stem.isdigit():
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        operations = raw["sandbox_operations"]
        by_kind = {operation["kind"]: operation for operation in operations}
        if set(by_kind) != {"vul", "fix"}:
            raise ValueError(f"card {path} does not contain one vul and one fix operation")

        for operation in operations:
            operation_id = operation.get("checkpoint_operation_uuid")
            if operation_id:
                if operation_id not in measurements:
                    measurements[operation_id] = await operation_measurement(client, operation_id)
                duration, cost = measurements[operation_id]
                operation["checkpoint_wall_seconds"] = round(duration, 6)
                operation["checkpoint_cost_usd"] = cost
                print(
                    f"checkpoint_operation_uuid={operation_id} status=SUCCESS cost_usd={cost:.8f}"
                )

        vulnerable = by_kind["vul"]
        fixed = by_kind["fix"]
        vulnerable_output = "\n".join((vulnerable["stdout"], vulnerable["stderr"]))
        measured = parse_crash(vulnerable_output)
        vulnerable_clean = (
            looks_clean(int(vulnerable["exit_code"]), vulnerable_output) and not measured.state
        )
        fixed_clean = looks_clean(
            int(fixed["exit_code"]), "\n".join((fixed["stdout"], fixed["stderr"]))
        )
        duplicates = index.find_candidates(str(raw["project"]), measured)
        comparison = compare_claim(_claim_from_rows(raw), measured)
        missing_details = [
            detail
            for detail in raw["missing_details"]
            if detail != DIRTY_FIX_DETAIL
            and not detail.startswith(
                "The vulnerable build did not produce a recognized sanitizer trace"
            )
        ]
        if not measured.crashed and not vulnerable_clean:
            missing_details.append(
                "The vulnerable build did not produce a recognized sanitizer trace and did not "
                f"complete cleanly (exit code {vulnerable['exit_code']}); inspect its captured "
                "stdout and stderr."
            )
        if not fixed_clean:
            missing_details.append(DIRTY_FIX_DETAIL)

        task = repository.get(int(raw["arvo_id"]))
        matching_records = [
            record
            for record in index.for_issue(task.local_id)
            if record.report_text == raw["report_text"]
        ]
        if len(matching_records) != 1:
            raise ValueError(
                f"card {path} report matched {len(matching_records)} mapped OSV records"
            )
        record_id = matching_records[0].id

        raw["schema_version"] = "1.4"
        raw["verdict"] = _verdict(
            measured.crashed,
            vulnerable_clean,
            fixed_clean,
            len(duplicates),
        ).value
        raw["missing_details"] = missing_details
        raw["evidence"]["crash"] = (
            {
                "crash_type": measured.crash_type,
                "crash_state": list(measured.state),
                "sanitizer_excerpt": sanitizer_excerpt(measured),
                "sanitizer_kind": measured.sanitizer_kind,
            }
            if measured.crashed
            else None
        )
        raw["evidence"]["fix_clean"] = fixed_clean
        raw["evidence"]["fixed_exit_code"] = int(fixed["exit_code"])
        raw["evidence"]["duplicate_candidates"] = [
            candidate.model_dump() for candidate in duplicates
        ]
        raw["evidence"]["claim_vs_evidence"] = [row.model_dump() for row in comparison]
        raw["slice_manifest_sha256"] = {
            kind: manifest_digest(Path("slices").resolve() / f"{raw['arvo_id']}-{kind}")
            for kind in ("vul", "fix")
        }
        existing_provenance = raw.get("provenance", {})
        execution_source_sha256 = existing_provenance.get("execution_source_sha256")
        if execution_source_sha256 is None:
            execution_source_sha256 = legacy_execution_source_sha256
        if execution_source_sha256 is None:
            raise ValueError(
                f"card {path} lacks immutable execution provenance; "
                "pass --legacy-execution-source-sha256 once"
            )
        raw["provenance"] = TriageProvenance(
            arvo_task_sha256=arvo_task_sha256(task),
            report_sha256=text_sha256(raw["report_text"]),
            osv_archive_sha256=file_sha256(ensure_osv_archive()),
            monorail_mapping_sha256=file_sha256(default_mapping_path()),
            execution_source_sha256=execution_source_sha256,
            derivation_source_sha256=derivation_source_sha256(),
            derivation_method="saved-output-refresh",
            osv_record_id=record_id,
        ).model_dump()
        sandbox_cost = sum(
            float(operation["checkpoint_cost_usd"]) + float(operation.get("cost_usd") or 0.0)
            for operation in operations
        )
        raw["sandbox_cost_usd"] = round(sandbox_cost, 8)
        raw["total_cost_usd"] = round(float(raw["model_cost_usd"]) + sandbox_cost, 8)
        card = TriageCard.model_validate(raw)
        write_card(path, card)
        print(
            f"refreshed={path.as_posix()} verdict={card.verdict.value} "
            f"sanitizer={card.evidence.crash.sanitizer_kind if card.evidence.crash else None} "
            f"cost_usd={card.total_cost_usd:.8f}"
        )

    for entry in registry.values():
        operation_id = entry.get("create_operation_uuid")
        if operation_id and operation_id in measurements:
            duration, cost = measurements[operation_id]
            entry["checkpoint_wall_seconds"] = round(duration, 6)
            entry["checkpoint_cost_usd"] = cost
    registry_store.write(registry)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-execution-source-sha256")
    arguments = parser.parse_args()
    asyncio.run(refresh(arguments.legacy_execution_source_sha256))
