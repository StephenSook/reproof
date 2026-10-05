"""Run measured reproduction, duplicate matching, and claim comparison."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any

from reproof.arvo import ArvoRepository, ArvoTask
from reproof.claims import compare_claim, extract_claim
from reproof.crash import (
    DIRTY_FIX_DETAIL,
    ambiguous_vulnerable_detail,
    looks_clean,
    parse_crash,
    sanitizer_excerpt,
)
from reproof.dup import (
    OsvIndex,
    OsvRecord,
    default_mapping_path,
    ensure_osv_archive,
    frames_match,
)
from reproof.errors import EvidencePersistenceError, TriageExecutionError
from reproof.models import (
    CrashEvidence,
    TriageCard,
    TriageEvidence,
    TriageProvenance,
    Verdict,
)
from reproof.provenance import arvo_task_sha256, file_sha256, source_sha256, text_sha256
from reproof.sandbox import SandboxRunner, manifest_digest
from reproof.slice import extract_runtime_slice


def _triage_failure(
    error: Exception,
    model_call: Any,
    state: dict[str, Any],
) -> TriageExecutionError:
    request_ids = [model_call.request_id]
    request_ids.extend(getattr(error, "request_ids", None) or [])
    child_request_id = getattr(error, "request_id", None)
    if child_request_id:
        request_ids.append(str(child_request_id))
    operation_uuids = dict(getattr(error, "operation_uuids", None) or {})
    checkpoint_uuids = dict(getattr(error, "checkpoint_uuids", None) or {})
    checkpoint_operation_uuids = dict(getattr(error, "checkpoint_operation_uuids", None) or {})

    runner = state.get("runner")
    for kind in ("vul", "fix"):
        checkpoint = state.get(f"{kind}_checkpoint")
        if checkpoint is not None:
            checkpoint_uuid = str(checkpoint.uuid)
            checkpoint_uuids.setdefault(kind, checkpoint_uuid)
            metadata = getattr(runner, "checkpoint_metadata", {}).get(checkpoint_uuid, {})
            operation_id = metadata.get("operation_uuid")
            if operation_id:
                checkpoint_operation_uuids.setdefault(kind, str(operation_id))
    for operation in state.get("operations", []):
        if operation.operation_uuid is not None:
            operation_uuids[operation.kind] = operation.operation_uuid
        checkpoint_uuids.setdefault(operation.kind, operation.checkpoint_uuid)
        if operation.checkpoint_operation_uuid is not None:
            checkpoint_operation_uuids.setdefault(
                operation.kind, operation.checkpoint_operation_uuid
            )

    return TriageExecutionError(
        f"Triage failed after model request: {type(error).__name__}: {error}",
        request_ids=request_ids,
        operation_uuids=operation_uuids,
        checkpoint_uuids=checkpoint_uuids,
        checkpoint_operation_uuids=checkpoint_operation_uuids,
    )


def write_card(path: Path, card: TriageCard) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(card.model_dump_json(indent=2), encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    except Exception as error:
        operations = {operation.kind: operation for operation in card.sandbox_operations}
        raise EvidencePersistenceError(
            f"Triage card persistence failed: {type(error).__name__}: {error}",
            request_ids=[call.request_id for call in card.model_calls],
            operation_uuids={
                kind: operation.operation_uuid
                for kind, operation in operations.items()
                if operation.operation_uuid is not None
            },
            checkpoint_uuids={
                kind: operation.checkpoint_uuid for kind, operation in operations.items()
            },
            checkpoint_operation_uuids={
                kind: operation.checkpoint_operation_uuid
                for kind, operation in operations.items()
                if operation.checkpoint_operation_uuid is not None
            },
        ) from error


def _combined(stdout: str, stderr: str) -> str:
    return "\n".join(part for part in (stdout, stderr) if part)


def _select_osv_report(task: ArvoTask, index: OsvIndex) -> OsvRecord | None:
    candidates = [
        record for record in index.for_issue(task.local_id) if record.project == task.project
    ]
    if not candidates:
        return None
    baseline = parse_crash(task.crash_output)
    exact = [record for record in candidates if frames_match(baseline.state, record.state)]
    if exact:
        return exact[0]
    groups = dict(baseline.inline_groups)
    inline = [record for record in candidates if frames_match(baseline.state, record.state, groups)]
    return inline[0] if inline else candidates[0]


def crash_agrees_with_osv(task_id: int, signature_state: tuple[str, ...], index: OsvIndex) -> bool:
    """Return whether a measured crash state agrees with any mapped OSV state."""

    if not signature_state:
        return False
    return any(frames_match(signature_state, record.state) for record in index.for_issue(task_id))


def _verdict(
    crashed: bool,
    vulnerable_clean: bool,
    fix_clean: bool,
    duplicate_count: int,
) -> Verdict:
    if not fix_clean or (not crashed and not vulnerable_clean):
        return Verdict.NEEDS_INFO
    if crashed and duplicate_count:
        return Verdict.DUPLICATE
    if crashed:
        return Verdict.REPRODUCED
    if not crashed and not duplicate_count:
        return Verdict.NOT_REPRODUCED
    return Verdict.NEEDS_INFO


def run_triage(
    task_id: int,
    *,
    report_text: str | None = None,
    report_source: str | None = None,
    candidate_input: bytes | None = None,
    repository: ArvoRepository | None = None,
    osv_index: OsvIndex | None = None,
    sandbox: SandboxRunner | None = None,
    output_path: Path | None = None,
) -> TriageCard:
    """Run a single ARVO task and persist its strict triage card."""

    started = time.perf_counter()
    tasks = repository or ArvoRepository()
    index = osv_index or OsvIndex.from_archive()
    task = tasks.get(task_id)
    osv_report = _select_osv_report(task, index)
    uses_public_osv_report = report_text is None
    if report_text is None:
        if osv_report is None:
            raise ValueError(
                f"ARVO task {task_id} has no mapped public OSS-Fuzz OSV report; use --report"
            )
        report_text = osv_report.report_text
        report_source = f"public OSS-Fuzz OSV report {osv_report.id}; this is not a private report"
    elif report_source is None:
        report_source = "user-supplied local report file"

    claim, model_call = extract_claim(report_text)
    state: dict[str, Any] = {}
    try:
        return _complete_triage(
            task_id=task_id,
            task=task,
            index=index,
            osv_report=osv_report,
            uses_public_osv_report=uses_public_osv_report,
            report_text=report_text,
            report_source=report_source,
            claim=claim,
            model_call=model_call,
            candidate_input=candidate_input,
            sandbox=sandbox,
            output_path=output_path,
            started=started,
            state=state,
        )
    except Exception as error:
        raise _triage_failure(error, model_call, state) from error


def _complete_triage(
    *,
    task_id: int,
    task: ArvoTask,
    index: OsvIndex,
    osv_report: OsvRecord | None,
    uses_public_osv_report: bool,
    report_text: str,
    report_source: str,
    claim: Any,
    model_call: Any,
    candidate_input: bytes | None,
    sandbox: SandboxRunner | None,
    output_path: Path | None,
    started: float,
    state: dict[str, Any],
) -> TriageCard:
    slice_root = Path("slices")
    vul_dir = slice_root.resolve() / f"{task_id}-vul"
    fix_dir = slice_root.resolve() / f"{task_id}-fix"
    extract_runtime_slice(task_id, "vul", task.fuzz_target, slice_root)
    extract_runtime_slice(task_id, "fix", task.fuzz_target, slice_root)

    runner = sandbox or SandboxRunner()
    state["runner"] = runner
    vulnerable_checkpoint = runner.ensure_checkpoint(task_id, "vul", vul_dir)
    state["vul_checkpoint"] = vulnerable_checkpoint
    fixed_checkpoint = runner.ensure_checkpoint(task_id, "fix", fix_dir)
    state["fix_checkpoint"] = fixed_checkpoint
    vulnerable, fixed = runner.run_pair(
        task_id,
        vulnerable_checkpoint,
        fixed_checkpoint,
        candidate_input=candidate_input,
    )
    state["operations"] = [vulnerable, fixed]

    vulnerable_output = _combined(vulnerable.stdout, vulnerable.stderr)
    fixed_output = _combined(fixed.stdout, fixed.stderr)
    measured = parse_crash(vulnerable_output)
    vulnerable_clean = looks_clean(vulnerable.exit_code, vulnerable_output) and not measured.state
    fixed_clean = looks_clean(fixed.exit_code, fixed_output)
    duplicates = index.find_candidates(task.project, measured)
    comparison = compare_claim(claim, measured)
    missing_details = list(dict.fromkeys(claim.missing_details))
    if not measured.crashed and not vulnerable_clean:
        missing_details.append(ambiguous_vulnerable_detail(vulnerable.exit_code))
    if not fixed_clean:
        missing_details.append(DIRTY_FIX_DETAIL)

    input_label = "stored ARVO PoC at /tmp/poc"
    if candidate_input is not None:
        digest = hashlib.sha256(candidate_input).hexdigest()
        input_label = f"candidate input sha256:{digest} uploaded as /tmp/poc"

    evidence = TriageEvidence(
        crash=(
            CrashEvidence(
                crash_type=measured.crash_type,
                crash_state=list(measured.state),
                sanitizer_excerpt=sanitizer_excerpt(measured),
                sanitizer_kind=measured.sanitizer_kind or "",
            )
            if measured.crashed
            else None
        ),
        fix_clean=fixed_clean,
        fixed_exit_code=fixed.exit_code,
        duplicate_candidates=duplicates,
        claim_vs_evidence=comparison,
        inputs_tried=[input_label],
    )
    operations = [vulnerable, fixed]
    sandbox_cost = round(
        sum(
            operation.checkpoint_cost_usd + (operation.cost_usd or 0.0) for operation in operations
        ),
        8,
    )
    card = TriageCard(
        arvo_id=task_id,
        project=task.project,
        report_source=report_source,
        report_text=report_text,
        verdict=_verdict(measured.crashed, vulnerable_clean, fixed_clean, len(duplicates)),
        missing_details=missing_details,
        evidence=evidence,
        model_calls=[model_call],
        sandbox_operations=operations,
        slice_manifest_sha256={
            "vul": manifest_digest(vul_dir),
            "fix": manifest_digest(fix_dir),
        },
        provenance=TriageProvenance(
            arvo_task_sha256=arvo_task_sha256(task),
            report_sha256=text_sha256(report_text),
            osv_archive_sha256=file_sha256(ensure_osv_archive()),
            monorail_mapping_sha256=file_sha256(default_mapping_path()),
            execution_source_sha256=source_sha256(),
            derivation_source_sha256=source_sha256(),
            derivation_method="live-execution",
            osv_record_id=(
                osv_report.id if uses_public_osv_report and osv_report is not None else None
            ),
        ),
        model_cost_usd=model_call.cost_usd,
        sandbox_cost_usd=sandbox_cost,
        total_cost_usd=round(model_call.cost_usd + sandbox_cost, 8),
        wall_seconds=round(time.perf_counter() - started, 6),
    )
    destination = output_path or Path("eval/results/cards") / f"{task_id}.json"
    write_card(destination, card)
    return card
