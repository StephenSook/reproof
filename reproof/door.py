"""Run one triage from a named ConTree checkpoint.

The local runtime slices are not read. They are only an input to checkpoint
creation, and this entry point never creates a checkpoint.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterator
from typing import Any, Literal

from pydantic import Field, model_validator

from reproof.claims import compare_claim, extract_claim
from reproof.crash import (
    DIRTY_FIX_DETAIL,
    ambiguous_vulnerable_detail,
    is_conclusive_crash,
    looks_clean,
    parse_crash,
    sanitizer_excerpt,
)
from reproof.door_data import ProjectIndex, load_catalog, load_manifest, load_project_index
from reproof.models import (
    Claim,
    CrashEvidence,
    ModelCall,
    SandboxOperation,
    StrictModel,
    TriageCard,
    TriageEvidence,
    TriageProvenance,
    Verdict,
)
from reproof.provenance import source_sha256, text_sha256
from reproof.sandbox import CheckpointError, SandboxRunner
from reproof.triage import _verdict

SECRET_ENV_NAMES = ("NEBIUS_API_KEY", "NEBIUS_PROJECT_ID")
NO_LOCAL_SLICE = "The server does not create a replacement checkpoint from a local slice."
ClaimExtractor = Callable[[str], tuple[Claim, ModelCall]]


class DoorStep(StrictModel):
    step: Literal["claim", "sandbox", "crash", "duplicates", "verdict"]
    kind: Literal["vul", "fix"] | None = None
    payload: dict[str, Any]

    @model_validator(mode="after")
    def check_branch(self) -> DoorStep:
        if self.step == "sandbox" and self.kind not in {"vul", "fix"}:
            raise ValueError("a sandbox step must name the vul or fix branch")
        if self.step != "sandbox" and self.kind is not None:
            raise ValueError("only a sandbox step names a branch")
        return self


class DoorResult(StrictModel):
    schema_version: Literal["1"] = "1"
    arvo_id: int
    verdict: Verdict
    reason: str
    missing_details: list[str]
    steps: list[DoorStep]
    card: TriageCard | None = None
    wall_seconds: float = Field(ge=0)


def scrub_text(value: str) -> str:
    """Remove live credential values from text that can leave the server."""

    redacted = value
    for name in SECRET_ENV_NAMES:
        secret = os.environ.get(name) or ""
        if len(secret) >= 8:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def public_payload(result: DoorResult) -> dict[str, Any]:
    value = json.loads(scrub_text(result.model_dump_json()))
    if not isinstance(value, dict):
        raise ValueError("door result must be a JSON object")
    return value


def _step(
    step: Literal["claim", "sandbox", "crash", "duplicates", "verdict"],
    payload: dict[str, Any],
    *,
    kind: Literal["vul", "fix"] | None = None,
) -> DoorStep:
    cleaned = json.loads(scrub_text(json.dumps(payload, sort_keys=True)))
    if not isinstance(cleaned, dict):
        raise ValueError("door step payload must be a JSON object")
    return DoorStep(step=step, kind=kind, payload=cleaned)


def _task_row(catalog: dict[str, Any], arvo_id: int) -> dict[str, Any] | None:
    tasks = catalog.get("tasks")
    if not isinstance(tasks, list):
        return None
    for task in tasks:
        if isinstance(task, dict) and task.get("arvo_id") == arvo_id:
            return task
    return None


def _checkpoint_row(manifest: dict[str, Any], arvo_id: int) -> dict[str, Any] | None:
    tasks = manifest.get("tasks")
    if not isinstance(tasks, dict):
        return None
    row = tasks.get(str(arvo_id))
    return row if isinstance(row, dict) else None


def _missing_checkpoint_reason(manifest: dict[str, Any], arvo_id: int) -> str | None:
    row = _checkpoint_row(manifest, arvo_id)
    if row is None:
        return f"ARVO {arvo_id} has no committed ConTree checkpoint. {NO_LOCAL_SLICE}"
    missing = [
        kind
        for kind in ("vul", "fix")
        if not isinstance(row.get(kind), dict) or not str(row[kind].get("checkpoint_uuid") or "")
    ]
    if not missing:
        return None
    return f"ARVO {arvo_id} {' and '.join(missing)} checkpoint is missing. {NO_LOCAL_SLICE}"


def _id_payload(error: BaseException, model_request_id: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {"reason": scrub_text(str(error))}
    request_ids: list[str] = []
    if model_request_id:
        request_ids.append(model_request_id)
    own_request_id = getattr(error, "request_id", None)
    if own_request_id:
        request_ids.append(str(own_request_id))
    for request_id in getattr(error, "request_ids", None) or []:
        if request_id:
            request_ids.append(str(request_id))
    deduped = list(dict.fromkeys(request_ids))
    if deduped:
        payload["request_ids"] = deduped
    operation_uuids = {
        str(kind): str(operation_id)
        for kind, operation_id in dict(getattr(error, "operation_uuids", None) or {}).items()
        if operation_id
    }
    if operation_uuids:
        payload["operation_uuids"] = operation_uuids
    checkpoint_uuids = {
        str(kind): str(checkpoint_id)
        for kind, checkpoint_id in dict(getattr(error, "checkpoint_uuids", None) or {}).items()
        if checkpoint_id
    }
    if checkpoint_uuids:
        payload["checkpoint_uuids"] = checkpoint_uuids
    return payload


def _needs_info(
    arvo_id: int,
    reason: str,
    *,
    started: float,
    steps: list[DoorStep],
    extra_payload: dict[str, Any] | None = None,
) -> DoorResult:
    cleaned = scrub_text(reason)
    payload: dict[str, Any] = {"verdict": Verdict.NEEDS_INFO.value, "reason": cleaned}
    if extra_payload:
        payload.update(extra_payload)
        payload["reason"] = cleaned
    verdict_step = _step("verdict", payload)
    return DoorResult(
        arvo_id=arvo_id,
        verdict=Verdict.NEEDS_INFO,
        reason=cleaned,
        missing_details=[cleaned],
        steps=[*steps, verdict_step],
        card=None,
        wall_seconds=round(time.perf_counter() - started, 6),
    )


def _finish(result: DoorResult) -> dict[str, Any]:
    return {"type": "result", "result": public_payload(result)}


def iter_cached_triage(
    arvo_id: int,
    *,
    catalog: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
    project_index: ProjectIndex | None = None,
    runner: SandboxRunner | None = None,
    extractor: ClaimExtractor | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield live steps, then one result. A missing checkpoint is NEEDS_INFO."""

    started = time.perf_counter()
    catalog_value = catalog if catalog is not None else load_catalog()
    manifest_value = manifest if manifest is not None else load_manifest()
    index = project_index if project_index is not None else load_project_index()
    task = _task_row(catalog_value, arvo_id)
    if task is None:
        result = _needs_info(
            arvo_id,
            f"ARVO {arvo_id} is not in the committed judge catalog. {NO_LOCAL_SLICE}",
            started=started,
            steps=[],
        )
        yield {"type": "step", "step": result.steps[-1].model_dump(mode="json")}
        yield _finish(result)
        return

    missing = _missing_checkpoint_reason(manifest_value, arvo_id)
    if missing is not None:
        result = _needs_info(arvo_id, missing, started=started, steps=[])
        yield {"type": "step", "step": result.steps[-1].model_dump(mode="json")}
        yield _finish(result)
        return

    row = _checkpoint_row(manifest_value, arvo_id)
    if row is None:
        raise RuntimeError("checkpoint row disappeared after the missing-checkpoint check")
    active_runner = runner or SandboxRunner()
    try:
        vulnerable_checkpoint = active_runner.open_checkpoint("vul", row["vul"])
        fixed_checkpoint = active_runner.open_checkpoint("fix", row["fix"])
    except CheckpointError as error:
        result = _needs_info(
            arvo_id,
            str(error),
            started=started,
            steps=[],
            extra_payload=_id_payload(error, None),
        )
        yield {"type": "step", "step": result.steps[-1].model_dump(mode="json")}
        yield _finish(result)
        return

    report_text = str(task["report_text"])
    recorded_report_hash = str(task.get("report_sha256") or "")
    if recorded_report_hash and recorded_report_hash != text_sha256(report_text):
        result = _needs_info(
            arvo_id,
            "Catalog report hash does not match the stored report text.",
            started=started,
            steps=[],
        )
        yield {"type": "step", "step": result.steps[-1].model_dump(mode="json")}
        yield _finish(result)
        return

    active_extractor = extractor or extract_claim
    try:
        claim, model_call = active_extractor(report_text)
    except Exception as error:
        result = _needs_info(
            arvo_id,
            f"Claim extraction failed: {error}",
            started=started,
            steps=[],
            extra_payload=_id_payload(error, None),
        )
        yield {"type": "step", "step": result.steps[-1].model_dump(mode="json")}
        yield _finish(result)
        return

    steps: list[DoorStep] = [
        _step(
            "claim",
            {
                "model": model_call.model,
                "request_id": model_call.request_id,
                "input_tokens": model_call.input_tokens,
                "output_tokens": model_call.output_tokens,
                "total_tokens": model_call.total_tokens,
                "cost_usd": model_call.cost_usd,
                "latency_seconds": model_call.latency_seconds,
                "bug_class": claim.bug_class,
                "functions": claim.functions,
            },
        )
    ]
    yield {"type": "step", "step": steps[-1].model_dump(mode="json")}

    try:
        vulnerable, fixed = active_runner.run_pair(
            arvo_id,
            vulnerable_checkpoint,
            fixed_checkpoint,
        )
    except Exception as error:
        result = _needs_info(
            arvo_id,
            f"Sandbox run failed: {error}",
            started=started,
            steps=steps,
            extra_payload=_id_payload(error, model_call.request_id),
        )
        yield {"type": "step", "step": result.steps[-1].model_dump(mode="json")}
        yield _finish(result)
        return

    for operation in (vulnerable, fixed):
        steps.append(_sandbox_step(operation))
        yield {"type": "step", "step": steps[-1].model_dump(mode="json")}

    card = _build_card(
        arvo_id=arvo_id,
        task=task,
        row=row,
        index=index,
        claim=claim,
        model_call=model_call,
        vulnerable=vulnerable,
        fixed=fixed,
        started=started,
    )
    measured = parse_crash(vulnerable.stderr)
    fixed_measured = parse_crash(fixed.stderr)
    vulnerable_crashed = is_conclusive_crash(vulnerable.exit_code, measured)
    vulnerable_clean = looks_clean(vulnerable.exit_code, vulnerable.stderr) and not measured.state
    fixed_clean = looks_clean(fixed.exit_code, fixed.stderr) and not fixed_measured.state
    steps.append(
        _step(
            "crash",
            {
                "crash_type": measured.crash_type if vulnerable_crashed else "",
                "crash_state": list(measured.state) if vulnerable_crashed else [],
                "sanitizer_kind": measured.sanitizer_kind or "",
                "vulnerable_crashed": vulnerable_crashed,
                "vulnerable_clean": vulnerable_clean,
                "fix_clean": fixed_clean,
                "fixed_exit_code": fixed.exit_code,
            },
        )
    )
    yield {"type": "step", "step": steps[-1].model_dump(mode="json")}
    steps.append(
        _step(
            "duplicates",
            {
                "excluded_osv_ids": card.evidence.excluded_osv_ids,
                "candidates": [
                    {
                        "id": candidate.id,
                        "summary": candidate.summary,
                        "match_kind": candidate.match_kind,
                        "fixed_commits": candidate.fixed_commits,
                    }
                    for candidate in card.evidence.duplicate_candidates
                ],
            },
        )
    )
    yield {"type": "step", "step": steps[-1].model_dump(mode="json")}
    steps.append(
        _step(
            "verdict",
            {
                "verdict": card.verdict.value,
                "missing_details": card.missing_details,
                "model_cost_usd": card.model_cost_usd,
                "sandbox_cost_usd": card.sandbox_cost_usd,
                "total_cost_usd": card.total_cost_usd,
                "wall_seconds": card.wall_seconds,
                "checkpoint_cost_usd": round(
                    sum(operation.checkpoint_cost_usd for operation in card.sandbox_operations),
                    8,
                ),
                "run_cost_usd": round(
                    sum(operation.cost_usd or 0.0 for operation in card.sandbox_operations),
                    8,
                ),
            },
        )
    )
    yield {"type": "step", "step": steps[-1].model_dump(mode="json")}
    result = DoorResult(
        arvo_id=arvo_id,
        verdict=card.verdict,
        reason="",
        missing_details=list(card.missing_details),
        steps=steps,
        card=card,
        wall_seconds=card.wall_seconds,
    )
    yield _finish(result)


def run_cached_triage(
    arvo_id: int,
    *,
    catalog: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
    project_index: ProjectIndex | None = None,
    runner: SandboxRunner | None = None,
    extractor: ClaimExtractor | None = None,
) -> DoorResult:
    """Run one cached triage and return its result, including a NEEDS_INFO refusal."""

    found: DoorResult | None = None
    for event in iter_cached_triage(
        arvo_id,
        catalog=catalog,
        manifest=manifest,
        project_index=project_index,
        runner=runner,
        extractor=extractor,
    ):
        if event["type"] == "result":
            found = DoorResult.model_validate(event["result"])
    if found is None:
        raise RuntimeError("cached triage produced no result")
    return found


def _sandbox_step(operation: SandboxOperation) -> DoorStep:
    kind: Literal["vul", "fix"] = "vul" if operation.kind == "vul" else "fix"
    return _step(
        "sandbox",
        {
            "checkpoint_uuid": operation.checkpoint_uuid,
            "checkpoint_operation_uuid": operation.checkpoint_operation_uuid,
            "operation_uuid": operation.operation_uuid,
            "wall_seconds": operation.wall_seconds,
            "server_elapsed_seconds": operation.server_elapsed_seconds,
            "exit_code": operation.exit_code,
            "cost_usd": operation.cost_usd,
            "checkpoint_cost_usd": operation.checkpoint_cost_usd,
            "checkpoint_wall_seconds": operation.checkpoint_wall_seconds,
        },
        kind=kind,
    )


def _build_card(
    *,
    arvo_id: int,
    task: dict[str, Any],
    row: dict[str, Any],
    index: ProjectIndex,
    claim: Claim,
    model_call: ModelCall,
    vulnerable: SandboxOperation,
    fixed: SandboxOperation,
    started: float,
) -> TriageCard:
    measured = parse_crash(vulnerable.stderr)
    fixed_measured = parse_crash(fixed.stderr)
    vulnerable_crashed = is_conclusive_crash(vulnerable.exit_code, measured)
    vulnerable_clean = looks_clean(vulnerable.exit_code, vulnerable.stderr) and not measured.state
    fixed_clean = looks_clean(fixed.exit_code, fixed.stderr) and not fixed_measured.state
    excluded_osv_ids = sorted({record.id for record in index.index.for_issue(arvo_id)})
    duplicates = (
        index.index.find_candidates(
            str(task["project"]),
            measured,
            excluded_osv_ids=excluded_osv_ids,
        )
        if vulnerable_crashed
        else []
    )
    comparison = compare_claim(claim, measured)
    missing_details = list(dict.fromkeys(claim.missing_details))
    if not vulnerable_crashed and not vulnerable_clean:
        missing_details.append(
            ambiguous_vulnerable_detail(
                vulnerable.exit_code,
                measured.sanitizer_kind,
                has_usable_frames=measured.crashed,
            )
        )
    if not fixed_clean:
        missing_details.append(DIRTY_FIX_DETAIL)
    report_text = str(task["report_text"])
    osv_record_id = str(task["osv_record_id"])
    report_source = str(
        task.get("report_source")
        or f"public OSS-Fuzz OSV report {osv_record_id}; this is not a private report"
    )
    operations = [vulnerable, fixed]
    sandbox_cost = round(
        sum(
            operation.checkpoint_cost_usd + (operation.cost_usd or 0.0) for operation in operations
        ),
        8,
    )
    source_hash = source_sha256()
    return TriageCard(
        arvo_id=arvo_id,
        project=str(task["project"]),
        report_source=report_source,
        report_text=report_text,
        verdict=_verdict(vulnerable_crashed, vulnerable_clean, fixed_clean, len(duplicates)),
        missing_details=missing_details,
        evidence=TriageEvidence(
            crash=(
                CrashEvidence(
                    crash_type=measured.crash_type,
                    crash_state=list(measured.state),
                    sanitizer_excerpt=sanitizer_excerpt(measured),
                    sanitizer_kind=measured.sanitizer_kind or "",
                )
                if vulnerable_crashed
                else None
            ),
            fix_clean=fixed_clean,
            fixed_exit_code=fixed.exit_code,
            excluded_osv_ids=excluded_osv_ids,
            duplicate_candidates=duplicates,
            claim_vs_evidence=comparison,
            inputs_tried=["stored ARVO PoC at /tmp/poc"],
        ),
        model_calls=[model_call],
        sandbox_operations=operations,
        slice_manifest_sha256={
            "vul": str(row["vul"]["manifest_sha256"]),
            "fix": str(row["fix"]["manifest_sha256"]),
        },
        provenance=TriageProvenance(
            arvo_task_sha256=str(task["arvo_task_sha256"]),
            report_sha256=text_sha256(report_text),
            osv_archive_sha256=index.archive_sha256,
            monorail_mapping_sha256=index.mapping_sha256,
            execution_source_sha256=source_hash,
            derivation_source_sha256=source_hash,
            derivation_method="live-execution",
            osv_record_id=osv_record_id,
        ),
        model_cost_usd=model_call.cost_usd,
        sandbox_cost_usd=sandbox_cost,
        total_cost_usd=round(model_call.cost_usd + sandbox_cost, 8),
        wall_seconds=round(time.perf_counter() - started, 6),
    )
