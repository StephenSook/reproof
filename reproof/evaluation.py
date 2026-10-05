"""Deterministic ARVO evaluation selection and execution."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from reproof.arvo import ArvoRepository, ArvoTask
from reproof.claims import comparison_rows_agree
from reproof.crash import CrashSignature, parse_crash
from reproof.dup import (
    OsvIndex,
    default_mapping_path,
    ensure_osv_archive,
    frames_match,
)
from reproof.errors import EvidencePersistenceError
from reproof.models import (
    EvalProvenance,
    EvalReport,
    EvalTaskResult,
    EvalTotals,
    TriageCard,
    TriageProvenance,
)
from reproof.provenance import (
    arvo_task_sha256,
    derivation_source_sha256,
    file_sha256,
    source_sha256,
    text_sha256,
)
from reproof.sandbox import manifest_digest
from reproof.slice import load_cached_runtime_slice
from reproof.triage import _verdict, run_triage

REQUIRED_TASKS = (42530604, 42507851, 42496387)
SELECTION_RULE = (
    "Always include ARVO 42530604, 42507851, and 42496387. Fill the remaining slots "
    "from the spike's frozen 2026-10-05 memory-safety candidate table, restricted to tasks "
    "with a mapped public OSV record, ordered by max(vulnerable GB, fixed GB) then ARVO ID."
)
SIZE = re.compile(r"vul=([0-9.]+)GB\s+fix=([0-9.]+)GB")


def _write_report(output: Path, report: EvalReport, cards: list[TriageCard]) -> None:
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(report.model_dump_json(indent=2), encoding="utf-8", newline="\n")
        temporary.replace(output)
    except Exception as error:
        raise EvidencePersistenceError(
            f"Evaluation report persistence failed: {type(error).__name__}: {error}",
            request_ids=[call.request_id for card in cards for call in card.model_calls],
            operation_uuids={
                f"{card.arvo_id}:{operation.kind}": operation.operation_uuid
                for card in cards
                for operation in card.sandbox_operations
                if operation.operation_uuid is not None
            },
            checkpoint_uuids={
                f"{card.arvo_id}:{operation.kind}": operation.checkpoint_uuid
                for card in cards
                for operation in card.sandbox_operations
            },
            checkpoint_operation_uuids={
                f"{card.arvo_id}:{operation.kind}": operation.checkpoint_operation_uuid
                for card in cards
                for operation in card.sandbox_operations
                if operation.checkpoint_operation_uuid is not None
            },
        ) from error


def default_candidate_table() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "eval"
        / "fixtures"
        / "hub_sizes_candidates-2026-10-05.tsv"
    )


def select_tasks(n: int, index: OsvIndex, table: Path | None = None) -> list[int]:
    if n < len(REQUIRED_TASKS):
        raise ValueError(f"eval n must be at least {len(REQUIRED_TASKS)}")
    ranked: list[tuple[float, int]] = []
    source = table or default_candidate_table()
    for line in source.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) < 5 or not fields[0].isdigit():
            continue
        task_id = int(fields[0])
        match = SIZE.search(" ".join(fields[4:6]))
        if match and index.for_issue(task_id):
            ranked.append((max(float(match.group(1)), float(match.group(2))), task_id))
    selected = list(REQUIRED_TASKS)
    for _, task_id in sorted(ranked):
        if task_id not in selected:
            selected.append(task_id)
        if len(selected) == n:
            break
    if len(selected) != n:
        raise ValueError(f"selection produced {len(selected)} tasks, but {n} were requested")
    return selected


def _slice_directory(task_id: int, kind: str) -> Path:
    return Path("slices").resolve() / f"{task_id}-{kind}"


def _valid_slice(task_id: int, kind: str, fuzz_target: str) -> bool:
    image = f"n132/arvo:{task_id}-{kind}"
    return (
        load_cached_runtime_slice(
            _slice_directory(task_id, kind),
            task_id=task_id,
            kind=kind,
            image=image,
            fuzz_target=fuzz_target,
        )
        is not None
    )


def _ensure_local_or_slice(task_id: int, kind: str, fuzz_target: str) -> None:
    if _valid_slice(task_id, kind, fuzz_target):
        return
    image = f"n132/arvo:{task_id}-{kind}"
    result = subprocess.run(
        ["docker", "pull", image],
        check=False,
        capture_output=True,
        text=True,
    )
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if output:
        print(output)
    if result.returncode != 0:
        raise RuntimeError(f"docker pull {image} failed with exit {result.returncode}: {output}")


def _agrees_with_mapped_osv(task_id: int, signature: CrashSignature, index: OsvIndex) -> bool:
    groups = dict(signature.inline_groups)
    return bool(signature.state) and any(
        frames_match(signature.state, record.state)
        or frames_match(signature.state, record.state, groups)
        for record in index.for_issue(task_id)
    )


def _current_card_provenance(
    task: ArvoTask,
    report_text: str,
    osv_record_id: str | None,
    execution_source_sha256: str,
    derivation_method: str,
) -> TriageProvenance:
    return TriageProvenance(
        arvo_task_sha256=arvo_task_sha256(task),
        report_sha256=text_sha256(report_text),
        osv_archive_sha256=file_sha256(ensure_osv_archive()),
        monorail_mapping_sha256=file_sha256(default_mapping_path()),
        execution_source_sha256=execution_source_sha256,
        derivation_source_sha256=(
            source_sha256() if derivation_method == "live-execution" else derivation_source_sha256()
        ),
        derivation_method=derivation_method,
        osv_record_id=osv_record_id,
    )


def run_eval(
    n: int = 10,
    output: Path = Path("eval/results/arvo10.json"),
    *,
    resume: bool = False,
) -> EvalReport:
    repository = ArvoRepository()
    index = OsvIndex.from_archive()
    selected = select_tasks(n, index)
    results: list[EvalTaskResult] = []
    cards: list[TriageCard] = []
    for task_id in selected:
        task = repository.get(task_id)
        card_path = Path("eval/results/cards") / f"{task_id}.json"
        if resume and card_path.is_file():
            card = TriageCard.model_validate_json(card_path.read_text(encoding="utf-8"))
            if card.arvo_id != task_id:
                raise ValueError(
                    f"resume card {card_path} has ARVO ID {card.arvo_id}, expected {task_id}"
                )
            if card.project != task.project:
                raise ValueError(f"resume card {card_path} project differs from the ARVO task")
            current_records = {record.id: record for record in index.for_issue(task_id)}
            record_id = card.provenance.osv_record_id
            if record_id is None or record_id not in current_records:
                raise ValueError(f"resume card {card_path} lacks a current mapped OSV record")
            current_report = current_records[record_id].report_text
            if card.report_text != current_report:
                raise ValueError(f"resume card {card_path} report differs from current OSV record")
            expected_provenance = _current_card_provenance(
                task,
                current_report,
                record_id,
                card.provenance.execution_source_sha256,
                card.provenance.derivation_method,
            )
            if card.provenance != expected_provenance:
                raise ValueError(f"resume card {card_path} provenance is stale")
            vulnerable = next(
                operation for operation in card.sandbox_operations if operation.kind == "vul"
            )
            measured = parse_crash("\n".join((vulnerable.stdout, vulnerable.stderr)))
            expected_duplicates = index.find_candidates(task.project, measured)
            if card.evidence.duplicate_candidates != expected_duplicates:
                raise ValueError(f"resume card {card_path} duplicate evidence is stale")
            expected_verdict = _verdict(
                measured.crashed,
                card.evidence.fix_clean,
                len(expected_duplicates),
            )
            if card.verdict is not expected_verdict:
                raise ValueError(f"resume card {card_path} verdict is stale")
            for kind, expected_digest in card.slice_manifest_sha256.items():
                slice_dir = _slice_directory(task_id, kind)
                if not _valid_slice(task_id, kind, task.fuzz_target):
                    raise ValueError(f"resume card {card_path} has an invalid {kind} runtime slice")
                actual_digest = manifest_digest(slice_dir)
                if actual_digest != expected_digest:
                    raise ValueError(
                        f"resume card {card_path} has stale {kind} slice manifest: "
                        f"{expected_digest} != {actual_digest}"
                    )
            print(f"Resuming from validated card {card_path}")
        else:
            _ensure_local_or_slice(task_id, "vul", task.fuzz_target)
            _ensure_local_or_slice(task_id, "fix", task.fuzz_target)
            card = run_triage(
                task_id,
                repository=repository,
                osv_index=index,
                output_path=card_path,
            )
        cards.append(card)
        vulnerable = next(
            operation for operation in card.sandbox_operations if operation.kind == "vul"
        )
        measured = parse_crash("\n".join((vulnerable.stdout, vulnerable.stderr)))
        model_calls = card.model_calls
        results.append(
            EvalTaskResult(
                arvo_id=task_id,
                project=task.project,
                verdict=card.verdict,
                crash_state_agreement_with_osv=_agrees_with_mapped_osv(task_id, measured, index),
                fix_clean=card.evidence.fix_clean,
                duplicate_candidates=[
                    candidate.id for candidate in card.evidence.duplicate_candidates
                ],
                claim_agreement=comparison_rows_agree(card.evidence.claim_vs_evidence),
                crash_type=measured.crash_type,
                crash_state=list(measured.state),
                sanitizer_kind=measured.sanitizer_kind,
                fixed_exit_code=card.evidence.fixed_exit_code,
                model_request_ids=[
                    call.request_id for call in model_calls if call.request_id is not None
                ],
                input_tokens=sum(call.input_tokens for call in model_calls),
                output_tokens=sum(call.output_tokens for call in model_calls),
                model_cost_usd=card.model_cost_usd,
                sandbox_cost_usd=card.sandbox_cost_usd,
                checkpoint_operation_uuids=[
                    operation.checkpoint_operation_uuid
                    for operation in card.sandbox_operations
                    if operation.checkpoint_operation_uuid is not None
                ],
                sandbox_operation_uuids=[
                    operation.operation_uuid
                    for operation in card.sandbox_operations
                    if operation.operation_uuid is not None
                ],
                slice_manifest_sha256=card.slice_manifest_sha256,
                card_provenance=card.provenance,
                cost_usd=round(card.total_cost_usd, 8),
                wall_seconds=card.wall_seconds,
                card_path=str(card_path).replace("\\", "/"),
            )
        )
    execution_sources = {card.provenance.execution_source_sha256 for card in cards}
    derivation_sources = {card.provenance.derivation_source_sha256 for card in cards}
    derivation_methods = {card.provenance.derivation_method for card in cards}
    if len(execution_sources) != 1:
        raise ValueError("eval cards do not share one execution source hash")
    if len(derivation_sources) != 1 or len(derivation_methods) != 1:
        raise ValueError("eval cards do not share one derivation provenance")
    report = EvalReport(
        selection_rule=SELECTION_RULE,
        selected_arvo_ids=selected,
        provenance=EvalProvenance(
            arvo_database_sha256=file_sha256(repository.database),
            osv_archive_sha256=file_sha256(ensure_osv_archive()),
            monorail_mapping_sha256=file_sha256(default_mapping_path()),
            candidate_table_sha256=file_sha256(default_candidate_table()),
            execution_source_sha256=next(iter(execution_sources)),
            derivation_source_sha256=next(iter(derivation_sources)),
            derivation_method=next(iter(derivation_methods)),
        ),
        tasks=results,
        totals=EvalTotals(
            tasks_requested=n,
            tasks_completed=len(results),
            crash_state_agreements=sum(result.crash_state_agreement_with_osv for result in results),
            fixes_clean=sum(result.fix_clean for result in results),
            claims_agree=sum(result.claim_agreement for result in results),
            total_duplicate_candidates=sum(len(result.duplicate_candidates) for result in results),
            total_input_tokens=sum(
                call.input_tokens for card in cards for call in card.model_calls
            ),
            total_output_tokens=sum(
                call.output_tokens for card in cards for call in card.model_calls
            ),
            total_model_cost_usd=round(sum(card.model_cost_usd for card in cards), 8),
            total_sandbox_cost_usd=round(sum(card.sandbox_cost_usd for card in cards), 8),
            total_cost_usd=round(sum(result.cost_usd for result in results), 8),
            total_wall_seconds=round(sum(result.wall_seconds for result in results), 6),
        ),
    )
    _write_report(output, report, cards)
    return report
