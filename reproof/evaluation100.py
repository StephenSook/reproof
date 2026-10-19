"""Failure-tolerant execution for the registered ARVO eval-100 run."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import asdict
from pathlib import Path

from reproof.arvo import ArvoRepository, ArvoTask
from reproof.claims import comparison_rows_agree
from reproof.crash import is_conclusive_crash, looks_clean, parse_crash
from reproof.dup import OsvIndex
from reproof.eval100 import Eval100InputPaths, default_eval100_inputs, select_eval100
from reproof.eval_prepare import (
    DEFAULT_LEDGER,
    Eval100PrepLedger,
    load_eval100_prep_ledger,
)
from reproof.evaluation import (
    _agrees_with_mapped_osv,
    _current_card_provenance,
    _eval_crash_evidence,
    _slice_directory,
    _valid_slice,
)
from reproof.models import (
    Eval100Provenance,
    Eval100Report,
    Eval100Totals,
    EvalPrepFailure,
    EvalRunAttempt,
    EvalRunFailure,
    EvalTaskResult,
    TriageCard,
)
from reproof.provenance import source_sha256
from reproof.sandbox import manifest_digest
from reproof.triage import _verdict, run_triage

EVAL100_SELECTION_RULE = (
    "The 10-task historical convenience sample plus 90 prepared tasks from the pinned "
    "ARVO population in random.Random(20261019) draw order, with a 1,500,000,000-byte "
    "per-image cap and a three-task combined project cap. Prepare failures are recorded "
    "and the draw continues. Every prepared task remains in the run denominator."
)
LEGACY_EVAL_OUTPUT = Path(__file__).resolve().parents[1] / "eval" / "results" / "arvo10.json"
DEFAULT_CARDS_DIR = Path("eval/results/cards100")
DEFAULT_EVAL100_OUTPUT = Path("eval/results/arvo100.json")

TaskRunner = Callable[..., EvalTaskResult]


def _exception_chain(error: BaseException) -> Iterator[BaseException]:
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)


def _is_transport_error(error: BaseException) -> bool:
    retryable_names = {
        "APIConnectionError",
        "APITimeoutError",
        "ConnectError",
        "ConnectTimeout",
        "ConnectionClosed",
        "NetworkError",
        "PoolTimeout",
        "ReadError",
        "ReadTimeout",
        "RemoteProtocolError",
        "TransportError",
        "WriteError",
        "WriteTimeout",
    }
    return any(
        isinstance(item, (ConnectionError, TimeoutError)) or type(item).__name__ in retryable_names
        for item in _exception_chain(error)
    )


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(str(item) for item in value if item))


def _string_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items() if item is not None}


def _non_negative_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _non_negative_float(value: object) -> float:
    return float(value) if isinstance(value, (int, float)) and value >= 0 else 0.0


def _attempt_evidence(task: ArvoTask, error: Exception, attempt: int) -> EvalRunAttempt:
    request_ids = _string_list(getattr(error, "request_ids", None))
    request_id = getattr(error, "request_id", None)
    if request_id is not None and str(request_id) not in request_ids:
        request_ids.append(str(request_id))
    model_cost = _non_negative_float(getattr(error, "model_cost_usd", 0.0))
    sandbox_cost = _non_negative_float(getattr(error, "sandbox_cost_usd", 0.0))
    return EvalRunAttempt(
        arvo_id=task.local_id,
        project=task.project,
        attempt=attempt,
        error_type=type(error).__name__,
        error=str(error),
        request_ids=request_ids,
        operation_uuids=_string_dict(getattr(error, "operation_uuids", None)),
        checkpoint_uuids=_string_dict(getattr(error, "checkpoint_uuids", None)),
        checkpoint_operation_uuids=_string_dict(getattr(error, "checkpoint_operation_uuids", None)),
        input_tokens=_non_negative_int(getattr(error, "input_tokens", 0)),
        output_tokens=_non_negative_int(getattr(error, "output_tokens", 0)),
        model_cost_usd=model_cost,
        sandbox_cost_usd=sandbox_cost,
        cost_usd=round(model_cost + sandbox_cost, 8),
        wall_seconds=_non_negative_float(getattr(error, "wall_seconds", 0.0)),
    )


def _merged_attempt_dict(attempts: list[EvalRunAttempt], field: str) -> dict[str, str]:
    merged: dict[str, str] = {}
    for attempt in attempts:
        for key, value in getattr(attempt, field).items():
            output_key = key if key not in merged else f"attempt{attempt.attempt}:{key}"
            merged[output_key] = value
    return merged


def _run_failure(
    task: ArvoTask,
    error: Exception,
    attempt_evidence: list[EvalRunAttempt],
) -> EvalRunFailure:
    return EvalRunFailure(
        arvo_id=task.local_id,
        project=task.project,
        attempts=len(attempt_evidence),
        error_type=type(error).__name__,
        error=str(error),
        request_ids=list(
            dict.fromkeys(
                request_id for attempt in attempt_evidence for request_id in attempt.request_ids
            )
        ),
        operation_uuids=_merged_attempt_dict(attempt_evidence, "operation_uuids"),
        checkpoint_uuids=_merged_attempt_dict(attempt_evidence, "checkpoint_uuids"),
        checkpoint_operation_uuids=_merged_attempt_dict(
            attempt_evidence, "checkpoint_operation_uuids"
        ),
        attempt_evidence=attempt_evidence,
    )


def _validate_resume_card(
    card_path: Path,
    task: ArvoTask,
    index: OsvIndex,
    expected_source_sha256: str,
) -> TriageCard:
    card = TriageCard.model_validate_json(card_path.read_text(encoding="utf-8"))
    if card.arvo_id != task.local_id:
        raise ValueError(
            f"resume card {card_path} has ARVO ID {card.arvo_id}, expected {task.local_id}"
        )
    if card.project != task.project:
        raise ValueError(f"resume card {card_path} project differs from the ARVO task")
    current_records = {record.id: record for record in index.for_issue(task.local_id)}
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
        expected_source_sha256,
        "live-execution",
    )
    if card.provenance != expected_provenance:
        raise ValueError(f"resume card {card_path} provenance is stale")
    vulnerable = next(operation for operation in card.sandbox_operations if operation.kind == "vul")
    measured = parse_crash(vulnerable.stderr)
    vulnerable_crashed = is_conclusive_crash(vulnerable.exit_code, measured)
    expected_excluded_osv_ids = [record.id for record in index.for_issue(task.local_id)]
    if card.evidence.excluded_osv_ids != expected_excluded_osv_ids:
        raise ValueError(f"resume card {card_path} OSV exclusions are stale")
    expected_duplicates = (
        index.find_candidates(
            task.project,
            measured,
            excluded_osv_ids=expected_excluded_osv_ids,
        )
        if vulnerable_crashed
        else []
    )
    if card.evidence.duplicate_candidates != expected_duplicates:
        raise ValueError(f"resume card {card_path} duplicate evidence is stale")
    expected_verdict = _verdict(
        vulnerable_crashed,
        looks_clean(vulnerable.exit_code, vulnerable.stderr) and not measured.state,
        card.evidence.fix_clean,
        len(expected_duplicates),
    )
    if card.verdict is not expected_verdict:
        raise ValueError(f"resume card {card_path} verdict is stale")
    for kind, expected_digest in card.slice_manifest_sha256.items():
        slice_dir = _slice_directory(task.local_id, kind)
        if not _valid_slice(task.local_id, kind, task.fuzz_target):
            raise ValueError(f"resume card {card_path} has an invalid {kind} runtime slice")
        actual_digest = manifest_digest(slice_dir)
        if actual_digest != expected_digest:
            raise ValueError(
                f"resume card {card_path} has stale {kind} slice manifest: "
                f"{expected_digest} != {actual_digest}"
            )
    return card


def _card_result(
    card: TriageCard, task: ArvoTask, index: OsvIndex, card_path: Path
) -> EvalTaskResult:
    vulnerable = next(operation for operation in card.sandbox_operations if operation.kind == "vul")
    measured = parse_crash(vulnerable.stderr)
    vulnerable_crashed = is_conclusive_crash(vulnerable.exit_code, measured)
    vulnerable_clean = looks_clean(vulnerable.exit_code, vulnerable.stderr) and not measured.state
    crash_type, crash_state, sanitizer_kind = _eval_crash_evidence(measured, vulnerable.exit_code)
    return EvalTaskResult(
        arvo_id=task.local_id,
        project=task.project,
        verdict=card.verdict,
        crash_state_agreement_with_osv=vulnerable_crashed
        and _agrees_with_mapped_osv(task.local_id, measured, index),
        fix_clean=card.evidence.fix_clean,
        duplicate_candidates=[candidate.id for candidate in card.evidence.duplicate_candidates],
        claim_agreement=vulnerable_crashed
        and comparison_rows_agree(card.evidence.claim_vs_evidence),
        crash_type=crash_type,
        crash_state=crash_state,
        sanitizer_kind=sanitizer_kind,
        vulnerable_clean=vulnerable_clean,
        vulnerable_exit_code=vulnerable.exit_code,
        fixed_exit_code=card.evidence.fixed_exit_code,
        model_request_ids=[
            call.request_id for call in card.model_calls if call.request_id is not None
        ],
        input_tokens=sum(call.input_tokens for call in card.model_calls),
        output_tokens=sum(call.output_tokens for call in card.model_calls),
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


def _evaluate_task(
    task: ArvoTask,
    *,
    repository: ArvoRepository,
    index: OsvIndex,
    cards_dir: Path,
    resume: bool,
    expected_source_sha256: str,
) -> EvalTaskResult:
    for kind in ("vul", "fix"):
        if not _valid_slice(task.local_id, kind, task.fuzz_target):
            raise ValueError(f"prepared task {task.local_id} lacks a valid {kind} runtime slice")
    card_path = cards_dir / f"{task.local_id}.json"
    if resume and card_path.is_file():
        card = _validate_resume_card(card_path, task, index, expected_source_sha256)
        print(f"Resuming from validated card {card_path}")
    else:
        card = run_triage(
            task.local_id,
            repository=repository,
            osv_index=index,
            output_path=card_path,
        )
    if card.provenance.execution_source_sha256 != expected_source_sha256:
        raise ValueError(f"card {card_path} execution source differs from this eval-100 run")
    if card.provenance.derivation_method != "live-execution":
        raise ValueError(f"card {card_path} is not from live execution")
    return _card_result(card, task, index, card_path)


def _prep_failures(ledger: Eval100PrepLedger) -> list[EvalPrepFailure]:
    return [
        EvalPrepFailure.model_validate(asdict(failure))
        for attempt in ledger.attempted
        if (failure := attempt.failure) is not None
    ]


def _totals(
    selected: list[int],
    tasks: list[EvalTaskResult],
    prep_failed: list[EvalPrepFailure],
    retry_attempts: list[EvalRunAttempt],
    run_failed: list[EvalRunFailure],
) -> Eval100Totals:
    failed_attempts = retry_attempts + [
        attempt for failure in run_failed for attempt in failure.attempt_evidence
    ]
    return Eval100Totals(
        tasks_requested=len(selected),
        tasks_completed=len(tasks),
        prep_failures=len(prep_failed),
        run_failures=len(run_failed),
        crash_state_agreements=sum(task.crash_state_agreement_with_osv for task in tasks),
        fixes_clean=sum(task.fix_clean for task in tasks),
        claims_agree=sum(task.claim_agreement for task in tasks),
        total_duplicate_candidates=sum(len(task.duplicate_candidates) for task in tasks),
        total_input_tokens=sum(task.input_tokens for task in tasks)
        + sum(attempt.input_tokens for attempt in failed_attempts),
        total_output_tokens=sum(task.output_tokens for task in tasks)
        + sum(attempt.output_tokens for attempt in failed_attempts),
        total_model_cost_usd=round(
            sum(task.model_cost_usd for task in tasks)
            + sum(attempt.model_cost_usd for attempt in failed_attempts),
            8,
        ),
        total_sandbox_cost_usd=round(
            sum(task.sandbox_cost_usd for task in tasks)
            + sum(attempt.sandbox_cost_usd for attempt in failed_attempts),
            8,
        ),
        total_cost_usd=round(
            sum(task.cost_usd for task in tasks)
            + sum(attempt.cost_usd for attempt in failed_attempts),
            8,
        ),
        total_wall_seconds=round(
            sum(task.wall_seconds for task in tasks)
            + sum(attempt.wall_seconds for attempt in failed_attempts),
            6,
        ),
    )


def _write_report(path: Path, report: Eval100Report) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(report.model_dump_json(indent=2), encoding="utf-8", newline="\n")
    temporary.replace(path)


def run_eval100(
    prereg: Path,
    output: Path = DEFAULT_EVAL100_OUTPUT,
    *,
    cards_dir: Path = DEFAULT_CARDS_DIR,
    ledger_path: Path = DEFAULT_LEDGER,
    resume: bool = False,
    inputs: Eval100InputPaths | None = None,
    repository: ArvoRepository | None = None,
    index: OsvIndex | None = None,
    task_runner: TaskRunner | None = None,
) -> Eval100Report:
    """Run every prepared task, retry transport once, and retain every failure row."""
    actual_inputs = inputs or default_eval100_inputs()
    selection = select_eval100(prereg, inputs=actual_inputs)
    ledger = load_eval100_prep_ledger(ledger_path, selection)
    if len(ledger.prepared) != selection.target_new_tasks:
        raise ValueError(
            f"prepare ledger has {len(ledger.prepared)} tasks, expected "
            f"{selection.target_new_tasks}; finish eval-prepare before paid execution"
        )
    selected = list(selection.historical_arvo_ids) + ledger.prepared
    if len(selected) != 10 and output.resolve() == LEGACY_EVAL_OUTPUT.resolve():
        raise ValueError("refusing to overwrite eval/results/arvo10.json for a non-10 selection")

    active_repository = repository or ArvoRepository(actual_inputs.arvo_database)
    active_index = index or OsvIndex.from_archive(
        actual_inputs.osv_archive,
        actual_inputs.monorail_mapping,
    )
    evaluate = task_runner or _evaluate_task
    execution_source = source_sha256()
    tasks: list[EvalTaskResult] = []
    retry_attempts: list[EvalRunAttempt] = []
    run_failed: list[EvalRunFailure] = []
    for task_id in selected:
        task = active_repository.get(task_id)
        attempts = 0
        attempt_evidence: list[EvalRunAttempt] = []
        while True:
            attempts += 1
            try:
                result = evaluate(
                    task,
                    repository=active_repository,
                    index=active_index,
                    cards_dir=cards_dir,
                    resume=resume,
                    expected_source_sha256=execution_source,
                )
            except Exception as error:
                attempt_evidence.append(_attempt_evidence(task, error, attempts))
                if attempts == 1 and _is_transport_error(error):
                    continue
                run_failed.append(_run_failure(task, error, attempt_evidence))
                break
            retry_attempts.extend(attempt_evidence)
            tasks.append(result)
            break

    prep_failed = _prep_failures(ledger)
    report = Eval100Report(
        selection_rule=EVAL100_SELECTION_RULE,
        historical_arvo_ids=list(selection.historical_arvo_ids),
        random_draw_arvo_ids=ledger.prepared,
        selected_arvo_ids=selected,
        provenance=Eval100Provenance(
            prereg_sha256=selection.prereg_sha256,
            population_fixture_sha256=selection.fixture_sha256,
            arvo_database_sha256=selection.expected_input_sha256["arvo_database"],
            osv_archive_sha256=selection.expected_input_sha256["osv_archive"],
            monorail_mapping_sha256=selection.expected_input_sha256["monorail_mapping"],
            execution_source_sha256=execution_source,
            derivation_source_sha256=execution_source,
        ),
        prep_failed=prep_failed,
        retry_attempts=retry_attempts,
        run_failed=run_failed,
        tasks=tasks,
        totals=_totals(selected, tasks, prep_failed, retry_attempts, run_failed),
    )
    _write_report(output, report)
    return report
