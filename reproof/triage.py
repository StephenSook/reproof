"""Run measured reproduction, duplicate matching, and claim comparison."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from reproof.arvo import ArvoRepository, ArvoTask
from reproof.claims import compare_claim, extract_claim
from reproof.crash import looks_clean, parse_crash, sanitizer_excerpt
from reproof.dup import OsvIndex, OsvRecord, frames_match
from reproof.models import (
    CrashEvidence,
    TriageCard,
    TriageEvidence,
    Verdict,
)
from reproof.sandbox import SandboxRunner
from reproof.slice import extract_runtime_slice


def _atomic_card(path: Path, card: TriageCard) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(card.model_dump_json(indent=2), encoding="utf-8", newline="\n")
    os.replace(temporary, path)


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


def _verdict(crashed: bool, fix_clean: bool, duplicate_count: int) -> Verdict:
    if crashed and duplicate_count:
        return Verdict.DUPLICATE
    if crashed and fix_clean:
        return Verdict.REPRODUCED
    if not crashed:
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
    slice_root = Path("slices")
    vul_dir = slice_root.resolve() / f"{task_id}-vul"
    fix_dir = slice_root.resolve() / f"{task_id}-fix"
    extract_runtime_slice(task_id, "vul", task.fuzz_target, slice_root)
    extract_runtime_slice(task_id, "fix", task.fuzz_target, slice_root)

    runner = sandbox or SandboxRunner()
    vulnerable_checkpoint = runner.ensure_checkpoint(task_id, "vul", vul_dir)
    fixed_checkpoint = runner.ensure_checkpoint(task_id, "fix", fix_dir)
    vulnerable, fixed = runner.run_pair(
        task_id,
        vulnerable_checkpoint,
        fixed_checkpoint,
        candidate_input=candidate_input,
    )

    vulnerable_output = _combined(vulnerable.stdout, vulnerable.stderr)
    fixed_output = _combined(fixed.stdout, fixed.stderr)
    measured = parse_crash(vulnerable_output)
    fixed_clean = looks_clean(fixed.exit_code, fixed_output)
    duplicates = index.find_candidates(task.project, measured)
    comparison = compare_claim(claim, measured)
    missing_details = list(dict.fromkeys(claim.missing_details))
    if measured.crashed and not fixed_clean:
        missing_details.append(
            "The fixed build did not exit cleanly; inspect its captured stdout and stderr."
        )

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
        verdict=_verdict(measured.crashed, fixed_clean, len(duplicates)),
        missing_details=missing_details,
        evidence=evidence,
        model_calls=[model_call],
        sandbox_operations=operations,
        model_cost_usd=model_call.cost_usd,
        sandbox_cost_usd=sandbox_cost,
        total_cost_usd=round(model_call.cost_usd + sandbox_cost, 8),
        wall_seconds=round(time.perf_counter() - started, 6),
    )
    destination = output_path or Path("eval/results/cards") / f"{task_id}.json"
    _atomic_card(destination, card)
    return card
