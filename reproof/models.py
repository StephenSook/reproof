"""Shared typed records written to triage and evaluation JSON."""

from __future__ import annotations

import hashlib
import math
import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model that rejects fields Reproof did not measure."""

    model_config = ConfigDict(extra="forbid")


class Verdict(StrEnum):
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    DUPLICATE = "DUPLICATE"
    NEEDS_INFO = "NEEDS_INFO"


class Claim(StrictModel):
    project: str
    bug_class: str
    functions: list[str]
    files: list[str]
    trigger: str
    poc_attached: bool
    affected_version: str
    missing_details: list[str]


class ModelCall(StrictModel):
    model: str
    latency_seconds: float = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    input_price_per_million: float = Field(ge=0)
    output_price_per_million: float = Field(ge=0)
    price_source: str
    cost_usd: float = Field(ge=0)
    request_id: str = Field(min_length=1)


class CrashEvidence(StrictModel):
    crash_type: str = Field(min_length=1)
    crash_state: list[str] = Field(min_length=1)
    sanitizer_excerpt: str = Field(min_length=1)
    sanitizer_kind: str = Field(min_length=1)


class DuplicateCandidate(StrictModel):
    id: str
    summary: str
    fixed_commits: list[str]
    match_kind: str


class SandboxOperation(StrictModel):
    task_id: int
    kind: str
    checkpoint_uuid: str
    checkpoint_operation_uuid: str | None
    checkpoint_wall_seconds: float = Field(ge=0)
    checkpoint_cost_usd: float = Field(ge=0)
    operation_uuid: str | None
    exit_code: int
    stdout: str
    stderr: str
    wall_seconds: float = Field(ge=0)
    server_elapsed_seconds: float | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)
    disposable: bool = True


class ClaimComparisonRow(StrictModel):
    field: str
    claimed: str | list[str]
    measured: str | list[str]
    matches: bool
    detail: str


class TriageEvidence(StrictModel):
    crash: CrashEvidence | None
    fix_clean: bool
    fixed_exit_code: int
    excluded_osv_ids: list[str]
    duplicate_candidates: list[DuplicateCandidate]
    claim_vs_evidence: list[ClaimComparisonRow]
    inputs_tried: list[str]


class TriageProvenance(StrictModel):
    arvo_task_sha256: str
    report_sha256: str
    osv_archive_sha256: str
    monorail_mapping_sha256: str
    execution_source_sha256: str
    derivation_source_sha256: str
    derivation_method: Literal["live-execution", "saved-output-refresh"]
    osv_record_id: str | None

    @model_validator(mode="after")
    def validate_hashes(self) -> TriageProvenance:
        for field in (
            "arvo_task_sha256",
            "report_sha256",
            "osv_archive_sha256",
            "monorail_mapping_sha256",
            "execution_source_sha256",
            "derivation_source_sha256",
        ):
            if re.fullmatch(r"[0-9a-f]{64}", getattr(self, field)) is None:
                raise ValueError(f"{field} must be a SHA-256 digest")
        if (
            self.derivation_method == "live-execution"
            and self.execution_source_sha256 != self.derivation_source_sha256
        ):
            raise ValueError("live execution requires identical source hashes")
        return self


class PublicTavilyCall(StrictModel):
    """One Tavily call that was actually sent. Credits come from that response."""

    operation: str
    request_id: str
    credits: int = Field(ge=0)
    query: str


class PublicEvidence(StrictModel):
    """One page that passed the host rule and the frame gate."""

    url: str
    title: str
    frames_matched: list[str]
    matched_lines: list[str]
    cve_ids: list[str]
    ghsa_ids: list[str]
    patched_versions: list[str]
    mentioned_commits: list[str]
    relation: str
    upstream_status: str
    upstream_version: str
    ancestry: str
    checked_tag: str
    checked_commit: str
    stale_fields: list[str]
    quotes: list[str]
    dispute: bool
    match_reason: str
    model_request_id: str


class PublicDraftLine(StrictModel):
    """One maintainer-facing sentence. The human sends it. It cites its source."""

    text: str
    source_url: str
    source_date: str
    confidence: Literal["high", "medium", "low"]


class PublicStatus(StrictModel):
    """Whether a measured crash is already public, separate from the triage verdict."""

    state: Literal[
        "PUBLICLY_KNOWN_FIXED",
        "PUBLICLY_KNOWN_OPEN",
        "RELATED_VARIANTS_ONLY",
        "SOURCE_DISPUTE",
        "NO_PUBLIC_FINDINGS",
    ]
    evidence: list[PublicEvidence]
    queries_sent: list[str]
    query_source: str
    domains: list[str]
    failed_sources: list[str]
    note: str
    tavily_request_ids: list[str]
    tavily_calls: list[PublicTavilyCall]
    tavily_credits: int = Field(default=0, ge=0)
    model_calls: list[ModelCall]
    draft: list[PublicDraftLine]
    host_rejected: int = Field(default=0, ge=0)
    snippet_rejected: int = Field(default=0, ge=0)
    frame_rejected: int = Field(default=0, ge=0)
    quote_rejected: int = Field(default=0, ge=0)
    unrelated_rejected: int = Field(default=0, ge=0)
    source_file_rejected: int = Field(default=0, ge=0)
    latency_seconds: float = Field(default=0, ge=0)


class TriageCard(StrictModel):
    schema_version: Literal["1.5"] = "1.5"
    arvo_id: int
    project: str
    report_source: str
    report_text: str
    verdict: Verdict
    missing_details: list[str]
    evidence: TriageEvidence
    model_calls: list[ModelCall]
    sandbox_operations: list[SandboxOperation]
    slice_manifest_sha256: dict[str, str]
    provenance: TriageProvenance
    model_cost_usd: float = Field(ge=0)
    sandbox_cost_usd: float = Field(ge=0)
    total_cost_usd: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)
    public_status: PublicStatus | None = None

    @model_validator(mode="after")
    def validate_evidence_and_costs(self) -> TriageCard:
        report_digest = hashlib.sha256(self.report_text.encode("utf-8")).hexdigest()
        if self.provenance.report_sha256 != report_digest:
            raise ValueError("report provenance hash does not match report text")
        if not self.model_calls:
            raise ValueError("a triage card must record at least one model call")
        operation_kinds = {operation.kind for operation in self.sandbox_operations}
        if operation_kinds != {"vul", "fix"} or len(self.sandbox_operations) != 2:
            raise ValueError("a triage card must contain exactly one vul and one fix operation")
        if any(operation.task_id != self.arvo_id for operation in self.sandbox_operations):
            raise ValueError("sandbox operation task IDs must match the card ARVO ID")
        if set(self.slice_manifest_sha256) != {"vul", "fix"} or any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in self.slice_manifest_sha256.values()
        ):
            raise ValueError("slice manifest hashes must contain vul and fix SHA-256 values")

        if self.verdict is Verdict.NEEDS_INFO and not self.missing_details:
            raise ValueError("a needs-info verdict must state at least one missing detail")
        if self.evidence.fix_clean and self.evidence.fixed_exit_code != 0:
            raise ValueError("a clean fixed build must have exit code zero")
        if self.evidence.excluded_osv_ids != sorted(set(self.evidence.excluded_osv_ids)):
            raise ValueError("excluded OSV IDs must be sorted and unique")
        candidate_ids = {candidate.id for candidate in self.evidence.duplicate_candidates}
        if candidate_ids.intersection(self.evidence.excluded_osv_ids):
            raise ValueError("a duplicate candidate cannot be an excluded OSV record")
        comparison_fields = {row.field for row in self.evidence.claim_vs_evidence}
        if (
            comparison_fields != {"bug_class", "functions"}
            or len(self.evidence.claim_vs_evidence) != 2
        ):
            raise ValueError("claim comparison must contain bug_class and functions exactly once")

        from reproof.crash import (
            DIRTY_FIX_DETAIL,
            ambiguous_vulnerable_detail,
            is_conclusive_crash,
            looks_clean,
            parse_crash,
            sanitizer_excerpt,
        )

        operations = {operation.kind: operation for operation in self.sandbox_operations}
        vulnerable = operations["vul"]
        fixed = operations["fix"]
        measured_fix_clean = (
            looks_clean(fixed.exit_code, fixed.stderr) and not parse_crash(fixed.stderr).state
        )
        if self.evidence.fixed_exit_code != fixed.exit_code:
            raise ValueError("fixed exit evidence does not match the saved fix operation")
        if self.evidence.fix_clean != measured_fix_clean:
            raise ValueError("fixed clean evidence does not match the saved fix operation")

        measured_crash = parse_crash(vulnerable.stderr)
        measured_vulnerable_crashed = is_conclusive_crash(vulnerable.exit_code, measured_crash)
        if measured_vulnerable_crashed:
            if self.evidence.crash is None:
                raise ValueError(
                    "saved vulnerable operation contains an unrecorded sanitizer crash"
                )
            expected_crash = {
                "crash_type": measured_crash.crash_type,
                "crash_state": list(measured_crash.state),
                "sanitizer_excerpt": sanitizer_excerpt(measured_crash),
                "sanitizer_kind": measured_crash.sanitizer_kind,
            }
            if self.evidence.crash.model_dump() != expected_crash:
                raise ValueError("crash evidence does not match the saved vulnerable operation")
        elif self.evidence.crash is not None:
            raise ValueError("crash evidence has no sanitizer trace in the vulnerable operation")

        measured_vulnerable_clean = (
            looks_clean(vulnerable.exit_code, vulnerable.stderr) and not measured_crash.state
        )
        duplicate_count = len(self.evidence.duplicate_candidates)
        if not measured_fix_clean or (
            not measured_vulnerable_crashed and not measured_vulnerable_clean
        ):
            expected_verdict = Verdict.NEEDS_INFO
        elif measured_vulnerable_crashed and duplicate_count:
            expected_verdict = Verdict.DUPLICATE
        elif measured_vulnerable_crashed:
            expected_verdict = Verdict.REPRODUCED
        elif not duplicate_count:
            expected_verdict = Verdict.NOT_REPRODUCED
        else:
            expected_verdict = Verdict.NEEDS_INFO
        if self.verdict is not expected_verdict:
            raise ValueError(
                f"verdict {self.verdict} does not match measured evidence {expected_verdict}"
            )
        if not measured_vulnerable_clean and not measured_vulnerable_crashed:
            required_detail = ambiguous_vulnerable_detail(
                vulnerable.exit_code,
                measured_crash.sanitizer_kind,
                has_usable_frames=measured_crash.crashed,
            )
            if required_detail not in self.missing_details:
                raise ValueError(
                    "missing details do not describe the ambiguous vulnerable execution"
                )
        if not measured_fix_clean and DIRTY_FIX_DETAIL not in self.missing_details:
            raise ValueError("missing details do not describe the unclean fixed execution")

        from reproof.claims import compare_claim

        rows = {row.field: row for row in self.evidence.claim_vs_evidence}
        claimed_functions = rows["functions"].claimed
        if not isinstance(rows["bug_class"].claimed, str) or not isinstance(
            claimed_functions, list
        ):
            raise ValueError("claim comparison has invalid claimed value types")
        comparison_claim = Claim(
            project=self.project,
            bug_class=rows["bug_class"].claimed,
            functions=[str(value) for value in claimed_functions],
            files=[],
            trigger="",
            poc_attached=True,
            affected_version="",
            missing_details=[],
        )
        expected_comparison = compare_claim(comparison_claim, measured_crash)
        if self.evidence.claim_vs_evidence != expected_comparison:
            raise ValueError("claim comparison does not match the saved vulnerable operation")

        model_cost = sum(call.cost_usd for call in self.model_calls)
        sandbox_cost = sum(
            operation.checkpoint_cost_usd + (operation.cost_usd or 0.0)
            for operation in self.sandbox_operations
        )
        if not math.isclose(self.model_cost_usd, model_cost, abs_tol=1e-7):
            raise ValueError("model cost does not equal recorded model calls")
        if not math.isclose(self.sandbox_cost_usd, sandbox_cost, abs_tol=1e-7):
            raise ValueError("sandbox cost does not equal recorded sandbox operations")
        if not math.isclose(
            self.total_cost_usd,
            self.model_cost_usd + self.sandbox_cost_usd,
            abs_tol=1e-7,
        ):
            raise ValueError("total cost does not equal model plus sandbox cost")
        if self.public_status is not None:
            recorded = {call.request_id for call in self.model_calls}
            missing = [
                call.request_id
                for call in self.public_status.model_calls
                if call.request_id not in recorded
            ]
            if missing:
                raise ValueError("public status model calls must also be card model calls")
        return self


class EvalTaskResult(StrictModel):
    arvo_id: int
    project: str
    verdict: Verdict
    crash_state_agreement_with_osv: bool
    fix_clean: bool
    duplicate_candidates: list[str]
    claim_agreement: bool
    crash_type: str
    crash_state: list[str]
    sanitizer_kind: str | None
    vulnerable_clean: bool
    vulnerable_exit_code: int
    fixed_exit_code: int
    model_request_ids: list[str]
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    model_cost_usd: float = Field(ge=0)
    sandbox_cost_usd: float = Field(ge=0)
    checkpoint_operation_uuids: list[str]
    sandbox_operation_uuids: list[str]
    slice_manifest_sha256: dict[str, str]
    card_provenance: TriageProvenance
    cost_usd: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)
    card_path: str

    @model_validator(mode="after")
    def validate_task_cost_and_hashes(self) -> EvalTaskResult:
        if not math.isclose(
            self.cost_usd,
            self.model_cost_usd + self.sandbox_cost_usd,
            abs_tol=1e-7,
        ):
            raise ValueError("eval task cost does not equal model plus sandbox cost")
        if set(self.slice_manifest_sha256) != {"vul", "fix"} or any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in self.slice_manifest_sha256.values()
        ):
            raise ValueError("eval slice hashes must contain vul and fix SHA-256 values")
        has_state = (
            bool(self.crash_state)
            and self.crash_state != ["NULL"]
            and all(frame.strip() for frame in self.crash_state)
        )
        has_type = bool(self.crash_type.strip())
        has_sanitizer = bool(self.sanitizer_kind and self.sanitizer_kind.strip())
        if len({has_state, has_type, has_sanitizer}) != 1:
            raise ValueError("eval crash state, type, and sanitizer must be present together")
        if has_state and self.vulnerable_exit_code == 0:
            raise ValueError("a conclusive eval crash must have a nonzero vulnerable exit code")
        if self.fix_clean and self.fixed_exit_code != 0:
            raise ValueError("a clean eval fix must have exit code zero")
        if self.vulnerable_clean and self.vulnerable_exit_code != 0:
            raise ValueError("a clean eval vulnerable run must have exit code zero")
        if has_state and self.vulnerable_clean:
            raise ValueError("a conclusive eval crash cannot be a clean vulnerable run")
        duplicate_count = len(self.duplicate_candidates)
        if not self.fix_clean or (not has_state and not self.vulnerable_clean):
            expected_verdict = Verdict.NEEDS_INFO
        elif has_state and duplicate_count:
            expected_verdict = Verdict.DUPLICATE
        elif has_state:
            expected_verdict = Verdict.REPRODUCED
        elif not duplicate_count:
            expected_verdict = Verdict.NOT_REPRODUCED
        else:
            expected_verdict = Verdict.NEEDS_INFO
        if self.verdict is not expected_verdict:
            raise ValueError(
                f"eval verdict {self.verdict} does not match evidence {expected_verdict}"
            )
        if not has_state and self.crash_state_agreement_with_osv:
            raise ValueError("a no-crash eval row cannot agree with an OSV crash state")
        if not has_state and self.claim_agreement:
            raise ValueError("a no-crash eval row cannot have claim agreement")
        return self


class EvalTotals(StrictModel):
    tasks_requested: int = Field(ge=0)
    tasks_completed: int = Field(ge=0)
    crash_state_agreements: int = Field(ge=0)
    fixes_clean: int = Field(ge=0)
    claims_agree: int = Field(ge=0)
    total_duplicate_candidates: int = Field(ge=0)
    total_input_tokens: int = Field(ge=0)
    total_output_tokens: int = Field(ge=0)
    total_model_cost_usd: float = Field(ge=0)
    total_sandbox_cost_usd: float = Field(ge=0)
    total_cost_usd: float = Field(ge=0)
    total_wall_seconds: float = Field(ge=0)


class EvalProvenance(StrictModel):
    arvo_database_sha256: str
    osv_archive_sha256: str
    monorail_mapping_sha256: str
    candidate_table_sha256: str
    execution_source_sha256: str
    derivation_source_sha256: str
    derivation_method: Literal["live-execution", "saved-output-refresh"]

    @model_validator(mode="after")
    def validate_hashes(self) -> EvalProvenance:
        for field in (
            "arvo_database_sha256",
            "osv_archive_sha256",
            "monorail_mapping_sha256",
            "candidate_table_sha256",
            "execution_source_sha256",
            "derivation_source_sha256",
        ):
            if re.fullmatch(r"[0-9a-f]{64}", getattr(self, field)) is None:
                raise ValueError(f"{field} must be a SHA-256 digest")
        if (
            self.derivation_method == "live-execution"
            and self.execution_source_sha256 != self.derivation_source_sha256
        ):
            raise ValueError("live execution requires identical source hashes")
        return self


class EvalReport(StrictModel):
    schema_version: Literal["1.5"] = "1.5"
    selection_rule: str
    selected_arvo_ids: list[int]
    provenance: EvalProvenance
    tasks: list[EvalTaskResult]
    totals: EvalTotals

    @model_validator(mode="after")
    def validate_report_shape(self) -> EvalReport:
        task_ids = [task.arvo_id for task in self.tasks]
        if task_ids != self.selected_arvo_ids:
            raise ValueError("eval task order must equal selected ARVO ID order")
        if self.totals.tasks_requested != len(self.selected_arvo_ids):
            raise ValueError("tasks requested must equal selected ARVO ID count")
        if self.totals.tasks_completed != len(self.tasks):
            raise ValueError("tasks completed must equal eval task count")
        if len(set(task_ids)) != len(task_ids):
            raise ValueError("eval task IDs must be unique")
        for task in self.tasks:
            card_provenance = task.card_provenance
            if card_provenance.osv_archive_sha256 != self.provenance.osv_archive_sha256:
                raise ValueError("card OSV archive provenance does not match eval provenance")
            if card_provenance.monorail_mapping_sha256 != self.provenance.monorail_mapping_sha256:
                raise ValueError("card mapping provenance does not match eval provenance")
            if card_provenance.execution_source_sha256 != self.provenance.execution_source_sha256:
                raise ValueError("card execution source does not match eval provenance")
            if card_provenance.derivation_source_sha256 != self.provenance.derivation_source_sha256:
                raise ValueError("card derivation source does not match eval provenance")
            if card_provenance.derivation_method != self.provenance.derivation_method:
                raise ValueError("card derivation method does not match eval provenance")
        integer_totals = {
            "crash_state_agreements": sum(
                task.crash_state_agreement_with_osv for task in self.tasks
            ),
            "fixes_clean": sum(task.fix_clean for task in self.tasks),
            "claims_agree": sum(task.claim_agreement for task in self.tasks),
            "total_duplicate_candidates": sum(
                len(task.duplicate_candidates) for task in self.tasks
            ),
            "total_input_tokens": sum(task.input_tokens for task in self.tasks),
            "total_output_tokens": sum(task.output_tokens for task in self.tasks),
        }
        for field, expected in integer_totals.items():
            if getattr(self.totals, field) != expected:
                raise ValueError(f"eval total {field} does not match task rows")
        float_totals = {
            "total_model_cost_usd": sum(task.model_cost_usd for task in self.tasks),
            "total_sandbox_cost_usd": sum(task.sandbox_cost_usd for task in self.tasks),
            "total_cost_usd": sum(task.cost_usd for task in self.tasks),
            "total_wall_seconds": sum(task.wall_seconds for task in self.tasks),
        }
        for field, expected_float in float_totals.items():
            if not math.isclose(getattr(self.totals, field), expected_float, abs_tol=1e-7):
                raise ValueError(f"eval total {field} does not match task rows")
        return self
