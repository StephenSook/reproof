"""Shared typed records written to triage and evaluation JSON."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


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
    request_id: str | None


class CrashEvidence(StrictModel):
    crash_type: str
    crash_state: list[str]
    sanitizer_excerpt: str


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
    duplicate_candidates: list[DuplicateCandidate]
    claim_vs_evidence: list[ClaimComparisonRow]
    inputs_tried: list[str]


class TriageCard(StrictModel):
    schema_version: str = "1.0"
    arvo_id: int
    project: str
    report_source: str
    report_text: str
    verdict: Verdict
    missing_details: list[str]
    evidence: TriageEvidence
    model_calls: list[ModelCall]
    sandbox_operations: list[SandboxOperation]
    model_cost_usd: float = Field(ge=0)
    sandbox_cost_usd: float = Field(ge=0)
    total_cost_usd: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)


class EvalTaskResult(StrictModel):
    arvo_id: int
    project: str
    verdict: Verdict
    crash_state_agreement_with_osv: bool
    fix_clean: bool
    duplicate_candidates: list[str]
    claim_agreement: bool
    cost_usd: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)
    card_path: str


class EvalTotals(StrictModel):
    tasks_requested: int = Field(ge=0)
    tasks_completed: int = Field(ge=0)
    crash_state_agreements: int = Field(ge=0)
    fixes_clean: int = Field(ge=0)
    claims_agree: int = Field(ge=0)
    total_duplicate_candidates: int = Field(ge=0)
    total_cost_usd: float = Field(ge=0)
    total_wall_seconds: float = Field(ge=0)


class EvalReport(StrictModel):
    schema_version: str = "1.0"
    selection_rule: str
    selected_arvo_ids: list[int]
    tasks: list[EvalTaskResult]
    totals: EvalTotals
