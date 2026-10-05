from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from reproof.crash import parse_crash
from reproof.evaluation import _eval_crash_evidence
from reproof.models import EvalReport, EvalTaskResult


def eval_payload() -> dict[str, object]:
    return json.loads(Path("eval/results/arvo10.json").read_text(encoding="utf-8"))


def test_eval_schema_accepts_tracked_result() -> None:
    report = EvalReport.model_validate(eval_payload())
    assert len(report.tasks) == 10


def test_eval_schema_rejects_task_cost_mismatch() -> None:
    payload = copy.deepcopy(eval_payload())
    payload["tasks"][0]["cost_usd"] += 1  # type: ignore[index]
    payload["totals"]["total_cost_usd"] += 1  # type: ignore[index]
    with pytest.raises(ValidationError, match="eval task cost"):
        EvalReport.model_validate(payload)


def test_eval_schema_rejects_card_provenance_mismatch() -> None:
    payload = copy.deepcopy(eval_payload())
    payload["tasks"][0]["card_provenance"]["execution_source_sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(ValidationError, match="card execution source"):
        EvalReport.model_validate(payload)


def test_eval_schema_rejects_invalid_global_digest() -> None:
    payload = copy.deepcopy(eval_payload())
    payload["provenance"]["arvo_database_sha256"] = "not-a-digest"  # type: ignore[index]
    with pytest.raises(ValidationError, match="arvo_database_sha256"):
        EvalReport.model_validate(payload)


def test_eval_schema_rejects_unknown_version() -> None:
    payload = eval_payload()
    payload["schema_version"] = "999"
    with pytest.raises(ValidationError, match=r"Input should be '1\.5'"):
        EvalReport.model_validate(payload)


def test_eval_schema_rejects_contradictory_live_provenance() -> None:
    payload = eval_payload()
    payload["provenance"]["derivation_method"] = "live-execution"  # type: ignore[index]
    with pytest.raises(ValidationError, match="live execution requires identical"):
        EvalReport.model_validate(payload)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"fix_clean": True, "fixed_exit_code": 99}, "clean eval fix"),
        ({"vulnerable_exit_code": 0}, "conclusive eval crash"),
        (
            {
                "verdict": "DUPLICATE",
                "crash_type": "",
                "crash_state": [],
                "sanitizer_kind": None,
            },
            "does not match evidence",
        ),
        (
            {
                "verdict": "REPRODUCED",
                "duplicate_candidates": ["OSV-EXTRA"],
            },
            "does not match evidence",
        ),
    ],
)
def test_eval_schema_rejects_contradictory_verdict_evidence(
    changes: dict[str, object], message: str
) -> None:
    payload = copy.deepcopy(eval_payload())
    payload["tasks"][0].update(changes)  # type: ignore[index]
    with pytest.raises(ValidationError, match=message):
        EvalReport.model_validate(payload)


@pytest.mark.parametrize("agreement_field", ["crash_state_agreement_with_osv", "claim_agreement"])
def test_eval_schema_rejects_no_crash_positive_agreement(agreement_field: str) -> None:
    payload = eval_payload()
    task = payload["tasks"][0]  # type: ignore[index]
    task.update(  # type: ignore[union-attr]
        {
            "verdict": "NOT_REPRODUCED",
            "crash_type": "",
            "crash_state": [],
            "sanitizer_kind": None,
            "vulnerable_clean": True,
            "vulnerable_exit_code": 0,
            "duplicate_candidates": [],
            "crash_state_agreement_with_osv": False,
            "claim_agreement": False,
        }
    )
    task[agreement_field] = True  # type: ignore[index]
    with pytest.raises(ValidationError, match="no-crash eval row"):
        EvalReport.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sanitizer_kind", ""),
        ("crash_type", "  "),
        ("crash_state", [""]),
    ],
)
def test_eval_schema_rejects_blank_crash_evidence(field: str, value: object) -> None:
    payload = eval_payload()
    payload["tasks"][0][field] = value  # type: ignore[index]
    with pytest.raises(ValidationError, match="must be present together"):
        EvalReport.model_validate(payload)


def test_eval_schema_rejects_clusterfuzz_null_state() -> None:
    payload = eval_payload()
    payload["tasks"][0]["crash_state"] = ["NULL"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="must be present together"):
        EvalReport.model_validate(payload)


@pytest.mark.parametrize("exit_code", [0, 1])
def test_eval_serializes_unsanitized_fatal_as_ambiguous_needs_info(exit_code: int) -> None:
    measured = parse_crash(
        "==1== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x1234 in parse_item /src/demo.c:3:2\n"
        "SUMMARY: libFuzzer: deadly signal\n"
    )
    assert not measured.crashed
    crash_type, crash_state, sanitizer_kind = _eval_crash_evidence(measured, exit_code)

    payload = eval_payload()
    task = payload["tasks"][0]  # type: ignore[index]
    task.update(  # type: ignore[union-attr]
        {
            "verdict": "NEEDS_INFO",
            "crash_type": crash_type,
            "crash_state": crash_state,
            "sanitizer_kind": sanitizer_kind,
            "vulnerable_clean": False,
            "vulnerable_exit_code": exit_code,
            "duplicate_candidates": [],
            "crash_state_agreement_with_osv": False,
            "claim_agreement": False,
        }
    )
    EvalTaskResult.model_validate(task)
