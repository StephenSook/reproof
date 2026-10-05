from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from reproof.models import EvalReport


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
    with pytest.raises(ValidationError, match=r"Input should be '1\.3'"):
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
            "duplicate_candidates": [],
            "crash_state_agreement_with_osv": False,
            "claim_agreement": False,
        }
    )
    task[agreement_field] = True  # type: ignore[index]
    with pytest.raises(ValidationError, match="no-crash eval row"):
        EvalReport.model_validate(payload)
