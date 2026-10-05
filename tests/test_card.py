from __future__ import annotations

import pytest
from pydantic import ValidationError

from reproof.models import TriageCard


def valid_card() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "arvo_id": 1,
        "project": "demo",
        "report_source": "public test fixture",
        "report_text": "report",
        "verdict": "NOT_REPRODUCED",
        "missing_details": [],
        "evidence": {
            "crash": None,
            "fix_clean": True,
            "fixed_exit_code": 0,
            "duplicate_candidates": [],
            "claim_vs_evidence": [
                {
                    "field": "bug_class",
                    "claimed": "heap buffer overflow",
                    "measured": "",
                    "matches": False,
                    "detail": "no measured crash",
                },
                {
                    "field": "functions",
                    "claimed": ["parse_item"],
                    "measured": [],
                    "matches": False,
                    "detail": "no measured crash frames",
                },
            ],
            "inputs_tried": ["stored ARVO PoC at /tmp/poc"],
        },
        "model_calls": [
            {
                "model": "test/model",
                "latency_seconds": 0.1,
                "input_tokens": 1,
                "output_tokens": 1,
                "total_tokens": 2,
                "input_price_per_million": 0.3,
                "output_price_per_million": 0.9,
                "price_source": "public test price",
                "cost_usd": 0.0000012,
                "request_id": "request-test",
            }
        ],
        "sandbox_operations": [
            {
                "task_id": 1,
                "kind": kind,
                "checkpoint_uuid": f"checkpoint-{kind}",
                "checkpoint_operation_uuid": f"checkpoint-operation-{kind}",
                "checkpoint_wall_seconds": 0.1,
                "checkpoint_cost_usd": 0.000001,
                "operation_uuid": f"operation-{kind}",
                "exit_code": 1 if kind == "vul" else 0,
                "stdout": "",
                "stderr": "",
                "wall_seconds": 0.1,
                "server_elapsed_seconds": 0.1,
                "cost_usd": 0.000002,
                "disposable": True,
            }
            for kind in ("vul", "fix")
        ],
        "slice_manifest_sha256": {"vul": "a" * 64, "fix": "b" * 64},
        "model_cost_usd": 0.0000012,
        "sandbox_cost_usd": 0.000006,
        "total_cost_usd": 0.0000072,
        "wall_seconds": 1.0,
    }


def test_card_schema_accepts_complete_card() -> None:
    card = TriageCard.model_validate(valid_card())
    assert card.verdict.value == "NOT_REPRODUCED"
    assert card.evidence.inputs_tried == ["stored ARVO PoC at /tmp/poc"]


def test_card_schema_rejects_unknown_field() -> None:
    payload = valid_card()
    payload["fabricated_confidence"] = 1.0
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_conclusive_verdict_with_dirty_fix() -> None:
    payload = valid_card()
    payload["evidence"]["fix_clean"] = False  # type: ignore[index]
    payload["evidence"]["fixed_exit_code"] = 1  # type: ignore[index]
    with pytest.raises(ValidationError, match="not-reproduced verdict requires"):
        TriageCard.model_validate(payload)
