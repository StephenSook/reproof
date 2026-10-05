from __future__ import annotations

import pytest
from pydantic import ValidationError

from reproof.models import TriageCard


def valid_card() -> dict[str, object]:
    return {
        "schema_version": "1.0",
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
            "claim_vs_evidence": [],
            "inputs_tried": ["stored ARVO PoC at /tmp/poc"],
        },
        "model_calls": [],
        "sandbox_operations": [],
        "model_cost_usd": 0.0,
        "sandbox_cost_usd": 0.0,
        "total_cost_usd": 0.0,
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
