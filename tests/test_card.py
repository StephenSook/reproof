from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from reproof.models import TriageCard


def valid_card() -> dict[str, object]:
    return {
        "schema_version": "1.3",
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
                    "detail": "normalized sanitizer bug family equality",
                },
                {
                    "field": "functions",
                    "claimed": ["parse_item"],
                    "measured": [],
                    "matches": False,
                    "detail": (
                        "at least one claimed function occurs in the top ClusterFuzz crash frames"
                    ),
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
        "provenance": {
            "arvo_task_sha256": "c" * 64,
            "report_sha256": hashlib.sha256(b"report").hexdigest(),
            "osv_archive_sha256": "e" * 64,
            "monorail_mapping_sha256": "f" * 64,
            "execution_source_sha256": "1" * 64,
            "derivation_source_sha256": "2" * 64,
            "derivation_method": "live-execution",
            "osv_record_id": "OSV-TEST-1",
        },
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


def test_card_schema_rejects_report_hash_mismatch() -> None:
    payload = valid_card()
    payload["report_text"] = "changed report"
    with pytest.raises(ValidationError, match="report provenance hash"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_conclusive_verdict_with_dirty_fix() -> None:
    payload = valid_card()
    payload["evidence"]["fix_clean"] = False  # type: ignore[index]
    payload["evidence"]["fixed_exit_code"] = 1  # type: ignore[index]
    with pytest.raises(ValidationError, match="does not match measured evidence NEEDS_INFO"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_needs_info_when_not_reproduced_is_measured() -> None:
    payload = valid_card()
    payload["verdict"] = "NEEDS_INFO"
    payload["missing_details"] = ["ambiguous"]
    with pytest.raises(ValidationError, match="does not match measured evidence"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_outputs_that_do_not_match_evidence() -> None:
    payload = valid_card()
    payload["sandbox_operations"][1]["exit_code"] = 17  # type: ignore[index]
    with pytest.raises(ValidationError, match="fixed exit evidence does not match"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_crash_evidence_without_saved_trace() -> None:
    payload = valid_card()
    payload["verdict"] = "REPRODUCED"
    payload["evidence"]["crash"] = {  # type: ignore[index]
        "crash_type": "Heap-buffer-overflow READ 1",
        "crash_state": ["parse_item"],
        "sanitizer_excerpt": "ERROR: AddressSanitizer",
        "sanitizer_kind": "AddressSanitizer",
    }
    with pytest.raises(ValidationError, match="no sanitizer trace"):
        TriageCard.model_validate(payload)
