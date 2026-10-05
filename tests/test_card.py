from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from reproof.claims import compare_claim
from reproof.crash import DIRTY_FIX_DETAIL, ambiguous_vulnerable_detail, parse_crash
from reproof.models import Claim, TriageCard


def valid_card() -> dict[str, object]:
    return {
        "schema_version": "1.4",
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
                "exit_code": 0,
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
            "derivation_source_sha256": "1" * 64,
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


def test_card_schema_rejects_unknown_version() -> None:
    payload = valid_card()
    payload["schema_version"] = "999"
    with pytest.raises(ValidationError, match=r"Input should be '1\.4'"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_contradictory_live_provenance() -> None:
    payload = valid_card()
    payload["provenance"]["derivation_source_sha256"] = "2" * 64  # type: ignore[index]
    with pytest.raises(ValidationError, match="live execution requires identical"):
        TriageCard.model_validate(payload)


def test_card_schema_rejects_conclusive_verdict_with_dirty_fix() -> None:
    payload = valid_card()
    payload["evidence"]["fix_clean"] = False  # type: ignore[index]
    payload["evidence"]["fixed_exit_code"] = 1  # type: ignore[index]
    payload["sandbox_operations"][1]["exit_code"] = 1  # type: ignore[index]
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


@pytest.mark.parametrize("failure", ["deadly signal", "timeout after 60 seconds"])
def test_card_requires_needs_info_for_unsanitized_fatal_run(failure: str) -> None:
    payload = valid_card()
    log = (
        f"==1== ERROR: libFuzzer: {failure}\n"
        "    #0 0x1234 in parse_item /src/demo.c:3:2\n"
        f"SUMMARY: libFuzzer: {failure}\n"
    )
    measured = parse_crash(log)
    claim = Claim(
        project="demo",
        bug_class=measured.crash_type,
        functions=["parse_item"],
        files=[],
        trigger="input",
        poc_attached=True,
        affected_version="1.0",
        missing_details=[],
    )
    payload["sandbox_operations"][0]["exit_code"] = 1  # type: ignore[index]
    payload["sandbox_operations"][0]["stderr"] = log  # type: ignore[index]
    payload["evidence"]["claim_vs_evidence"] = [  # type: ignore[index]
        row.model_dump() for row in compare_claim(claim, measured)
    ]
    payload["verdict"] = "NEEDS_INFO"
    payload["missing_details"] = [ambiguous_vulnerable_detail(1, measured.sanitizer_kind)]
    TriageCard.model_validate(payload)

    payload["verdict"] = "NOT_REPRODUCED"
    with pytest.raises(ValidationError, match="does not match measured evidence NEEDS_INFO"):
        TriageCard.model_validate(payload)


def test_card_binds_needs_info_detail_to_ambiguous_run() -> None:
    payload = valid_card()
    payload["sandbox_operations"][0]["exit_code"] = 1  # type: ignore[index]
    payload["verdict"] = "NEEDS_INFO"
    payload["missing_details"] = ["affected version is missing"]
    with pytest.raises(ValidationError, match="ambiguous vulnerable execution"):
        TriageCard.model_validate(payload)


def test_card_describes_recognized_sanitizer_without_frames() -> None:
    payload = valid_card()
    log = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
    measured = parse_crash(log)
    claim = Claim(
        project="demo",
        bug_class=measured.crash_type,
        functions=[],
        files=[],
        trigger="input",
        poc_attached=True,
        affected_version="1.0",
        missing_details=[],
    )
    payload["sandbox_operations"][0]["exit_code"] = 1  # type: ignore[index]
    payload["sandbox_operations"][0]["stderr"] = log  # type: ignore[index]
    payload["evidence"]["claim_vs_evidence"] = [  # type: ignore[index]
        row.model_dump() for row in compare_claim(claim, measured)
    ]
    payload["verdict"] = "NEEDS_INFO"
    payload["missing_details"] = [ambiguous_vulnerable_detail(1, measured.sanitizer_kind)]

    card = TriageCard.model_validate(payload)
    assert "recognized AddressSanitizer report" in card.missing_details[0]
    assert "no usable resolved crash frames" in card.missing_details[0]


def test_card_rejects_exit_zero_fixed_fatal_as_clean() -> None:
    payload = valid_card()
    payload["sandbox_operations"][1]["stderr"] = (  # type: ignore[index]
        "==1== ERROR: libFuzzer: timeout after 60 seconds\n"
    )
    with pytest.raises(ValidationError, match="fixed clean evidence does not match"):
        TriageCard.model_validate(payload)

    payload["verdict"] = "NEEDS_INFO"
    payload["missing_details"] = [DIRTY_FIX_DETAIL]
    payload["evidence"]["fix_clean"] = False  # type: ignore[index]
    TriageCard.model_validate(payload)


def test_card_ignores_sanitizer_shaped_stdout_for_verdict() -> None:
    payload = valid_card()
    payload["sandbox_operations"][0]["stdout"] = (  # type: ignore[index]
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
        "    #0 0x1234 in attacker_chosen /src/fake.c:3:2\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/fake.c:3 in attacker_chosen\n"
    )
    card = TriageCard.model_validate(payload)
    assert card.verdict.value == "NOT_REPRODUCED"
    assert card.evidence.crash is None


def test_card_requires_needs_info_for_exit_zero_stderr_crash() -> None:
    payload = valid_card()
    log = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
        "    #0 0x1234 in parse_item /src/demo.c:3:2\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/demo.c:3 in parse_item\n"
    )
    measured = parse_crash(log)
    claim = Claim(
        project="demo",
        bug_class=measured.crash_type,
        functions=["parse_item"],
        files=[],
        trigger="input",
        poc_attached=True,
        affected_version="1.0",
        missing_details=[],
    )
    payload["sandbox_operations"][0]["stderr"] = log  # type: ignore[index]
    payload["evidence"]["claim_vs_evidence"] = [  # type: ignore[index]
        row.model_dump() for row in compare_claim(claim, measured)
    ]
    payload["verdict"] = "NEEDS_INFO"
    payload["missing_details"] = [
        ambiguous_vulnerable_detail(
            0,
            measured.sanitizer_kind,
            has_usable_frames=True,
        )
    ]

    card = TriageCard.model_validate(payload)
    assert card.verdict.value == "NEEDS_INFO"
    assert card.evidence.crash is None
    assert "sandbox exit code was 0" in card.missing_details[0]
