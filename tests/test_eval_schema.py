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
    payload["tasks"][0]["card_provenance"]["reproof_source_sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(ValidationError, match="card source provenance"):
        EvalReport.model_validate(payload)


def test_eval_schema_rejects_invalid_global_digest() -> None:
    payload = copy.deepcopy(eval_payload())
    payload["provenance"]["arvo_database_sha256"] = "not-a-digest"  # type: ignore[index]
    with pytest.raises(ValidationError, match="arvo_database_sha256"):
        EvalReport.model_validate(payload)
