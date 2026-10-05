from __future__ import annotations

from types import SimpleNamespace

import pytest

from reproof import triage
from reproof.errors import TriageExecutionError
from reproof.models import Claim, ModelCall
from reproof.sandbox import CheckpointError


def model_call() -> ModelCall:
    return ModelCall(
        model="test/model",
        latency_seconds=0.1,
        input_tokens=1,
        output_tokens=1,
        total_tokens=2,
        input_price_per_million=0.3,
        output_price_per_million=0.9,
        price_source="public test price",
        cost_usd=0.0000012,
        request_id="request-paid",
    )


def test_post_model_slice_failure_preserves_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = SimpleNamespace(
        local_id=1,
        project="demo",
        crash_output="",
        fuzz_target="fuzz_demo",
    )
    repository = SimpleNamespace(get=lambda _task_id: task)
    index = SimpleNamespace(for_issue=lambda _task_id: [])
    claim = Claim(
        project="demo",
        bug_class="heap-buffer-overflow",
        functions=["parse"],
        files=[],
        trigger="input",
        poc_attached=True,
        affected_version="1.0",
        missing_details=[],
    )
    monkeypatch.setattr(triage, "extract_claim", lambda _text: (claim, model_call()))

    def fail_slice(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("image missing")

    monkeypatch.setattr(triage, "extract_runtime_slice", fail_slice)
    with pytest.raises(TriageExecutionError, match="image missing") as captured:
        triage.run_triage(
            1,
            report_text="public report",
            report_source="public test fixture",
            repository=repository,  # type: ignore[arg-type]
            osv_index=index,  # type: ignore[arg-type]
        )
    assert captured.value.request_ids == ["request-paid"]


def test_triage_failure_unions_prior_checkpoint_and_child_ids() -> None:
    runner = SimpleNamespace(
        checkpoint_metadata={"checkpoint-vul": {"operation_uuid": "checkpoint-operation-vul"}}
    )
    state = {
        "runner": runner,
        "vul_checkpoint": SimpleNamespace(uuid="checkpoint-vul"),
    }
    child = CheckpointError(
        "fixed checkpoint failed",
        kind="fix",
        operation_uuid="checkpoint-operation-fix",
        checkpoint_uuid="checkpoint-fix",
        request_id="request-fix",
    )
    wrapped = triage._triage_failure(child, model_call(), state)
    assert wrapped.request_ids == ["request-paid", "request-fix"]
    assert wrapped.checkpoint_uuids == {
        "fix": "checkpoint-fix",
        "vul": "checkpoint-vul",
    }
    assert wrapped.checkpoint_operation_uuids == {
        "fix": "checkpoint-operation-fix",
        "vul": "checkpoint-operation-vul",
    }
