from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reproof.errors import EvidencePersistenceError
from reproof.evaluation import _write_report
from reproof.triage import write_card


def evidence_card() -> SimpleNamespace:
    operations = [
        SimpleNamespace(
            kind=kind,
            operation_uuid=f"operation-{kind}",
            checkpoint_uuid=f"checkpoint-{kind}",
            checkpoint_operation_uuid=f"checkpoint-operation-{kind}",
        )
        for kind in ("vul", "fix")
    ]
    return SimpleNamespace(
        arvo_id=1,
        model_calls=[SimpleNamespace(request_id="request-test")],
        sandbox_operations=operations,
        model_dump_json=lambda **_kwargs: "{}",
    )


def fail_write(
    self: Path,
    _data: str,
    *,
    encoding: str,
    newline: str,
) -> None:
    del self, encoding, newline
    raise OSError("disk full")


def test_triage_write_failure_preserves_remote_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "write_text", fail_write)
    with pytest.raises(EvidencePersistenceError, match="Triage card persistence") as captured:
        write_card(tmp_path / "card.json", evidence_card())  # type: ignore[arg-type]
    assert captured.value.request_ids == ["request-test"]
    assert captured.value.operation_uuids == {
        "vul": "operation-vul",
        "fix": "operation-fix",
    }


def test_eval_write_failure_preserves_remote_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "write_text", fail_write)
    card = evidence_card()
    report = SimpleNamespace(model_dump_json=lambda **_kwargs: "{}")
    with pytest.raises(EvidencePersistenceError, match="Evaluation report persistence") as captured:
        _write_report(tmp_path / "eval.json", report, [card])  # type: ignore[arg-type,list-item]
    assert captured.value.request_ids == ["request-test"]
    assert captured.value.checkpoint_operation_uuids == {
        "1:vul": "checkpoint-operation-vul",
        "1:fix": "checkpoint-operation-fix",
    }
