from __future__ import annotations

import json
from pathlib import Path

import pytest

from reproof.claims import ClaimExtractionError, extract_claim


def test_failed_model_call_is_recorded_without_report_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REPROOF_CACHE_DIR", str(tmp_path))

    class Completions:
        def create(self, **_kwargs: object) -> None:
            raise RuntimeError("request failed")

    class Chat:
        completions = Completions()

    class Client:
        chat = Chat()

    report_text = "private-looking test marker that must not enter the attempt ledger"
    with pytest.raises(ClaimExtractionError, match="request failed"):
        extract_claim(report_text, client=Client())  # type: ignore[arg-type]

    attempt = json.loads((tmp_path / "model-attempts.jsonl").read_text(encoding="utf-8"))
    assert attempt["status"] == "failed"
    assert attempt["request_id"] is None
    assert report_text not in json.dumps(attempt)
