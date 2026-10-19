from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reproof import claims
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
    assert attempt["input_tokens"] is None
    assert attempt["cost_usd"] is None
    assert attempt["input_price_per_million"] == 0.3
    assert report_text not in json.dumps(attempt)


def test_response_failure_records_usage_and_cost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REPROOF_CACHE_DIR", str(tmp_path))

    class Completions:
        def create(self, **_kwargs: object) -> object:
            return SimpleNamespace(
                _request_id="request-with-no-choice",
                choices=[],
                usage=SimpleNamespace(
                    prompt_tokens=10,
                    completion_tokens=5,
                    total_tokens=15,
                ),
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    with pytest.raises(ClaimExtractionError, match="no choices"):
        extract_claim("public test report", client=client)  # type: ignore[arg-type]

    attempt = json.loads((tmp_path / "model-attempts.jsonl").read_text(encoding="utf-8"))
    assert attempt["request_id"] == "request-with-no-choice"
    assert attempt["input_tokens"] == 10
    assert attempt["output_tokens"] == 5
    assert attempt["cost_usd"] == 0.0000075


def test_failed_attempt_log_write_preserves_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RequestError(RuntimeError):
        request_id = "request-failed"

    class Completions:
        def create(self, **_kwargs: object) -> None:
            raise RequestError("provider failed")

    def fail_log(_payload: dict[str, object]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(claims, "_record_attempt", fail_log)
    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    with pytest.raises(ClaimExtractionError, match="attempt log write failed") as captured:
        extract_claim("public test report", client=client)  # type: ignore[arg-type]
    assert captured.value.request_ids == ["request-failed"]


def test_success_attempt_log_write_preserves_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = json.dumps(
        {
            "project": "demo",
            "bug_class": "heap-buffer-overflow",
            "functions": ["parse"],
            "files": [],
            "trigger": "input",
            "poc_attached": True,
            "affected_version": "1.0",
            "missing_details": [],
        }
    )

    class Completions:
        def create(self, **_kwargs: object) -> object:
            return SimpleNamespace(
                _request_id="request-success",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop",
                        message=SimpleNamespace(content=content),
                    )
                ],
                usage=SimpleNamespace(
                    prompt_tokens=10,
                    completion_tokens=5,
                    total_tokens=15,
                ),
            )

    def fail_log(_payload: dict[str, object]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(claims, "_record_attempt", fail_log)
    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    with pytest.raises(ClaimExtractionError, match="response succeeded") as captured:
        extract_claim("public test report", client=client)  # type: ignore[arg-type]
    assert captured.value.request_ids == ["request-success"]


def test_intake_project_goes_to_the_system_message_and_never_into_report_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A jq report once came back asking for "version of json-c affected"; the report text never
    # named a project, so the maintainer's intake field now supplies it as trusted context.
    monkeypatch.setenv("REPROOF_CACHE_DIR", str(tmp_path))
    seen: list[list[dict[str, str]]] = []
    content = json.dumps(
        {
            "project": "jq",
            "bug_class": "heap-buffer-overflow",
            "functions": ["jv_parse"],
            "files": [],
            "trigger": "input",
            "poc_attached": True,
            "affected_version": "",
            "missing_details": [],
        }
    )

    class Completions:
        def create(self, **kwargs: object) -> object:
            seen.append(kwargs["messages"])  # type: ignore[arg-type]
            return SimpleNamespace(
                _request_id="request-project",
                choices=[
                    SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content=content))
                ],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    claim, _call = extract_claim("public test report", client=client, project="jq")  # type: ignore[arg-type]
    assert claim.project == "jq"
    system, user = seen[0]
    assert system["role"] == "system" and '"jq"' in system["content"]
    assert "never ask for a detail about a different project" in system["content"]
    assert user == {"role": "user", "content": "public test report"}

    extract_claim("public test report", client=client)  # type: ignore[arg-type]
    assert seen[1][0]["content"] == claims.SYSTEM_PROMPT


@pytest.mark.parametrize(
    ("project", "expected"),
    [
        ("jq", ["specific version affected"]),
        (None, ["project name (inferred from context)", "specific version affected"]),
    ],
)
def test_known_project_is_never_listed_as_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project: str | None,
    expected: list[str],
) -> None:
    # Production 2026-10-19, ARVO 42530604: the card listed "project name (inferred from
    # context)" although the intake had supplied jq.
    monkeypatch.setenv("REPROOF_CACHE_DIR", str(tmp_path))
    content = json.dumps(
        {
            "project": "jq",
            "bug_class": "heap-buffer-overflow",
            "functions": ["jv_parse"],
            "files": [],
            "trigger": "input",
            "poc_attached": True,
            "affected_version": "",
            "missing_details": [
                "project name (inferred from context)",
                "specific version affected",
            ],
        }
    )

    class Completions:
        def create(self, **_kwargs: object) -> object:
            return SimpleNamespace(
                _request_id="request-details",
                choices=[
                    SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content=content))
                ],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    claim, _call = extract_claim("public test report", client=client, project=project)  # type: ignore[arg-type]
    assert claim.missing_details == expected


def test_schema_field_names_in_missing_details_become_plain_phrases() -> None:
    # Production 2026-10-19, ARVO 42530604: one run returned these exact strings.
    assert claims.plain_missing_details(
        ["files", "trigger", "poc_attachesd (should be boolean)", "affected_version"]
    ) == ["file locations", "triggering input", "proof-of-concept input", "affected version"]
    assert claims.plain_missing_details(
        [
            "Affected version (e.g., git commit hash or release tag)",
            "File where `decToString` is defined",
            "affected version",
            "affected_version",
        ]
    ) == [
        "Affected version (e.g., git commit hash or release tag)",
        "File where `decToString` is defined",
        "affected version",
    ]
