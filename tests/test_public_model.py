"""Mocked Nemotron planning and classification. No network."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from reproof.public_match import fallback_queries
from reproof.public_model import (
    QUERY_TOOL_NAME,
    BudgetExhausted,
    ModelBudget,
    PublicModelError,
    classify_page,
    plan_queries,
)

FRAMES = ("decNaNs", "decNumberCopy", "decCompareOp")
PAGE = "Stack-buffer-overflow in decNaNs\nPatched versions: 1.7.1\n"


def _usage() -> SimpleNamespace:
    return SimpleNamespace(prompt_tokens=11, completion_tokens=7, total_tokens=18)


def _response(
    *,
    request_id: str = "req-plan-1",
    tool_queries: list[str] | None = None,
    content: str | None = None,
    finish_reason: str = "tool_calls",
) -> SimpleNamespace:
    function = None
    tool_calls = None
    if tool_queries is not None:
        function = SimpleNamespace(
            name=QUERY_TOOL_NAME,
            arguments=json.dumps({"queries": tool_queries}),
        )
        tool_calls = [SimpleNamespace(function=function)]
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(finish_reason=finish_reason, message=message)
    return SimpleNamespace(_request_id=request_id, choices=[choice], usage=_usage())


class ScriptedClient:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if not self.responses:
            raise RuntimeError("no scripted response")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _client(responses: list[object]) -> SimpleNamespace:
    scripted = ScriptedClient(responses)
    client = SimpleNamespace(chat=SimpleNamespace(completions=scripted), scripted=scripted)
    return client


@pytest.fixture(autouse=True)
def _cache(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPROOF_CACHE_DIR", str(tmp_path))


def test_planner_sends_a_tool_call_and_keeps_guarded_queries() -> None:
    client = _client(
        [
            _response(
                tool_queries=[
                    "jq Stack-buffer-overflow decNaNs",
                    "jq decNaNs decNumberCopy",
                ]
            )
        ]
    )
    plan = plan_queries("jq", "Stack-buffer-overflow", FRAMES, client=client)  # type: ignore[arg-type]
    sent = client.scripted.calls[0]
    assert sent["tools"][0]["function"]["name"] == QUERY_TOOL_NAME  # type: ignore[index]
    assert "response_format" not in sent
    assert sent["temperature"] == 0
    assert sent["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}
    assert plan.query_source == "model"
    assert plan.rounds == 1
    assert plan.queries == (
        "jq Stack-buffer-overflow decNaNs",
        "jq decNaNs decNumberCopy",
    )
    assert plan.model_calls[0].request_id == "req-plan-1"
    assert plan.model_calls[0].cost_usd > 0


def test_rejected_queries_get_one_repair_round_and_are_not_returned() -> None:
    client = _client(
        [
            _response(request_id="req-bad", tool_queries=["stack overflow", "memory bug"]),
            _response(
                request_id="req-good",
                tool_queries=["jq decNaNs", "jq decNumberCopy decCompareOp"],
            ),
        ]
    )
    plan = plan_queries("jq", "Stack-buffer-overflow", FRAMES, client=client)  # type: ignore[arg-type]
    assert plan.query_source == "model"
    assert plan.rounds == 2
    assert plan.queries == ("jq decNaNs", "jq decNumberCopy decCompareOp")
    assert plan.rejected == (
        ("stack overflow", "missing_project_and_frame"),
        ("memory bug", "missing_project_and_frame"),
    )
    repair = str(client.scripted.calls[1]["messages"][1]["content"])  # type: ignore[index]
    assert "missing_project_and_frame" in repair
    assert "stack overflow" not in plan.queries


def test_two_rejected_rounds_use_the_deterministic_fallback() -> None:
    prose = json.dumps({"queries": ["jq decNaNs", "jq decNumberCopy"]})
    client = _client(
        [
            _response(content=prose, finish_reason="stop"),
            _response(request_id="req-2", content=prose, finish_reason="stop"),
        ]
    )
    plan = plan_queries("jq", "Stack-buffer-overflow", FRAMES, client=client)  # type: ignore[arg-type]
    assert plan.query_source == "deterministic_fallback"
    assert plan.queries == fallback_queries("jq", "Stack-buffer-overflow", FRAMES)
    assert plan.queries != ("jq decNaNs", "jq decNumberCopy")
    assert len(client.scripted.calls) == 2


def test_api_failure_is_not_turned_into_a_fallback(tmp_path: object) -> None:
    client = _client([RuntimeError("tools are not supported")])
    with pytest.raises(PublicModelError, match="tools are not supported") as caught:
        plan_queries("jq", "Stack-buffer-overflow", FRAMES, client=client)  # type: ignore[arg-type]
    assert caught.value.kind == "api"
    ledger = (tmp_path / "model-attempts.jsonl").read_text(encoding="utf-8")  # type: ignore[operator]
    assert "tools are not supported" in ledger
    assert "NEBIUS_API_KEY" not in ledger


def test_budget_exhaustion_skips_the_model() -> None:
    client = _client([_response(tool_queries=["jq decNaNs", "jq decNumberCopy"])])
    plan = plan_queries(
        "jq",
        "Stack-buffer-overflow",
        FRAMES,
        client=client,  # type: ignore[arg-type]
        budget=ModelBudget(limit=0),
    )
    assert plan.query_source == "budget_exhausted"
    assert plan.model_calls == ()
    assert client.scripted.calls == []
    assert plan.queries == fallback_queries("jq", "Stack-buffer-overflow", FRAMES)


def test_classifier_keeps_an_exact_quote_and_drops_a_composed_one() -> None:
    kept = {
        "relation": "SAME_BUG",
        "upstream_status": "FIXED",
        "upstream_version": "1.7.1",
        "upstream_commit": "",
        "supporting_quotes": ["Stack-buffer-overflow in decNaNs"],
        "dispute": False,
        "dispute_quotes": [],
    }
    client = _client(
        [_response(request_id="req-class", content=json.dumps(kept), finish_reason="stop")]
    )
    page = classify_page(
        PAGE,
        project="jq",
        crash_type="Stack-buffer-overflow",
        frames=FRAMES,
        client=client,  # type: ignore[arg-type]
    )
    sent = client.scripted.calls[0]
    schema = sent["response_format"]["json_schema"]  # type: ignore[index]
    assert schema["strict"] is True
    assert sent["temperature"] == 0
    assert sent["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}
    assert page.accepted
    assert page.relation == "SAME_BUG"
    assert page.upstream_version == "1.7.1"
    assert page.supporting_quotes == ("Stack-buffer-overflow in decNaNs",)

    composed = dict(kept)
    composed["supporting_quotes"] = ["decNaNs was fixed in a later release"]
    composed["upstream_version"] = "9.9.9"
    client = _client(
        [_response(request_id="req-bad-quote", content=json.dumps(composed), finish_reason="stop")]
    )
    rejected = classify_page(
        PAGE,
        project="jq",
        crash_type="Stack-buffer-overflow",
        frames=FRAMES,
        client=client,  # type: ignore[arg-type]
    )
    assert not rejected.accepted
    assert rejected.relation == ""
    assert rejected.rejection == "quote_not_in_page"
    assert rejected.model_calls[0].request_id == "req-bad-quote"


def test_classifier_rejects_a_version_missing_from_the_page() -> None:
    payload = {
        "relation": "SAME_BUG",
        "upstream_status": "FIXED",
        "upstream_version": "9.9.9",
        "upstream_commit": "",
        "supporting_quotes": ["Stack-buffer-overflow in decNaNs"],
        "dispute": False,
        "dispute_quotes": [],
    }
    client = _client([_response(content=json.dumps(payload), finish_reason="stop")])
    page = classify_page(
        PAGE,
        project="jq",
        crash_type="Stack-buffer-overflow",
        frames=FRAMES,
        client=client,  # type: ignore[arg-type]
    )
    assert not page.accepted
    assert page.rejection == "version_not_in_page"


def test_unrelated_classification_is_not_evidence() -> None:
    payload = {
        "relation": "UNRELATED",
        "upstream_status": "UNKNOWN",
        "upstream_version": "",
        "upstream_commit": "",
        "supporting_quotes": ["Stack-buffer-overflow in decNaNs"],
        "dispute": False,
        "dispute_quotes": [],
    }
    client = _client([_response(content=json.dumps(payload), finish_reason="stop")])
    page = classify_page(
        PAGE,
        project="jq",
        crash_type="Stack-buffer-overflow",
        frames=FRAMES,
        client=client,  # type: ignore[arg-type]
    )
    assert not page.accepted
    assert page.rejection == "unrelated"


def test_classify_budget_does_not_call_the_model() -> None:
    client = _client([])
    page = classify_page(
        PAGE,
        project="jq",
        crash_type="Stack-buffer-overflow",
        frames=FRAMES,
        client=client,  # type: ignore[arg-type]
        budget=ModelBudget(limit=0),
    )
    assert page.rejection == "budget_exhausted"
    assert client.scripted.calls == []
    with pytest.raises(BudgetExhausted):
        ModelBudget(limit=0).reserve()
