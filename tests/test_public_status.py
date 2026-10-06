"""Public-status lookup with fakes and recorded Tavily responses. No network."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from reproof.models import ModelCall, PublicStatus, PublicTavilyCall, TriageCard
from reproof.public_model import QUERY_TOOL_NAME
from reproof.public_status import (
    AdvisoryRecord,
    GitHubError,
    UrllibGitHub,
    attach_public_status,
    lookup_public_status,
    parse_advisory,
    task_advisory,
)
from reproof.public_tavily import (
    EXTRACT_CHUNKS,
    MAX_RESULTS,
    SEARCH_DEPTH,
    CreditLedger,
    TavilyApiError,
)
from tests.test_card import valid_card

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tavily"
FRAMES = ("decNaNs", "decNumberCopy", "decCompareOp")
CRASH = "Stack-buffer-overflow WRITE 2"
FIX = "b86ff49f46a4a37e5a8e75a140cb5fd6e1331384"
FORBIDDEN = "NAN1000000000"
PAGE = "https://github.com/jqlang/jq/issues/1"
FRAME_LINE = "Stack-buffer-overflow in decNaNs"
X6C3_QUOTE = "stack-buffer-overflow on address 0x7f0d8"


@pytest.fixture(autouse=True)
def _cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPROOF_CACHE_DIR", str(tmp_path))


def _usage() -> SimpleNamespace:
    return SimpleNamespace(prompt_tokens=11, completion_tokens=7, total_tokens=18)


def _response(
    *,
    request_id: str,
    tool_queries: list[str] | None = None,
    content: str | None = None,
    finish_reason: str = "tool_calls",
) -> SimpleNamespace:
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


def _model(*responses: object) -> SimpleNamespace:
    scripted = ScriptedClient(list(responses))
    return SimpleNamespace(chat=SimpleNamespace(completions=scripted), scripted=scripted)


def _plan(*queries: str, request_id: str = "req-plan") -> SimpleNamespace:
    return _response(request_id=request_id, tool_queries=list(queries))


def _classify(
    relation: str,
    status: str,
    quote: str,
    *,
    request_id: str,
    version: str = "",
    commit: str = "",
    dispute: bool = False,
    dispute_quotes: list[str] | None = None,
) -> SimpleNamespace:
    payload = {
        "relation": relation,
        "upstream_status": status,
        "upstream_version": version,
        "upstream_commit": commit,
        "supporting_quotes": [quote],
        "dispute": dispute,
        "dispute_quotes": dispute_quotes or [],
    }
    return _response(
        request_id=request_id,
        content=json.dumps(payload),
        finish_reason="stop",
    )


class FakeTavily:
    def __init__(
        self,
        searches: list[object] | None = None,
        extracts: list[object] | None = None,
        crawls: list[object] | None = None,
    ) -> None:
        self.searches = list(searches or [])
        self.extracts = list(extracts or [])
        self.crawls = list(crawls or [])
        self.search_calls: list[dict[str, Any]] = []
        self.extract_calls: list[dict[str, Any]] = []
        self.crawl_calls: list[dict[str, Any]] = []

    def search(self, **kwargs: Any) -> object:
        self.search_calls.append(kwargs)
        return self._pop(self.searches)

    def extract(self, **kwargs: Any) -> object:
        self.extract_calls.append(kwargs)
        return self._pop(self.extracts)

    def crawl(self, **kwargs: Any) -> object:
        self.crawl_calls.append(kwargs)
        return self._pop(self.crawls)

    @staticmethod
    def _pop(items: list[object]) -> object:
        if not items:
            raise RuntimeError("no scripted response")
        item = items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class ScriptedGitHub:
    def __init__(
        self,
        tags: tuple[str, ...],
        ahead_by: int = 102,
        behind_by: int = 0,
        *,
        status: str | None = None,
        advisory: AdvisoryRecord | None = None,
        advisory_error: str = "",
    ) -> None:
        self.tags = tags
        self.ahead_by = ahead_by
        self.behind_by = behind_by
        self.status = status if status is not None else ("ahead" if ahead_by else "behind")
        self.advisory = advisory
        self.advisory_error = advisory_error
        self.compare_calls: list[tuple[str, str]] = []
        self.advisory_calls: list[tuple[str, str, str]] = []
        self.tag_calls = 0

    def list_tags(self, owner: str, repo: str) -> tuple[str, ...]:
        self.tag_calls += 1
        return self.tags

    def compare(self, owner: str, repo: str, base: str, head: str) -> Any:
        self.compare_calls.append((base, head))
        from reproof.public_status import CompareResult

        return CompareResult(self.status, self.ahead_by, self.behind_by)

    def read_advisory(self, owner: str, repo: str, ghsa_id: str) -> AdvisoryRecord:
        self.advisory_calls.append((owner, repo, ghsa_id))
        if self.advisory_error:
            return AdvisoryRecord(ghsa_id=ghsa_id, error=self.advisory_error)
        if self.advisory is not None:
            return self.advisory
        return AdvisoryRecord(ghsa_id=ghsa_id)


class RaisingGitHub:
    def list_tags(self, owner: str, repo: str) -> tuple[str, ...]:
        raise AssertionError("tags")

    def compare(self, owner: str, repo: str, base: str, head: str) -> Any:
        raise AssertionError("compare")

    def read_advisory(self, owner: str, repo: str, ghsa_id: str) -> AdvisoryRecord:
        raise AssertionError("advisory")


def _recorded(name: str) -> dict[str, Any]:
    payload = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    assert payload["label"] == "RECORDED"
    return payload


def _search_body(results: list[dict[str, Any]], request_id: str) -> dict[str, Any]:
    return {"request_id": request_id, "results": results, "usage": {"credits": 2}}


def _hit(content: str, url: str = PAGE) -> dict[str, Any]:
    return {"url": url, "title": "jq", "content": content, "score": 0.9}


def _extract_body(text: str, *, url: str = PAGE, title: str = "jq page") -> dict[str, Any]:
    return {
        "request_id": "req-extract",
        "usage": {"credits": 1},
        "results": [{"url": url, "title": title, "raw_content": text}],
    }


def _empty_search(request_id: str) -> dict[str, Any]:
    return _search_body([], request_id)


def _one_page_tavily(text: str) -> FakeTavily:
    return FakeTavily(
        searches=[
            _search_body([_hit(text)], "req-search-1"),
            _empty_search("req-search-2"),
        ],
        extracts=[_extract_body(text)],
    )


def _lookup(**kwargs: Any) -> PublicStatus:
    defaults: dict[str, Any] = {
        "project": "jq",
        "crash_type": CRASH,
        "frames": FRAMES,
        "owner": "jqlang",
        "repo": "jq",
        "fix_commits": (FIX,),
        "retrieved_on": "2026-10-05",
        "ledger": CreditLedger(),
    }
    defaults.update(kwargs)
    return lookup_public_status(**defaults)


def test_recorded_jq_demotes_1_7_1_and_keeps_the_open_advisory() -> None:
    search_1 = _recorded("RECORDED-jq-42531223-search-1.json")
    search_2 = _recorded("RECORDED-jq-42531223-search-2.json")
    extract = _recorded("RECORDED-jq-42531223-extract.json")
    tavily = FakeTavily(
        searches=[search_1["response"], search_2["response"]],
        extracts=[extract["response"]],
    )
    model = _model(
        _plan(search_1["query"], search_2["query"]),
        _classify(
            "SAME_BUG",
            "FIXED",
            FRAME_LINE,
            request_id="req-7hmr",
            version="1.7.1",
        ),
        _classify("SAME_BUG", "OPEN", X6C3_QUOTE, request_id="req-x6c3"),
    )
    github = ScriptedGitHub(("jq-1.7.1", "jq-1.7"), ahead_by=102, behind_by=0)
    status = _lookup(
        tavily_client=tavily,
        model_client=model,
        transport=github,
        forbidden=(FORBIDDEN,),
    )

    assert status.state == "PUBLICLY_KNOWN_OPEN"
    assert status.tavily_credits == 5
    assert status.tavily_request_ids == [
        search_1["response"]["request_id"],
        search_2["response"]["request_id"],
        extract["response"]["request_id"],
    ]
    assert status.queries_sent == [search_1["query"], search_2["query"]]
    assert status.query_source == "model"
    assert status.frame_rejected == 2
    assert status.host_rejected == 2
    assert status.snippet_rejected == 1
    assert status.source_file_rejected == 1
    assert status.quote_rejected == 0
    assert status.unrelated_rejected == 0
    assert [call.request_id for call in status.model_calls] == [
        "req-plan",
        "req-7hmr",
        "req-x6c3",
    ]
    assert len(tavily.extract_calls) == 1
    sent = tavily.extract_calls[0]
    assert sent["chunks_per_source"] == EXTRACT_CHUNKS
    assert sent["include_usage"] is True
    assert sent["query"] == "decNaNs decNumberCopy decCompareOp"
    search = tavily.search_calls[0]
    assert search["search_depth"] == SEARCH_DEPTH
    assert search["max_results"] == MAX_RESULTS
    assert search["auto_parameters"] is False
    assert "github.com" in search["include_domains"]
    assert "nvd.nist.gov" in search["include_domains"]
    assert "cve.org" in search["include_domains"]
    assert github.compare_calls == [("jq-1.7.1", FIX)]

    older, newer = status.evidence
    assert older.url.endswith("GHSA-7hmr-442f-qc8j")
    assert older.relation == "RELATED_VARIANT"
    assert older.upstream_status == "UNKNOWN"
    assert older.upstream_version == ""
    assert older.ancestry == "DOES_NOT_CONTAIN_FIX"
    assert older.checked_tag == "jq-1.7.1"
    assert older.checked_commit == FIX
    assert older.stale_fields == ["patched_version:1.7.1"]
    assert older.frames_matched == ["decNaNs"]
    assert older.ghsa_ids == ["ghsa-7hmr-442f-qc8j"]
    assert older.patched_versions == ["1.7.1"]
    assert older.version_sources == ["page_text:1.7.1", "model:1.7.1"]
    assert older.match_reason == "top_frame_and_crash_type"
    assert "64771" in older.title
    assert FORBIDDEN not in "".join(older.matched_lines)

    assert newer.url.endswith("GHSA-x6c3-qv5r-7q22")
    assert newer.relation == "SAME_BUG"
    assert newer.upstream_status == "OPEN"
    assert newer.ancestry == "NOT_CHECKABLE"
    assert newer.ghsa_ids == []
    assert newer.frames_matched == ["decNaNs", "decNumberCopy", "decCompareOp"]
    assert "matched line withheld" in newer.matched_lines
    assert FIX not in newer.mentioned_commits
    assert newer.checked_tag == ""
    assert newer.version_sources == []
    assert github.advisory_calls == [
        ("jqlang", "jq", "GHSA-7hmr-442f-qc8j"),
        ("jqlang", "jq", "GHSA-x6c3-qv5r-7q22"),
    ]

    dumped = status.model_dump_json()
    assert FORBIDDEN not in dumped
    assert "novel" not in dumped.casefold()
    assert "\u2014" not in dumped
    assert "not recorded as the fix" not in status.note
    assert status.draft[0].confidence == "high"
    assert "does not contain the recorded fix" in status.draft[0].text
    assert "patched_version:1.7.1" in status.draft[0].text
    assert "Date: 2026-10-05" in status.draft[0].text
    assert status.draft[1].confidence == "medium"
    assert "No containing fix was verified" in status.draft[1].text
    assert status.draft[1].source_url == newer.url


def test_unrelated_open_advisory_leaves_only_the_related_variant() -> None:
    search_1 = _recorded("RECORDED-jq-42531223-search-1.json")
    search_2 = _recorded("RECORDED-jq-42531223-search-2.json")
    extract = _recorded("RECORDED-jq-42531223-extract.json")
    tavily = FakeTavily(
        searches=[search_1["response"], search_2["response"]],
        extracts=[extract["response"]],
    )
    model = _model(
        _plan(search_1["query"], search_2["query"]),
        _classify("SAME_BUG", "FIXED", FRAME_LINE, request_id="req-7hmr", version="1.7.1"),
        _classify("UNRELATED", "OPEN", X6C3_QUOTE, request_id="req-x6c3"),
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=model,
        transport=ScriptedGitHub(("jq-1.7.1",), ahead_by=102),
    )
    assert status.state == "RELATED_VARIANTS_ONLY"
    assert status.unrelated_rejected == 1
    assert [item.url for item in status.evidence] == [
        "https://github.com/jqlang/jq/security/advisories/GHSA-7hmr-442f-qc8j"
    ]
    assert status.evidence[0].relation == "RELATED_VARIANT"


def test_containing_tag_is_recorded_as_the_fix() -> None:
    text = f"{FRAME_LINE}\nPatched versions: 1.8.0\n"
    github = ScriptedGitHub(("jq-1.8.0", "jq-1.7"), ahead_by=0, behind_by=4)
    status = _lookup(
        tavily_client=_one_page_tavily(text),
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "FIXED", FRAME_LINE, request_id="req-fix", version="1.8.0"),
        ),
        transport=github,
    )
    assert status.state == "PUBLICLY_KNOWN_FIXED"
    assert status.evidence[0].upstream_version == "1.8.0"
    assert status.evidence[0].checked_tag == "jq-1.8.0"
    assert status.evidence[0].relation == "SAME_BUG"
    assert status.evidence[0].upstream_status == "FIXED"
    assert github.compare_calls == [("jq-1.8.0", FIX)]
    assert status.evidence[0].version_sources == ["page_text:1.8.0", "model:1.8.0"]
    assert (
        "Fixed in jq 1.8.0. Git ancestry: tag jq-1.8.0 contains OSV fix b86ff49."
        in status.draft[0].text
    )
    assert status.draft[0].confidence == "high"


def test_named_fix_commit_marks_a_none_field_stale_without_compare() -> None:
    text = f"{FRAME_LINE}\nPatched versions: None\n{FIX}\n"
    status = _lookup(
        tavily_client=_one_page_tavily(text),
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "FIXED", FRAME_LINE, request_id="req-hash"),
        ),
        transport=RaisingGitHub(),
    )
    item = status.evidence[0]
    assert status.state == "PUBLICLY_KNOWN_FIXED"
    assert item.ancestry == "CONTAINS_FIX"
    assert item.checked_commit == FIX
    assert item.checked_tag == ""
    assert item.upstream_version == ""
    assert "patched_versions:None" in item.stale_fields
    assert "names the recorded fix commit" in status.draft[0].text
    assert "git ancestry" not in status.draft[0].text.casefold()


def test_dispute_leads_when_the_fix_is_not_verified() -> None:
    text = f"{FRAME_LINE}\nThe OSV range is wrong\n"
    status = _lookup(
        tavily_client=_one_page_tavily(text),
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify(
                "SAME_BUG",
                "OPEN",
                FRAME_LINE,
                request_id="req-dispute",
                dispute=True,
                dispute_quotes=["The OSV range is wrong"],
            ),
        ),
        transport=None,
    )
    assert status.state == "SOURCE_DISPUTE"
    assert status.evidence[0].dispute is True
    assert status.draft[0].text.startswith("This page disputes the recorded upstream status.")


def test_short_frames_send_no_search() -> None:
    class Boom:
        def search(self, **kwargs: Any) -> object:
            raise AssertionError("search")

        def extract(self, **kwargs: Any) -> object:
            raise AssertionError("extract")

    model = _model()
    status = _lookup(frames=["abc"], tavily_client=Boom(), model_client=model)
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.tavily_credits == 0
    assert status.model_calls == []
    assert status.note == "No measured crash frame was available, so no search was sent."
    assert model.scripted.calls == []


def test_search_error_redacts_the_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "dummy-key-value-12345678"
    monkeypatch.setenv("TAVILY_API_KEY", secret)

    class Boom:
        def search(self, **kwargs: Any) -> object:
            raise RuntimeError(f"boom {secret}")

    status = _lookup(
        tavily_client=Boom(),
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
    )
    dumped = status.model_dump_json()
    assert secret not in dumped
    assert "[redacted]" in dumped
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert any(item.startswith("search failed:") for item in status.failed_sources)


def test_unread_search_hits_are_not_reported_as_no_findings() -> None:
    text = f"{FRAME_LINE}\n"
    tavily = FakeTavily(
        searches=[_search_body([_hit(text)], "req-search-1"), _empty_search("req-search-2")],
        extracts=[RuntimeError("extract down")],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
    )
    assert len(tavily.extract_calls) == 1
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.evidence == []
    assert any(item.startswith("extract failed:") for item in status.failed_sources)


def test_empty_search_is_no_findings_not_unavailable() -> None:
    tavily = FakeTavily(searches=[_empty_search("req-a"), _empty_search("req-b")])
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
    )
    assert len(tavily.search_calls) == 2
    assert tavily.extract_calls == []
    assert status.state == "NO_PUBLIC_FINDINGS"


def test_budget_stop_before_any_search_is_unavailable() -> None:
    tavily = FakeTavily()
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
        ledger=CreditLedger(used=199),
    )
    assert tavily.search_calls == []
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.queries_sent == []
    assert "search stopped: budget" in status.failed_sources


def test_first_response_without_usage_is_unavailable() -> None:
    text = f"{FRAME_LINE}\n"
    no_usage = {"request_id": "req-no-usage", "results": [_hit(text)]}
    tavily = FakeTavily(searches=[no_usage, AssertionError("second search")])
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
    )
    assert len(tavily.search_calls) == 1
    assert tavily.extract_calls == []
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.queries_sent == ["jq Stack-buffer-overflow decNaNs"]


def test_responses_without_a_result_list_are_unavailable() -> None:
    bare = {"request_id": "req-bare", "usage": {"credits": 2}}
    tavily = FakeTavily(searches=[bare, {**bare, "request_id": "req-bare-2", "results": None}])
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
    )
    assert len(tavily.search_calls) == 2
    assert status.state == "LOOKUP_UNAVAILABLE"


def test_only_sent_queries_are_listed_as_searched() -> None:
    tavily = FakeTavily(searches=[_empty_search("req-a"), _empty_search("req-b")])
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy", "jq decCompareOp crash")
        ),
    )
    assert len(tavily.search_calls) == 2
    assert status.state == "NO_PUBLIC_FINDINGS"
    sent = [call["query"] for call in tavily.search_calls]
    assert status.queries_sent == sent
    assert "jq decCompareOp crash" not in status.note


def test_a_later_search_error_keeps_the_first_result_list() -> None:
    text = f"{FRAME_LINE}\nThis crash is still open.\n"
    tavily = FakeTavily(
        searches=[
            _search_body([_hit(text)], "req-search-1"),
            RuntimeError("second search transport down"),
        ],
        extracts=[_extract_body(text)],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "OPEN", FRAME_LINE, request_id="req-open"),
        ),
    )
    assert len(tavily.search_calls) == 2
    assert len(tavily.extract_calls) == 1
    assert status.state == "PUBLICLY_KNOWN_OPEN"
    assert status.queries_sent == ["jq Stack-buffer-overflow decNaNs"]
    assert any(item.startswith("search stopped: error:") for item in status.failed_sources)
    # The failed search is not reported as charged, but its estimate is carried for the budget.
    assert status.tavily_credits == 3
    assert status.tavily_unanswered_credits == 2


def test_a_later_response_without_request_id_is_kept_as_sent() -> None:
    text = f"{FRAME_LINE}\n"
    no_id = {"request_id": "", "results": [_hit(text)], "usage": {"credits": 2}}
    tavily = FakeTavily(
        searches=[_search_body([_hit(text)], "req-search-1"), no_id],
        extracts=[_extract_body(text)],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "OPEN", FRAME_LINE, request_id="req-open"),
        ),
    )
    assert status.queries_sent == ["jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"]
    assert len(tavily.extract_calls) == 1
    assert status.state != "LOOKUP_UNAVAILABLE"
    assert any("no request_id" in item for item in status.failed_sources)


def test_a_later_response_that_is_not_an_object_is_not_listed_as_sent() -> None:
    text = f"{FRAME_LINE}\n"
    tavily = FakeTavily(
        searches=[_search_body([_hit(text)], "req-search-1"), "not-a-dict"],
        extracts=[_extract_body(text)],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "OPEN", FRAME_LINE, request_id="req-open"),
        ),
    )
    assert len(tavily.search_calls) == 2
    assert status.queries_sent == ["jq Stack-buffer-overflow decNaNs"]
    assert any("not an object" in item for item in status.failed_sources)
    # Sent and unreadable: not reported, but its estimate is counted.
    assert status.tavily_unanswered_credits == 2


def test_an_unreadable_answer_counts_before_the_next_call_is_allowed() -> None:
    text = f"{FRAME_LINE}\n"
    overbilled = {"request_id": "req-search-1", "results": [_hit(text)], "usage": {"credits": 3}}
    tavily = FakeTavily(
        searches=[overbilled, "not-a-dict"],
        extracts=[AssertionError("extract must be refused")],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
        ledger=CreditLedger(limit=5),
    )
    # 3 reported + 2 unanswered + 1 for the extract would pass 5, so the extract is not sent.
    assert len(tavily.search_calls) == 2
    assert tavily.extract_calls == []
    assert status.tavily_credits == 3
    assert status.tavily_unanswered_credits == 2
    assert status.state == "LOOKUP_UNAVAILABLE"


def test_a_later_search_error_text_is_scrubbed_on_the_card(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "dummy-key-value-12345678"
    monkeypatch.setenv("TAVILY_API_KEY", secret)
    text = f"{FRAME_LINE}\n"
    tavily = FakeTavily(
        searches=[
            _search_body([_hit(text)], "req-search-1"),
            TavilyApiError(f"direct {secret}\n" + "x" * 400),
        ],
        extracts=[_extract_body(text)],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "OPEN", FRAME_LINE, request_id="req-open"),
        ),
    )
    stopped = [item for item in status.failed_sources if item.startswith("search stopped:")]
    assert len(stopped) == 1
    assert secret not in status.model_dump_json()
    assert "\n" not in stopped[0]
    assert len(stopped[0]) <= 300


def test_rejected_crawl_page_counts_as_read() -> None:
    text = f"{FRAME_LINE}\n"
    page = {
        "url": "https://github.com/jqlang/jq/blob/HEAD/SECURITY.md",
        "title": "SECURITY.md",
        "raw_content": "Report security issues privately.\n",
    }
    tavily = FakeTavily(
        searches=[_search_body([_hit(text)], "req-search-1"), _empty_search("req-search-2")],
        extracts=[RuntimeError("extract down")],
        crawls=[
            {"request_id": "req-crawl", "usage": {"credits": 2}, "results": [page]},
            {"request_id": "req-crawl-2", "usage": {"credits": 2}, "results": []},
        ],
    )
    status = _lookup(
        tavily_client=tavily,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
        crawl_fallback=True,
    )
    assert len(tavily.crawl_calls) >= 1
    assert status.frame_rejected >= 1
    assert status.state == "NO_PUBLIC_FINDINGS"


def test_quote_missing_from_the_page_is_rejected() -> None:
    text = f"{FRAME_LINE}\n"
    status = _lookup(
        tavily_client=_one_page_tavily(text),
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "OPEN", "this quote is not on the page", request_id="req-bad"),
        ),
    )
    assert status.state == "NO_PUBLIC_FINDINGS"
    assert status.quote_rejected == 1
    assert status.evidence == []


def test_crawl_stays_off_unless_asked_and_stops_after_one_match() -> None:
    class NoCrawl(FakeTavily):
        def crawl(self, **kwargs: Any) -> object:
            raise AssertionError("crawl")

    quiet = NoCrawl(
        searches=[_empty_search("req-a"), _empty_search("req-b")],
    )
    skipped = _lookup(
        tavily_client=quiet,
        model_client=_model(_plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy")),
    )
    assert skipped.state == "NO_PUBLIC_FINDINGS"
    assert quiet.crawl_calls == []

    page = {
        "url": "https://github.com/jqlang/jq/blob/HEAD/SECURITY.md",
        "title": "SECURITY.md",
        "raw_content": f"{FRAME_LINE}\nThis crash is still open.\n",
    }
    crawled = FakeTavily(
        searches=[_empty_search("req-c"), _empty_search("req-d")],
        crawls=[
            {"request_id": "req-crawl", "usage": {"credits": 2}, "results": [page]},
            AssertionError("second crawl"),
        ],
    )
    status = _lookup(
        tavily_client=crawled,
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "OPEN", FRAME_LINE, request_id="req-security"),
        ),
        crawl_fallback=True,
    )
    assert status.state == "PUBLICLY_KNOWN_OPEN"
    assert len(crawled.crawl_calls) == 1
    assert crawled.crawl_calls[0]["url"].endswith("/SECURITY.md")


def test_missing_tag_is_not_recorded_as_the_fix() -> None:
    text = f"{FRAME_LINE}\nPatched versions: 9.9.9\n"
    status = _lookup(
        tavily_client=_one_page_tavily(text),
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", "FIXED", FRAME_LINE, request_id="req-missing", version="9.9.9"),
        ),
        transport=ScriptedGitHub(("jq-1.7.1",)),
    )
    assert status.state == "PUBLICLY_KNOWN_OPEN"
    assert status.evidence[0].upstream_status == "UNKNOWN"
    assert status.evidence[0].upstream_version == ""
    assert status.evidence[0].ancestry == "NOT_CHECKABLE"
    assert "9.9.9" in status.note
    assert "not recorded as the fix" in status.note
    assert any("git tag 9.9.9" in item for item in status.failed_sources)


def test_attach_merges_model_cost_and_leaves_tavily_credits_off_the_total() -> None:
    call = ModelCall(
        model="test/model",
        latency_seconds=0.1,
        input_tokens=1,
        output_tokens=1,
        total_tokens=2,
        input_price_per_million=0.3,
        output_price_per_million=0.9,
        price_source="public test price",
        cost_usd=0.0000012,
        request_id="public-status-call",
    )
    status = PublicStatus(
        state="NO_PUBLIC_FINDINGS",
        evidence=[],
        queries_sent=["jq decNaNs"],
        query_source="model",
        domains=["github.com"],
        failed_sources=[],
        note="Searched queries: jq decNaNs.",
        tavily_request_ids=["req-tavily"],
        tavily_calls=[
            PublicTavilyCall(
                operation="search",
                request_id="req-tavily",
                credits=2,
                query="jq decNaNs",
            )
        ],
        tavily_credits=2,
        model_calls=[call],
        draft=[],
    )
    raw = valid_card()
    raw["public_status"] = status.model_dump()
    with pytest.raises(
        ValidationError, match="public status model calls must also be card model calls"
    ):
        TriageCard.model_validate(raw)

    card = TriageCard.model_validate(valid_card())
    updated = attach_public_status(card, status)
    assert updated.schema_version == "1.5"
    assert updated.verdict == card.verdict
    assert updated.public_status is not None
    assert updated.public_status.tavily_credits == 2
    assert updated.model_cost_usd == pytest.approx(card.model_cost_usd + call.cost_usd)
    assert updated.total_cost_usd == pytest.approx(updated.model_cost_usd + card.sandbox_cost_usd)
    assert updated.total_cost_usd == pytest.approx(card.total_cost_usd + call.cost_usd)
    assert {item.request_id for item in updated.model_calls} == {
        "request-test",
        "public-status-call",
    }


def test_unsafe_github_refs_do_not_call_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network")

    monkeypatch.setattr("reproof.public_status.urllib.request.urlopen", boom)
    github = UrllibGitHub()
    assert github.compare("../x", "jq", "jq-1.7.1", FIX).error == "unsafe_repo"
    assert github.compare("jqlang", "jq", "bad ref", FIX).error == "unsafe_base"
    assert github.compare("jqlang", "jq", "jq-1.7.1", "abc").error == "unsafe_head"
    with pytest.raises(GitHubError, match="unsafe_repo"):
        github.list_tags("../x", "jq")
    assert github.read_advisory("../x", "jq", "GHSA-686w-5m7m-54vc").error == "unsafe_repo"
    assert github.read_advisory("jqlang", "jq", "not-a-ghsa").error == "unsafe_ghsa"


GITHUB_DIR = Path(__file__).parent / "fixtures" / "github"
JQ_FIX_686 = "71c2ab509a8628dbbad4bc7b3f98a64aa90d3297"
ADVISORY_686 = "https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc"


def _github_fixture(name: str) -> dict[str, Any]:
    return json.loads((GITHUB_DIR / name).read_text(encoding="utf-8"))


def _recorded_686() -> AdvisoryRecord:
    payload = _github_fixture("RECORDED-advisory-GHSA-686w-5m7m-54vc.json")
    assert payload["label"] == "RECORDED"
    return parse_advisory(payload["response"], "GHSA-686w-5m7m-54vc")


class _Body:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def test_recorded_advisory_parse_keeps_only_a_version_token() -> None:
    payload = _github_fixture("RECORDED-advisory-GHSA-686w-5m7m-54vc.json")
    record = parse_advisory(payload["response"], "GHSA-686w-5m7m-54vc")
    assert record.error == ""
    assert record.cve_id == "CVE-2023-50246"
    assert record.state == "published"
    assert record.published_at == "2023-12-13T19:20:47Z"
    assert record.patched_versions == ("1.7.1",)
    assert record.raw_patched_versions == ("1.7.1",)
    compare = _github_fixture("RECORDED-compare-jq-1.7.1-71c2ab5.json")
    assert compare["label"] == "RECORDED"
    assert compare["response"]["status"] == "identical"
    assert compare["response"]["ahead_by"] == 0
    assert compare["response"]["behind_by"] == 0

    stale = _github_fixture("HAND-BUILT-advisory-stale.json")
    assert stale["label"] == "HAND-BUILT"
    parsed = parse_advisory(stale["response"], "GHSA-2222-2222-2222")
    assert parsed.error == ""
    assert parsed.cve_id == ""
    assert parsed.patched_versions == ("1.6.0",)
    assert parsed.raw_patched_versions == ("1.6.0, >= 9.9.9",)


def test_urllib_advisory_reader_uses_the_recorded_body(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _github_fixture("RECORDED-advisory-GHSA-686w-5m7m-54vc.json")
    seen: list[str] = []

    def fake_open(request: Any, timeout: int = 30) -> _Body:
        seen.append(request.full_url)
        assert timeout == 30
        return _Body(json.dumps(payload["response"]).encode("utf-8"))

    monkeypatch.setattr("reproof.public_status.urllib.request.urlopen", fake_open)
    record = UrllibGitHub().read_advisory("jqlang", "jq", "GHSA-686w-5m7m-54vc")
    assert record.patched_versions == ("1.7.1",)
    assert record.cve_id == "CVE-2023-50246"
    assert seen == [
        "https://api.github.com/repos/jqlang/jq/security-advisories/GHSA-686w-5m7m-54vc"
    ]


def test_urllib_advisory_reader_reports_http_and_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    def missing(request: Any, timeout: int = 30) -> _Body:
        raise urllib.error.HTTPError(request.full_url, 404, "missing", hdrs=None, fp=None)

    monkeypatch.setattr("reproof.public_status.urllib.request.urlopen", missing)
    assert UrllibGitHub().read_advisory("jqlang", "jq", "GHSA-686w-5m7m-54vc").error == "http_404"

    def slow(request: Any, timeout: int = 30) -> _Body:
        raise TimeoutError("timed out")

    monkeypatch.setattr("reproof.public_status.urllib.request.urlopen", slow)
    assert UrllibGitHub().read_advisory("jqlang", "jq", "GHSA-686w-5m7m-54vc").error == "timeout"

    def broken(request: Any, timeout: int = 30) -> _Body:
        return _Body(b"not-json")

    monkeypatch.setattr("reproof.public_status.urllib.request.urlopen", broken)
    assert UrllibGitHub().read_advisory("jqlang", "jq", "GHSA-686w-5m7m-54vc").error == "not_json"

    def shaped(request: Any, timeout: int = 30) -> _Body:
        return _Body(b'{"ghsa_id": "GHSA-0000-0000-0000"}')

    monkeypatch.setattr("reproof.public_status.urllib.request.urlopen", shaped)
    assert (
        UrllibGitHub().read_advisory("jqlang", "jq", "GHSA-686w-5m7m-54vc").error
        == "advisory_shape"
    )


def test_task_advisory_matches_only_the_task_repo() -> None:
    assert task_advisory(ADVISORY_686, "jqlang", "jq") == (
        "jqlang",
        "jq",
        "GHSA-686w-5m7m-54vc",
    )
    mixed = "https://github.com/JQLang/JQ/security/advisories/GHSA-686W-5M7M-54VC"
    assert task_advisory(mixed, "jqlang", "jq") == ("jqlang", "jq", "GHSA-686w-5m7m-54vc")
    assert task_advisory(ADVISORY_686 + "/", "jqlang", "jq") is None
    assert task_advisory(ADVISORY_686 + "/extra", "jqlang", "jq") is None
    other = "https://github.com/other/jq/security/advisories/GHSA-686w-5m7m-54vc"
    assert task_advisory(other, "jqlang", "jq") is None
    assert (
        task_advisory(
            "https://www.github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc",
            "jqlang",
            "jq",
        )
        is None
    )


def _advisory_lookup(
    github: ScriptedGitHub,
    *,
    url: str = ADVISORY_686,
    fix: str = JQ_FIX_686,
    status: str = "UNKNOWN",
) -> Any:
    text = f"{FRAME_LINE}\nThe advisory page names the crash.\n"
    return _lookup(
        tavily_client=FakeTavily(
            searches=[
                _search_body([_hit(text, url)], "req-search-1"),
                _empty_search("req-search-2"),
            ],
            extracts=[_extract_body(text, url=url, title="jq advisory")],
        ),
        model_client=_model(
            _plan("jq Stack-buffer-overflow decNaNs", "jq decNumberCopy"),
            _classify("SAME_BUG", status, FRAME_LINE, request_id="req-adv"),
        ),
        transport=github,
        fix_commits=(fix,),
    )


def test_advisory_version_and_ancestry_record_the_fix() -> None:
    compare = _github_fixture("RECORDED-compare-jq-1.7.1-71c2ab5.json")["response"]
    github = ScriptedGitHub(
        ("jq-1.7.1",),
        ahead_by=compare["ahead_by"],
        behind_by=compare["behind_by"],
        status=compare["status"],
        advisory=_recorded_686(),
    )
    status = _advisory_lookup(github)
    item = status.evidence[0]
    assert status.state == "PUBLICLY_KNOWN_FIXED"
    assert item.upstream_status == "FIXED"
    assert item.upstream_version == "1.7.1"
    assert item.checked_tag == "jq-1.7.1"
    assert item.checked_commit == JQ_FIX_686
    assert item.version_sources == ["github_advisory_api:1.7.1"]
    assert item.ancestry == "CONTAINS_FIX"
    assert github.advisory_calls == [("jqlang", "jq", "GHSA-686w-5m7m-54vc")]
    assert github.compare_calls == [("jq-1.7.1", JQ_FIX_686)]
    assert (
        "Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5."
        in status.draft[0].text
    )
    assert ADVISORY_686 in status.draft[0].text


@pytest.mark.parametrize("reason", ["http_404", "advisory_shape"])
def test_advisory_lookup_failure_keeps_the_old_state(reason: str) -> None:
    github = ScriptedGitHub(("jq-1.7.1",), advisory_error=reason)
    status = _advisory_lookup(github)
    assert status.state == "PUBLICLY_KNOWN_OPEN"
    assert status.state != "PUBLICLY_KNOWN_FIXED"
    item = status.evidence[0]
    assert item.upstream_status == "UNKNOWN"
    assert item.upstream_version == ""
    assert item.version_sources == []
    assert item.ancestry == "NOT_CHECKABLE"
    assert status.failed_sources == [f"github advisory GHSA-686w-5m7m-54vc: {reason}"]
    assert github.compare_calls == []


def test_advisory_on_another_repo_is_not_read() -> None:
    github = ScriptedGitHub(("jq-1.7.1",), advisory=_recorded_686())
    other = "https://github.com/other/jq/security/advisories/GHSA-686w-5m7m-54vc"
    status = _advisory_lookup(github, url=other)
    assert github.advisory_calls == []
    assert status.state == "NO_PUBLIC_FINDINGS"
    assert status.host_rejected == 1

    slashed = ADVISORY_686 + "/"
    kept = _advisory_lookup(github, url=slashed)
    assert github.advisory_calls == []
    assert kept.state == "PUBLICLY_KNOWN_OPEN"
    assert kept.evidence[0].version_sources == []
    assert "github advisory" not in " ".join(kept.failed_sources)


def test_advisory_version_git_contradicts_is_stale_and_not_fixed() -> None:
    stale = parse_advisory(
        _github_fixture("HAND-BUILT-advisory-stale.json")["response"],
        "GHSA-2222-2222-2222",
    )
    url = "https://github.com/jqlang/jq/security/advisories/GHSA-2222-2222-2222"
    github = ScriptedGitHub(("jq-1.6.0",), ahead_by=3, behind_by=0, status="ahead", advisory=stale)
    status = _advisory_lookup(github, url=url, fix=FIX)
    assert status.state == "RELATED_VARIANTS_ONLY"
    assert status.state != "PUBLICLY_KNOWN_FIXED"
    item = status.evidence[0]
    assert item.relation == "RELATED_VARIANT"
    assert item.upstream_status == "UNKNOWN"
    assert item.stale_fields == ["patched_version:1.6.0"]
    assert item.version_sources == ["github_advisory_api:1.6.0"]
    assert item.checked_tag == "jq-1.6.0"
    assert "does not contain the recorded fix" in status.draft[0].text
    assert "patched_version:1.6.0" in status.draft[0].text
