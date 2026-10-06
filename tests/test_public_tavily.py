"""Tavily search and extract ledger. Network stays behind the live marker.

RECORDED responses, once captured, live in tests/fixtures/tavily and are the
SDK payloads from this task's own calls. The tests in this file use a fake
client unless the test is marked live.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reproof.public_match import match_frames, quote_is_exact
from reproof.public_tavily import (
    ADVANCED_SEARCH_ESTIMATE,
    MAX_RESULTS,
    RECORDED_CALL_CREDITS,
    SCORE_FLOOR,
    SEARCH_DEPTH,
    TAVILY_CREDIT_BUDGET,
    CreditLedger,
    TavilyApiError,
    TavilyRejected,
    crawl_estimate,
    crawl_rejection,
    default_domains,
    extract_estimate,
    filter_hits,
    perform_crawl,
    perform_extract,
    perform_search,
    read_credits,
    select_queries,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tavily"
FRAMES = ("decNaNs", "decNumberCopy", "decCompareOp")
WASM_FRAMES = ("ForEachModule", "Runtime_Release", "m3_FreeRuntime")


def _search_body(
    results: list[dict[str, Any]],
    *,
    request_id: str = "req-search",
    credits: int | None = 2,
) -> dict[str, Any]:
    body: dict[str, Any] = {"request_id": request_id, "results": results}
    if credits is not None:
        body["usage"] = {"credits": credits}
    return body


def _hit(
    url: str,
    *,
    score: float = 0.8,
    content: str = "Stack-buffer-overflow in decNaNs",
    title: str = "jq advisory",
) -> dict[str, Any]:
    return {"url": url, "score": score, "content": content, "title": title}


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


def _search(**kwargs: Any) -> Any:
    defaults: dict[str, Any] = {
        "queries": ("jq Stack-buffer-overflow decNaNs", "jq decNaNs decNumberCopy"),
        "project": "jq",
        "frames": FRAMES,
        "crash_type": "Stack-buffer-overflow WRITE 2",
        "owner": "jqlang",
        "repo": "jq",
        "include_domains": default_domains(),
    }
    defaults.update(kwargs)
    return perform_search(**defaults)


def test_search_sends_advanced_depth_usage_and_records_credits() -> None:
    issue = "https://github.com/jqlang/jq/issues/3196"
    client = FakeTavily(
        [
            _search_body([_hit(issue, score=0.466)], request_id="req-a", credits=2),
            _search_body([], request_id="req-b", credits=2),
        ]
    )
    ledger = CreditLedger()
    outcome = _search(client=client, ledger=ledger)
    assert ledger.used == 4
    assert [call.request_id for call in outcome.calls] == ["req-a", "req-b"]
    assert outcome.stopped == ""
    assert outcome.hits[0].url == issue
    assert len(client.search_calls) == 2
    sent = client.search_calls[0]
    assert sent["search_depth"] == SEARCH_DEPTH
    assert sent["include_usage"] is True
    assert sent["auto_parameters"] is False
    assert sent["max_results"] == MAX_RESULTS
    assert "openwall.com" not in sent["include_domains"]
    assert "github.com" in sent["include_domains"]


def test_rejected_and_capped_queries_are_not_sent() -> None:
    long_query = "jq " + ("decNaNs " * 80)
    client = FakeTavily(
        [
            _search_body([], request_id="req-one"),
            _search_body([], request_id="req-two"),
        ]
    )
    outcome = _search(
        client=client,
        queries=(
            "no project and no frame here",
            long_query,
            "jq Stack-buffer-overflow decNaNs",
            "jq decNaNs decNumberCopy",
            "jq decCompareOp stack overflow",
        ),
    )
    assert len(client.search_calls) == 2
    reasons = dict(outcome.queries_not_sent)
    assert reasons["no project and no frame here"] == "missing_project_and_frame"
    assert reasons[long_query] == "too_long"
    assert reasons["jq decCompareOp stack overflow"] == "cap"


def test_missing_usage_charges_the_estimate_and_blocks_the_next_call() -> None:
    client = FakeTavily(
        [
            _search_body([_hit("https://github.com/jqlang/jq/issues/1")], credits=None),
            _search_body([], request_id="not-sent"),
        ]
    )
    ledger = CreditLedger()
    outcome = _search(client=client, ledger=ledger)
    assert outcome.stopped == "usage_missing"
    assert ledger.usage_missing is True
    assert ledger.used == ADVANCED_SEARCH_ESTIMATE
    assert len(client.search_calls) == 1
    second = _search(client=client, ledger=ledger, queries=("jq decNaNs",))
    assert second.stopped == "usage_missing"
    assert len(client.search_calls) == 1


def test_score_host_source_and_snippet_filters() -> None:
    kept, rejected = filter_hits(
        [
            _hit("https://github.com/other/miniz/issues/1", score=0.174, content="miniz"),
            _hit(
                "https://github.com/jqlang/jq/issues/3196",
                score=0.466,
                content="Stack-buffer-overflow in decNaNs",
            ),
            _hit(
                "https://gist.github.com/someone/abc",
                score=0.85,
                content="ForEachModule heap-use-after-free",
            ),
            _hit(
                "https://github.com/jqlang/jq/blob/main/src/decNumber.c",
                score=0.7,
                content="decNaNs decNumberCopy",
            ),
            _hit(
                "https://github.com/jqlang/jq/issues/1",
                score=0.9,
                content="unrelated release note",
            ),
            _hit(
                "https://github.com/google/oss-fuzz/issues/13193",
                score=0.65,
                content="jq decNaNs Stack-buffer-overflow",
            ),
        ],
        query="jq decNaNs",
        project="jq",
        frames=FRAMES,
        crash_type="Stack-buffer-overflow",
        owner="jqlang",
        repo="jq",
    )
    assert [hit.url for hit in kept] == ["https://github.com/jqlang/jq/issues/3196"]
    reasons = {item.url: item.reason for item in rejected}
    assert reasons["https://github.com/other/miniz/issues/1"] == "score"
    assert reasons["https://gist.github.com/someone/abc"].startswith("host:")
    assert reasons["https://github.com/jqlang/jq/blob/main/src/decNumber.c"] == "source_file"
    assert reasons["https://github.com/jqlang/jq/issues/1"] == "snippet"
    assert reasons["https://github.com/google/oss-fuzz/issues/13193"].startswith("host:")
    assert SCORE_FLOOR == 0.40


def test_extract_is_one_call_and_is_skipped_when_nothing_matches() -> None:
    issue = "https://github.com/jqlang/jq/security/advisories/GHSA-7hmr-442f-qc8j"
    search = FakeTavily(
        [
            _search_body(
                [_hit(issue, content="Stack-buffer-overflow in decNaNs")],
                request_id="req-search",
            )
        ]
    )
    page = {
        "url": issue,
        "raw_content": "Stack-buffer-overflow in decNaNs\nPatched versions: 1.7.1\n",
    }
    extract = {
        "request_id": "req-extract",
        "results": [page],
        "failed_results": ["https://github.com/jqlang/jq/issues/missing"],
        "usage": {"credits": 1},
    }
    search.extracts.append(extract)
    ledger = CreditLedger()
    found = _search(client=search, ledger=ledger, queries=("jq Stack-buffer-overflow decNaNs",))
    extracted = perform_extract(
        urls=[hit.url for hit in found.hits], frames=FRAMES, client=search, ledger=ledger
    )
    assert ledger.used == 3
    assert len(search.extract_calls) == 1
    sent = search.extract_calls[0]
    assert sent["urls"] == [issue]
    assert sent["chunks_per_source"] == 3
    assert sent["include_usage"] is True
    assert "extract_depth" not in sent
    assert "decNaNs" in sent["query"]
    assert extracted.pages[0].text.startswith("Stack-buffer-overflow")
    assert extracted.failed_urls == ("https://github.com/jqlang/jq/issues/missing",)
    gate = match_frames(extracted.pages[0].text, FRAMES, "Stack-buffer-overflow")
    assert gate.passes
    assert quote_is_exact("Patched versions: 1.7.1", extracted.pages[0].text)
    assert not quote_is_exact("Patched versions: 1.7.1 today", extracted.pages[0].text)

    quiet = FakeTavily([_search_body([_hit(issue, score=0.1)])])
    skipped = _search(client=quiet, queries=("jq decNaNs",))
    assert skipped.hits == ()
    perform_extract(urls=[], frames=FRAMES, client=quiet, ledger=CreditLedger())
    assert quiet.extract_calls == []


def test_a_response_billed_past_the_budget_is_kept_and_stops_the_next_call() -> None:
    issue = "https://github.com/jqlang/jq/security/advisories/GHSA-7hmr-442f-qc8j"
    page = {"url": issue, "raw_content": "Stack-buffer-overflow in decNaNs\n"}
    client = FakeTavily(
        extracts=[
            {"request_id": "req-extract", "results": [page], "usage": {"credits": 2}},
            AssertionError("second extract"),
        ]
    )
    ledger = CreditLedger(limit=5, used=4)
    extracted = perform_extract(urls=[issue], frames=FRAMES, client=client, ledger=ledger)
    assert ledger.used == 6
    assert extracted.stopped == ""
    assert [page_item.url for page_item in extracted.pages] == [issue]
    after = perform_extract(urls=[issue], frames=FRAMES, client=client, ledger=ledger)
    assert after.stopped == "budget"
    assert len(client.extract_calls) == 1


def test_api_error_is_not_charged_and_the_key_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-secret-value")
    client = FakeTavily([RuntimeError("unauthorized tvly-test-secret-value")])
    ledger = CreditLedger()
    with pytest.raises(TavilyApiError) as caught:
        _search(client=client, ledger=ledger)
    assert ledger.used == 0
    assert ledger.calls == []
    assert "tvly-test-secret-value" not in str(caught.value)
    assert "[redacted]" in str(caught.value)


def test_budget_stops_before_the_second_search() -> None:
    client = FakeTavily(
        [
            _search_body([], request_id="req-only", credits=2),
            _search_body([], request_id="req-never"),
        ]
    )
    ledger = CreditLedger(limit=2)
    outcome = _search(client=client, ledger=ledger)
    assert len(client.search_calls) == 1
    assert outcome.stopped == "budget"
    assert outcome.queries_sent == ("jq Stack-buffer-overflow decNaNs",)
    assert outcome.queries_not_sent[-1][1] == "budget"


def test_missing_request_id_raises_after_the_credit_is_recorded() -> None:
    body = _search_body([], credits=2)
    del body["request_id"]
    client = FakeTavily([body])
    ledger = CreditLedger()
    with pytest.raises(TavilyApiError) as caught:
        _search(client=client, ledger=ledger, queries=("jq decNaNs",))
    assert ledger.used == 2
    assert caught.value.call is not None
    assert caught.value.call.request_id == ""


def test_wrong_usage_key_is_missing() -> None:
    credits, missing = read_credits({"usage": {"credit_cost": 2}}, estimate=2)
    assert missing is True
    assert credits == 2
    credits, missing = read_credits({"usage": {"credits": 2}}, estimate=9)
    assert missing is False
    assert credits == 2
    credits, missing = read_credits({"usage": {"credits": True}}, estimate=2)
    assert missing is True


def test_crawl_refuses_advisory_lists_and_calls_security_md() -> None:
    advisory = "https://github.com/jqlang/jq/security/advisories"
    assert crawl_rejection(advisory, owner="jqlang", repo="jq") == "advisory_list"
    security = "https://github.com/jqlang/jq/blob/main/SECURITY.md"
    assert crawl_rejection(security, owner="jqlang", repo="jq") == ""
    releases = "https://github.com/jqlang/jq/releases"
    assert crawl_rejection(releases, owner="jqlang", repo="jq") == ""
    other = "https://github.com/other/jq/releases"
    assert crawl_rejection(other, owner="jqlang", repo="jq") == "not_project_page"
    client = FakeTavily(
        crawls=[{"request_id": "req-crawl", "results": [], "usage": {"credits": 2}}]
    )
    with pytest.raises(TavilyRejected):
        perform_crawl(url=advisory, owner="jqlang", repo="jq", client=client)
    assert client.crawl_calls == []
    outcome = perform_crawl(url=security, owner="jqlang", repo="jq", client=client)
    assert outcome.calls[0].credits == 2
    assert client.crawl_calls[0]["include_usage"] is True
    assert client.crawl_calls[0]["limit"] == 5
    assert "instructions" not in client.crawl_calls[0]
    assert crawl_estimate(5) == 2
    assert extract_estimate(5) == 1
    assert extract_estimate(0) == 0


def test_duplicate_url_keeps_the_higher_score() -> None:
    url = "https://github.com/jqlang/jq/issues/3196"
    client = FakeTavily(
        [
            _search_body([_hit(url, score=0.5)], request_id="req-low"),
            _search_body(
                [
                    _hit(
                        url, score=0.9, content="Stack-buffer-overflow in decNaNs and decNumberCopy"
                    )
                ],
                request_id="req-high",
            ),
        ]
    )
    outcome = _search(client=client)
    assert len(outcome.hits) == 1
    assert outcome.hits[0].score == 0.9
    assert all(item.url != url for item in outcome.rejected)


def test_select_queries_and_domains() -> None:
    accepted, rejected = select_queries(
        ("jq decNaNs", "jq decNaNs", "   "),
        project="jq",
        frames=FRAMES,
    )
    assert accepted == ("jq decNaNs",)
    assert rejected[0][1] == "duplicate"
    assert rejected[1][1] == "empty"
    domains = default_domains("https://jqlang.github.io/jq/")
    assert "jqlang.github.io" in domains
    assert default_domains("") == ("github.com", "nvd.nist.gov", "cve.org", "www.cve.org")


def test_missing_key_raises_before_a_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    with pytest.raises(TavilyApiError, match="TAVILY_API_KEY"):
        perform_search(
            queries=("jq decNaNs",),
            project="jq",
            frames=FRAMES,
            crash_type="Stack-buffer-overflow",
            owner="jqlang",
            repo="jq",
            include_domains=default_domains(),
            client=None,
        )


def _recorded(name: str) -> dict[str, Any]:
    saved = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    assert saved["label"] == "RECORDED"
    assert saved["sdk"] == "tavily-python==0.8.4"
    response = saved["response"]
    assert isinstance(response, dict)
    return saved


def test_recorded_wasm3_search_keeps_issue_458() -> None:
    saved = _recorded("RECORDED-wasm3-42496387-search.json")
    response = saved["response"]
    credits, missing = read_credits(response, estimate=99)
    assert missing is False
    assert credits == 2
    assert response["request_id"] == "c09696fc-a536-40ed-b3ee-f00e7c3d90ba"
    kept, rejected = filter_hits(
        response["results"],
        query=saved["query"],
        project="wasm3",
        frames=WASM_FRAMES,
        crash_type="Heap-use-after-free READ 8",
        owner="wasm3",
        repo="wasm3",
    )
    assert [hit.url for hit in kept] == ["https://github.com/wasm3/wasm3/issues/458"]
    reasons = {item.url: item.reason for item in rejected}
    assert any(reason == "source_file" for reason in reasons.values())
    assert any(reason.startswith("host:") for reason in reasons.values())


def test_recorded_extracts_keep_the_frame_gate() -> None:
    wasm = _recorded("RECORDED-wasm3-42496387-extract.json")
    wasm_credits, wasm_missing = read_credits(wasm["response"], estimate=99)
    assert wasm_missing is False
    assert wasm_credits == 0
    wasm_text = wasm["response"]["results"][0]["raw_content"]
    wasm_gate = match_frames(wasm_text, WASM_FRAMES, "Heap-use-after-free")
    assert wasm_gate.passes
    assert wasm_gate.frames_matched == WASM_FRAMES
    assert quote_is_exact("in ForEachModule", wasm_text)
    assert not quote_is_exact("in ForEachModule was fixed upstream", wasm_text)

    jq = _recorded("RECORDED-jq-42531223-extract.json")
    pages = {page["url"]: page["raw_content"] for page in jq["response"]["results"]}
    advisory = pages["https://github.com/jqlang/jq/security/advisories/GHSA-7hmr-442f-qc8j"]
    gate = match_frames(advisory, FRAMES, "Stack-buffer-overflow")
    assert gate.passes
    assert gate.reason == "top_frame_and_crash_type"
    assert gate.frames_matched == ("decNaNs",)
    assert quote_is_exact("Upgrade to 1.7.1", advisory)
    assert quote_is_exact("Stack-buffer-overflow in decNaNs", advisory)
    assert not quote_is_exact("Upgrade to 1.7.1 fixes every later decNaNs crash", advisory)

    later = pages["https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22"]
    later_gate = match_frames(later, FRAMES, "Stack-buffer-overflow")
    assert later_gate.passes
    assert later_gate.frames_matched == FRAMES
    # The extract chunks name one frame, so these pages are not evidence.
    for url in (
        "https://github.com/jqlang/jq/issues/3246",
        "https://github.com/jqlang/jq/issues/3196",
    ):
        assert not match_frames(pages[url], FRAMES, "Stack-buffer-overflow").passes


def test_recorded_credit_total_is_the_ledger_start() -> None:
    total = 0
    paths = sorted(FIXTURE_DIR.glob("RECORDED-*.json"))
    assert len(paths) == 5
    for path in paths:
        saved = json.loads(path.read_text(encoding="utf-8"))
        credits, missing = read_credits(saved["response"], estimate=99)
        assert missing is False
        total += credits
    assert total == 7
    assert total == RECORDED_CALL_CREDITS


@pytest.mark.live
def test_live_tavily_search_one_advanced_call() -> None:
    ledger = CreditLedger(limit=TAVILY_CREDIT_BUDGET, used=0)
    outcome = perform_search(
        queries=("wasm3 Heap-use-after-free Runtime_Release",),
        project="wasm3",
        frames=WASM_FRAMES,
        crash_type="Heap-use-after-free",
        owner="wasm3",
        repo="wasm3",
        include_domains=default_domains(),
        ledger=ledger,
    )
    assert outcome.stopped == ""
    assert len(outcome.calls) == 1
    assert outcome.calls[0].credits == ADVANCED_SEARCH_ESTIMATE
    assert outcome.calls[0].request_id
    assert ledger.used == ADVANCED_SEARCH_ESTIMATE
