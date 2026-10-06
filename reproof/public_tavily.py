"""Tavily search, extract, and a narrow crawl fallback for public status.

Searches are short and sequential so the credit ledger can stop between them.
Every call sets include_usage. Credits are read from usage.credits, the field
returned on 2026-10-05. A response without that field is charged the documented
estimate, recorded as usage missing, and blocks every later call. The usage
endpoint is not called. Map is not used. Crawl is only a project SECURITY.md
or release-notes page, never a GitHub advisory list.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from tavily import TavilyClient

from reproof.public_match import host_allowed, query_rejection, snippet_worth_extract

TAVILY_CREDIT_BUDGET = 200
MAX_SEARCHES = 2
MAX_RESULTS = 5
MAX_EXTRACT_URLS = 5
SEARCH_DEPTH = "advanced"
EXTRACT_CHUNKS = 3
SEARCH_TIMEOUT_S = 90
EXTRACT_TIMEOUT_S = 60
CRAWL_PAGE_LIMIT = 5
# Measured on the prior 10-task run: jq issue #3196 scored 0.466 and is a page
# this stage must be able to extract. Wrong-project miniz hits scored at most
# 0.174. 0.40 sits between those two observations.
SCORE_FLOOR = 0.40
ADVANCED_SEARCH_ESTIMATE = 2
# Sum of usage.credits on the five recorded SDK responses in tests/fixtures/tavily.
# An eval ledger starts at this used count so the whole task stays within budget.
RECORDED_CALL_CREDITS = 7
USAGE_CREDIT_KEY = "credits"
_SECRET_ENV_NAMES = ("TAVILY_API_KEY", "NEBIUS_API_KEY", "NEBIUS_PROJECT_ID")


class TavilyApiError(Exception):
    """The Tavily call failed, or the response had no request id."""

    def __init__(self, message: str, *, call: TavilyCall | None = None) -> None:
        super().__init__(message)
        self.call = call


class TavilyStopped(Exception):
    """No further Tavily call is allowed. This is not a public-status finding."""

    def __init__(self, message: str, *, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


class TavilyRejected(Exception):
    """The crawl URL is refused before any request. No credits are spent."""


@dataclass(frozen=True)
class TavilyCall:
    operation: str
    request_id: str
    credits: int
    latency_s: float
    query: str
    usage_missing: bool
    urls: tuple[str, ...]


@dataclass
class CreditLedger:
    """Shared credit count for fixtures, the live test, and the eval."""

    limit: int = TAVILY_CREDIT_BUDGET
    used: int = 0
    usage_missing: bool = False
    calls: list[TavilyCall] = field(default_factory=list)

    def ensure(self, estimate: int) -> None:
        if self.usage_missing:
            raise TavilyStopped("an earlier response had no usage.credits", kind="usage_missing")
        if estimate < 0:
            raise ValueError("estimate must be >= 0")
        if self.used + estimate > self.limit:
            remain = self.limit - self.used
            raise TavilyStopped(f"need {estimate} credits and {remain} remain", kind="budget")

    def record(self, call: TavilyCall) -> None:
        self.used += call.credits
        self.calls.append(call)
        if call.usage_missing:
            self.usage_missing = True


@dataclass(frozen=True)
class SearchHit:
    url: str
    title: str
    snippet: str
    score: float
    query: str


@dataclass(frozen=True)
class RejectedHit:
    url: str
    reason: str
    score: float


@dataclass(frozen=True)
class SearchOutcome:
    hits: tuple[SearchHit, ...]
    rejected: tuple[RejectedHit, ...]
    queries_sent: tuple[str, ...]
    queries_not_sent: tuple[tuple[str, str], ...]
    calls: tuple[TavilyCall, ...]
    stopped: str
    raws: tuple[dict[str, Any], ...] = ()
    # Responses whose result list went through filter_hits. Zero means no search result was read.
    responses_read: int = 0


@dataclass(frozen=True)
class ExtractedPage:
    url: str
    text: str
    title: str = ""


@dataclass(frozen=True)
class ExtractOutcome:
    pages: tuple[ExtractedPage, ...]
    failed_urls: tuple[str, ...]
    calls: tuple[TavilyCall, ...]
    stopped: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class CrawlOutcome:
    pages: tuple[ExtractedPage, ...]
    calls: tuple[TavilyCall, ...]
    stopped: str
    raw: dict[str, Any]


def scrub_secrets(text: str) -> str:
    """Remove live credential values from an error string."""

    redacted = text
    for name in _SECRET_ENV_NAMES:
        secret = os.environ.get(name) or ""
        if len(secret) >= 8:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def default_domains(project_site: str = "") -> tuple[str, ...]:
    """Search hosts from the brief, plus a project site the caller already knows."""

    domains = ["github.com", "nvd.nist.gov", "cve.org", "www.cve.org"]
    site = project_site.strip().lower()
    if "://" in site:
        site = (urlparse(site).hostname or "").lower()
    if site and site not in domains:
        domains.append(site)
    return tuple(domains)


def extract_estimate(url_count: int) -> int:
    """Basic extract: 1 credit per 5 URLs. Zero URLs cost nothing."""

    if url_count <= 0:
        return 0
    return (url_count + 4) // 5


def crawl_estimate(page_limit: int) -> int:
    """Mapping is 1 credit per 10 pages. Basic extract is 1 per 5.

    Documented at https://docs.tavily.com/documentation/api-credits. This
    number is used only when usage.credits is absent.
    """

    pages = max(page_limit, 1)
    return (pages + 9) // 10 + (pages + 4) // 5


def read_credits(response: Mapping[str, Any], *, estimate: int) -> tuple[int, bool]:
    """Return (credits, usage_missing). Only usage.credits is accepted."""

    usage = response.get("usage")
    if not isinstance(usage, dict) or USAGE_CREDIT_KEY not in usage:
        return estimate, True
    value = usage[USAGE_CREDIT_KEY]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return estimate, True
    if isinstance(value, float):
        if not value.is_integer():
            return estimate, True
        return int(value), False
    return value, False


def select_queries(
    queries: Sequence[str],
    *,
    project: str,
    frames: Sequence[str],
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Keep at most two queries that pass the project-or-frame guard."""

    accepted: list[str] = []
    rejected: list[tuple[str, str]] = []
    for query in queries:
        reason = query_rejection(query, project, frames)
        if reason:
            rejected.append((query, reason))
            continue
        if query in accepted:
            rejected.append((query, "duplicate"))
            continue
        if len(accepted) >= MAX_SEARCHES:
            rejected.append((query, "cap"))
            continue
        accepted.append(query)
    return tuple(accepted), tuple(rejected)


def _text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _score(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _is_github_source(url: str) -> bool:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != "github.com":
        return False
    parts = [part for part in parsed.path.split("/") if part]
    return len(parts) >= 3 and parts[2].lower() in {"blob", "raw"}


def filter_hits(
    results: Sequence[Mapping[str, Any]],
    *,
    query: str,
    project: str,
    frames: Sequence[str],
    crash_type: str,
    owner: str,
    repo: str,
    extra_hosts: Sequence[str] = (),
    score_floor: float = SCORE_FLOOR,
) -> tuple[tuple[SearchHit, ...], tuple[RejectedHit, ...]]:
    """Drop low scores, other repos, source files, and snippets with no frame."""

    kept: list[SearchHit] = []
    rejected: list[RejectedHit] = []
    for result in results:
        url = _text(result, "url")
        score = _score(result.get("score"))
        shown = score if score is not None else 0.0
        if not url or score is None or score < score_floor:
            rejected.append(RejectedHit(url, "score", shown))
            continue
        if _is_github_source(url):
            rejected.append(RejectedHit(url, "source_file", score))
            continue
        title = _text(result, "title")
        snippet = _text(result, "content")
        text = f"{title}\n{snippet}"
        decision = host_allowed(
            url,
            owner=owner,
            repo=repo,
            project=project,
            text=text,
            extra_hosts=extra_hosts,
        )
        if not decision.allowed:
            rejected.append(RejectedHit(url, f"host:{decision.reason}", score))
            continue
        if not snippet_worth_extract(text, frames, crash_type):
            rejected.append(RejectedHit(url, "snippet", score))
            continue
        kept.append(SearchHit(url, title, snippet, score, query))
    return tuple(kept), tuple(rejected)


def _dedupe(
    kept: Sequence[SearchHit],
    rejected: Sequence[RejectedHit],
) -> tuple[tuple[SearchHit, ...], tuple[RejectedHit, ...]]:
    best: dict[str, SearchHit] = {}
    for hit in kept:
        current = best.get(hit.url)
        if current is None or hit.score > current.score:
            best[hit.url] = hit
    kept_urls = set(best)
    remaining = tuple(item for item in rejected if item.url not in kept_urls)
    ordered = tuple(sorted(best.values(), key=lambda hit: hit.score, reverse=True))
    return ordered, remaining


def crawl_rejection(
    url: str,
    *,
    owner: str,
    repo: str,
    extra_hosts: Sequence[str] = (),
) -> str:
    """Empty string when crawl may run. Advisory lists are always refused."""

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        return "unusable_url"
    lowered = parsed.path.lower()
    if "/security/advisories" in lowered:
        return "advisory_list"
    parts = [part for part in parsed.path.split("/") if part]
    project_repo = (
        host == "github.com"
        and len(parts) >= 2
        and owner
        and repo
        and parts[0].casefold() == owner.casefold()
        and parts[1].casefold() == repo.casefold()
    )
    project_site = host in {item.lower() for item in extra_hosts}
    if not project_repo and not project_site:
        return "not_project_page"
    last = parts[-1].lower() if parts else ""
    if last in {"security.md", "changelog", "changelog.md"}:
        return ""
    if "/releases" in lowered or "/release-notes" in lowered:
        return ""
    return "not_release_or_security"


def tavily_client() -> TavilyClient:
    key = os.environ.get("TAVILY_API_KEY") or ""
    if len(key) < 8:
        raise TavilyApiError("TAVILY_API_KEY is not set")
    return TavilyClient(api_key=key)


def _client(client: Any | None) -> Any:
    return tavily_client() if client is None else client


def _account(
    ledger: CreditLedger,
    *,
    operation: str,
    raw: object,
    estimate: int,
    query: str,
    urls: tuple[str, ...],
    started: float,
) -> TavilyCall:
    if not isinstance(raw, dict):
        raise TavilyApiError(scrub_secrets("Tavily response was not an object"))
    credits, missing = read_credits(raw, estimate=estimate)
    request_id = raw.get("request_id")
    request_text = request_id if isinstance(request_id, str) else ""
    call = TavilyCall(
        operation=operation,
        request_id=request_text,
        credits=credits,
        latency_s=round(time.perf_counter() - started, 3),
        query=query,
        usage_missing=missing,
        urls=urls,
    )
    ledger.record(call)
    if missing:
        raise TavilyStopped("usage.credits missing", kind="usage_missing")
    # A response billed past the budget is still used: it was paid for. The next
    # ensure() refuses, so no further call is sent.
    if not request_text:
        raise TavilyApiError("Tavily response had no request_id", call=call)
    return call


def _call(client: Any, operation: str, **kwargs: Any) -> Any:
    method = getattr(client, operation)
    try:
        return method(**kwargs)
    except TavilyStopped:
        raise
    except TavilyApiError:
        raise
    except Exception as exc:
        raise TavilyApiError(scrub_secrets(f"{operation} failed: {exc}")) from None


def _empty_search(
    not_sent: tuple[tuple[str, str], ...],
    *,
    stopped: str = "",
    calls: tuple[TavilyCall, ...] = (),
) -> SearchOutcome:
    return SearchOutcome((), (), (), not_sent, calls, stopped)


def perform_search(
    *,
    queries: Sequence[str],
    project: str,
    frames: Sequence[str],
    crash_type: str,
    owner: str,
    repo: str,
    include_domains: Sequence[str],
    extra_hosts: Sequence[str] = (),
    client: Any | None = None,
    ledger: CreditLedger | None = None,
    score_floor: float = SCORE_FLOOR,
) -> SearchOutcome:
    """Run at most two advanced searches and return hits worth extracting."""

    if not include_domains:
        raise TavilyApiError("include_domains is empty")
    book = ledger if ledger is not None else CreditLedger()
    accepted, not_sent = select_queries(queries, project=project, frames=frames)
    if not accepted:
        return _empty_search(not_sent)
    api = _client(client)
    kept: list[SearchHit] = []
    rejected: list[RejectedHit] = []
    calls: list[TavilyCall] = []
    sent: list[str] = []
    raws: list[dict[str, Any]] = []
    read = 0

    def _stop(
        kind: str, pending: Sequence[str], extra_calls: Sequence[TavilyCall] = ()
    ) -> SearchOutcome:
        skipped = tuple((item, kind) for item in pending)
        return SearchOutcome(
            *_dedupe(kept, rejected),
            tuple(sent),
            (*not_sent, *skipped),
            (*calls, *extra_calls),
            kind,
            tuple(raws),
            read,
        )

    for index, query in enumerate(accepted):
        pending = accepted[index:]
        try:
            book.ensure(ADVANCED_SEARCH_ESTIMATE)
        except TavilyStopped as exc:
            return _stop(exc.kind, pending)
        started = time.perf_counter()
        try:
            raw = _call(
                api,
                "search",
                query=query,
                search_depth=SEARCH_DEPTH,
                max_results=MAX_RESULTS,
                include_domains=list(include_domains),
                include_usage=True,
                auto_parameters=False,
                timeout=SEARCH_TIMEOUT_S,
            )
        except TavilyApiError as exc:
            if not sent:
                raise
            # A later search failed. Keep what the earlier responses already gave.
            return _stop(f"error: {exc}", pending)
        try:
            call = _account(
                book,
                operation="search",
                raw=raw,
                estimate=ADVANCED_SEARCH_ESTIMATE,
                query=query,
                urls=(),
                started=started,
            )
        except TavilyStopped as exc:
            sent.append(query)
            if isinstance(raw, dict):
                raws.append(raw)
            return _stop(exc.kind, accepted[index + 1 :], (book.calls[-1],))
        except TavilyApiError as exc:
            if not sent:
                raise
            if exc.call is None:
                # Not an object: nothing was recorded, so this query is not listed as sent.
                return _stop(f"error: {exc}", pending)
            sent.append(query)
            return _stop(f"error: {exc}", accepted[index + 1 :], (exc.call,))
        sent.append(query)
        calls.append(call)
        if isinstance(raw, dict):
            raws.append(raw)
        results = raw.get("results") if isinstance(raw, dict) else None
        if not isinstance(results, list):
            continue
        page_kept, page_rejected = filter_hits(
            results,
            query=query,
            project=project,
            frames=frames,
            crash_type=crash_type,
            owner=owner,
            repo=repo,
            extra_hosts=extra_hosts,
            score_floor=score_floor,
        )
        read += 1
        kept.extend(page_kept)
        rejected.extend(page_rejected)
    hits, rejected_hits = _dedupe(kept, rejected)
    return SearchOutcome(
        hits, rejected_hits, tuple(sent), not_sent, tuple(calls), "", tuple(raws), read
    )


def page_text(result: Mapping[str, Any]) -> str:
    """Text Tavily extracted. Chunks are joined. Missing text stays empty."""

    raw = result.get("raw_content")
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        return "\n".join(item for item in raw if isinstance(item, str))
    content = result.get("content")
    return content if isinstance(content, str) else ""


def _failed_urls(raw: Mapping[str, Any]) -> tuple[str, ...]:
    failed = raw.get("failed_results")
    if not isinstance(failed, list):
        return ()
    urls: list[str] = []
    for item in failed:
        if isinstance(item, str):
            urls.append(item)
        elif isinstance(item, dict):
            failed_url = _text(item, "url")
            if failed_url:
                urls.append(failed_url)
    return tuple(urls)


def _pages(raw: Mapping[str, Any]) -> tuple[ExtractedPage, ...]:
    results = raw.get("results")
    if not isinstance(results, list):
        return ()
    pages: list[ExtractedPage] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        pages.append(ExtractedPage(_text(item, "url"), page_text(item), _text(item, "title")))
    return tuple(pages)


def extract_query(frames: Sequence[str]) -> str:
    parts = [frame.strip() for frame in frames if frame.strip()]
    return " ".join(parts)[:399]


def perform_extract(
    *,
    urls: Sequence[str],
    frames: Sequence[str],
    client: Any | None = None,
    ledger: CreditLedger | None = None,
) -> ExtractOutcome:
    """One basic extract. No call when every search hit was filtered out."""

    book = ledger if ledger is not None else CreditLedger()
    unique: list[str] = []
    for url in urls:
        if url and url not in unique:
            unique.append(url)
    chosen = tuple(unique[:MAX_EXTRACT_URLS])
    if not chosen:
        return ExtractOutcome((), (), (), "", {})
    query = extract_query(frames)
    if not query:
        raise TavilyApiError("extract query has no crash frames")
    try:
        book.ensure(extract_estimate(len(chosen)))
    except TavilyStopped as exc:
        return ExtractOutcome((), (), (), exc.kind, {})
    api = _client(client)
    started = time.perf_counter()
    raw = _call(
        api,
        "extract",
        urls=list(chosen),
        query=query,
        chunks_per_source=EXTRACT_CHUNKS,
        include_usage=True,
        timeout=EXTRACT_TIMEOUT_S,
    )
    try:
        call = _account(
            book,
            operation="extract",
            raw=raw,
            estimate=extract_estimate(len(chosen)),
            query=query,
            urls=chosen,
            started=started,
        )
    except TavilyStopped as exc:
        return ExtractOutcome(
            (), (), (book.calls[-1],), exc.kind, raw if isinstance(raw, dict) else {}
        )
    if not isinstance(raw, dict):
        raise TavilyApiError("Tavily extract response was not an object", call=call)
    return ExtractOutcome(_pages(raw), _failed_urls(raw), (call,), "", raw)


def perform_crawl(
    *,
    url: str,
    owner: str,
    repo: str,
    extra_hosts: Sequence[str] = (),
    client: Any | None = None,
    ledger: CreditLedger | None = None,
) -> CrawlOutcome:
    """Crawl one project SECURITY.md or release page. Advisory lists are refused."""

    reason = crawl_rejection(url, owner=owner, repo=repo, extra_hosts=extra_hosts)
    if reason:
        raise TavilyRejected(reason)
    book = ledger if ledger is not None else CreditLedger()
    estimate = crawl_estimate(CRAWL_PAGE_LIMIT)
    try:
        book.ensure(estimate)
    except TavilyStopped as exc:
        return CrawlOutcome((), (), exc.kind, {})
    api = _client(client)
    started = time.perf_counter()
    raw = _call(
        api,
        "crawl",
        url=url,
        limit=CRAWL_PAGE_LIMIT,
        max_depth=1,
        extract_depth="basic",
        include_usage=True,
        timeout=120,
    )
    try:
        call = _account(
            book,
            operation="crawl",
            raw=raw,
            estimate=estimate,
            query=url,
            urls=(url,),
            started=started,
        )
    except TavilyStopped as exc:
        return CrawlOutcome((), (book.calls[-1],), exc.kind, raw if isinstance(raw, dict) else {})
    if not isinstance(raw, dict):
        raise TavilyApiError("Tavily crawl response was not an object", call=call)
    return CrawlOutcome(_pages(raw), (call,), "", raw)
