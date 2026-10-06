"""Public-status stage: is this measured crash already public, and is it fixed?

Tavily searches, then one extract. A page reaches the card only after the host
rule and the frame gate. Nemotron classifies those pages. Git ancestry checks
a stated version or the recorded fix commit before anything is called fixed.
A field git contradicts is marked stale and is not repeated as the fix.

Crawl of a project's SECURITY.md or releases is off unless the caller asks.
GitHub advisory list pages are never crawled. This module does not call a
crash novel.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

from reproof.models import (
    ModelCall,
    PublicDraftLine,
    PublicEvidence,
    PublicStatus,
    PublicTavilyCall,
    TriageCard,
)
from reproof.public_match import (
    CONTAINS_FIX,
    DOES_NOT_CONTAIN_FIX,
    FRAME_MIN_LENGTH,
    LOOKUP_UNAVAILABLE,
    NO_FIX_COMMIT,
    NO_PUBLIC_FINDINGS,
    NOT_CHECKABLE,
    DraftRejected,
    EvidenceView,
    ExtractedIds,
    apply_ancestry,
    build_draft_line,
    decide_state,
    extract_ids,
    fallback_queries,
    host_allowed,
    interpret_compare,
    match_frames,
    named_fix_commit,
    none_field_is_stale,
    resolve_tag,
    sources_note,
)
from reproof.public_model import (
    GuardedPage,
    ModelBudget,
    PublicModelError,
    QueryPlan,
    classify_page,
    plan_queries,
)
from reproof.public_tavily import (
    CreditLedger,
    ExtractedPage,
    ExtractOutcome,
    SearchOutcome,
    TavilyApiError,
    TavilyCall,
    TavilyRejected,
    default_domains,
    perform_crawl,
    perform_extract,
    perform_search,
    scrub_secrets,
)

_REPO_PART = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_REF_PART = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_COMMIT_PART = re.compile(r"^[0-9a-f]{40}$")
_QUOTE_REJECTIONS = frozenset(
    {
        "quote_not_in_page",
        "dispute_quote_not_in_page",
        "version_not_in_page",
        "commit_not_in_page",
        "dispute_quotes_without_dispute",
    }
)
_GITHUB_API = "https://api.github.com"


class GitHubError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CompareResult:
    status: str
    ahead_by: int
    behind_by: int
    error: str = ""


class GitHubTransport(Protocol):
    def list_tags(self, owner: str, repo: str) -> tuple[str, ...]: ...

    def compare(self, owner: str, repo: str, base: str, head: str) -> CompareResult: ...


@dataclass(frozen=True)
class _Ancestry:
    ancestry: str
    version: str
    tag: str
    commit: str
    stale: tuple[str, ...]


def _repo_ok(owner: str, repo: str) -> bool:
    return bool(_REPO_PART.fullmatch(owner) and _REPO_PART.fullmatch(repo))


def _site_hosts(project_site: str) -> tuple[str, ...]:
    site = project_site.strip().lower()
    if not site:
        return ()
    if "://" in site:
        site = (urlparse(site).hostname or "").lower()
    if not site:
        return ()
    return (site,)


def _clean(text: str) -> str:
    return scrub_secrets(text).replace("\n", " ")[:300]


def _usable(frames: list[str] | tuple[str, ...]) -> list[str]:
    seen: list[str] = []
    for frame in frames:
        cleaned = frame.strip()
        if len(cleaned) < FRAME_MIN_LENGTH or cleaned in seen:
            continue
        seen.append(cleaned)
    return seen


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _github_get(url: str) -> object:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "reproof",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise GitHubError(f"http_{exc.code}") from None
    except urllib.error.URLError:
        raise GitHubError("transport") from None
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        raise GitHubError("not_json") from None


class UrllibGitHub:
    """GitHub compare and tag list. Tests inject their own transport."""

    def list_tags(self, owner: str, repo: str) -> tuple[str, ...]:
        if not _repo_ok(owner, repo):
            raise GitHubError("unsafe_repo")
        names: list[str] = []
        for page in range(1, 11):
            url = f"{_GITHUB_API}/repos/{owner}/{repo}/tags?per_page=100&page={page}"
            payload = _github_get(url)
            if not isinstance(payload, list) or not payload:
                break
            for item in payload:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    names.append(item["name"])
            if len(payload) < 100:
                break
        return tuple(dict.fromkeys(names))

    def compare(self, owner: str, repo: str, base: str, head: str) -> CompareResult:
        if not _repo_ok(owner, repo):
            return CompareResult("", 0, 0, "unsafe_repo")
        if not _REF_PART.fullmatch(base):
            return CompareResult("", 0, 0, "unsafe_base")
        if not _COMMIT_PART.fullmatch(head):
            return CompareResult("", 0, 0, "unsafe_head")
        url = f"{_GITHUB_API}/repos/{owner}/{repo}/compare/{base}...{head}"
        try:
            payload = _github_get(url)
        except GitHubError as exc:
            return CompareResult("", 0, 0, exc.reason)
        if not isinstance(payload, dict):
            return CompareResult("", 0, 0, "compare_shape")
        status = payload.get("status")
        ahead = _count(payload.get("ahead_by"))
        behind = _count(payload.get("behind_by"))
        if not isinstance(status, str) or ahead is None or behind is None:
            return CompareResult("", 0, 0, "compare_shape")
        return CompareResult(status, ahead, behind, "")


def _fix_commits(commits: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    found: list[str] = []
    for commit in commits:
        cleaned = commit.strip().lower()
        if _COMMIT_PART.fullmatch(cleaned) and cleaned not in found:
            found.append(cleaned)
    return tuple(found)


def _stated_versions(ids: ExtractedIds, model_version: str) -> list[str]:
    versions = list(ids.patched_versions)
    cleaned = model_version.strip()
    if cleaned and cleaned not in versions:
        versions.append(cleaned)
    return versions


def _compare_tag(
    transport: GitHubTransport,
    owner: str,
    repo: str,
    tag: str,
    commits: tuple[str, ...],
    failed: list[str],
) -> tuple[str, str]:
    """Return ancestry and the commit that decided it."""

    outcomes: list[tuple[str, str]] = []
    for commit in commits:
        result = transport.compare(owner, repo, tag, commit)
        if result.error:
            failed.append(f"git compare {tag}: {result.error}")
            return NOT_CHECKABLE, commit
        reading = interpret_compare(result.status, result.ahead_by, result.behind_by)
        outcomes.append((reading, commit))
    if not outcomes:
        return NO_FIX_COMMIT, ""
    for ancestry, commit in outcomes:
        if ancestry == DOES_NOT_CONTAIN_FIX:
            return DOES_NOT_CONTAIN_FIX, commit
    if all(ancestry == CONTAINS_FIX for ancestry, _commit in outcomes):
        return CONTAINS_FIX, outcomes[0][1]
    return NOT_CHECKABLE, outcomes[0][1]


def assess_ancestry(
    text: str,
    ids: ExtractedIds,
    guarded: GuardedPage,
    fix_commits: tuple[str, ...],
    *,
    owner: str,
    repo: str,
    transport: GitHubTransport | None,
    failed: list[str],
) -> _Ancestry:
    """A version git rejects wins over a side commit. An unchecked fix is not FIXED."""

    versions = _stated_versions(ids, guarded.upstream_version)
    named = named_fix_commit(text, fix_commits)
    if not versions and named:
        return _Ancestry(CONTAINS_FIX, "", "", named, ())
    if not _repo_ok(owner, repo) or transport is None or not versions:
        ancestry = NOT_CHECKABLE if fix_commits or versions else NO_FIX_COMMIT
        version = versions[0] if versions else ""
        return _Ancestry(ancestry, version, "", "", ())

    try:
        tags = transport.list_tags(owner, repo)
    except Exception as exc:
        failed.append(_clean(f"git tags failed: {type(exc).__name__}"))
        return _Ancestry(NOT_CHECKABLE, versions[0], "", "", ())

    decided = NOT_CHECKABLE
    version_out = versions[0]
    tag_out = ""
    commit_out = ""
    stale: list[str] = []
    saw_contains = False
    for version in versions:
        tag, reason = resolve_tag(version, tags)
        if not tag:
            failed.append(f"git tag {version}: {reason}")
            continue
        ancestry, commit = _compare_tag(transport, owner, repo, tag, fix_commits, failed)
        if ancestry == DOES_NOT_CONTAIN_FIX:
            field = f"patched_version:{version}"
            if field not in stale:
                stale.append(field)
            if decided != DOES_NOT_CONTAIN_FIX:
                decided = DOES_NOT_CONTAIN_FIX
                version_out = version
                tag_out = tag
                commit_out = commit
            continue
        if ancestry == CONTAINS_FIX and not saw_contains and decided != DOES_NOT_CONTAIN_FIX:
            saw_contains = True
            decided = CONTAINS_FIX
            version_out = version
            tag_out = tag
            commit_out = commit
    if decided == NOT_CHECKABLE and not saw_contains:
        version_out = versions[0]
    return _Ancestry(decided, version_out, tag_out, commit_out, tuple(stale))


def _withhold(
    lines: list[str] | tuple[str, ...], forbidden: list[str] | tuple[str, ...], label: str
) -> list[str]:
    kept: list[str] = []
    for line in lines:
        if any(blob and blob in line for blob in forbidden):
            kept.append(label)
        else:
            kept.append(line)
    return kept


def _apply(guarded: GuardedPage, ancestry: _Ancestry, text: str) -> tuple[str, str, str, list[str]]:
    decisive = ancestry.ancestry in {CONTAINS_FIX, DOES_NOT_CONTAIN_FIX}
    checked = ancestry.ancestry if decisive else NOT_CHECKABLE
    stated = ancestry.version if decisive else ""
    relation, status, version, stale = apply_ancestry(
        relation=guarded.relation,
        claimed_status=guarded.upstream_status,
        ancestry=checked,
        stated_version=stated,
    )
    fields = list(stale)
    for field in ancestry.stale:
        if field not in fields:
            fields.append(field)
    if none_field_is_stale(text, checked) and "patched_versions:None" not in fields:
        fields.append("patched_versions:None")
    if checked != CONTAINS_FIX:
        version = ""
    return relation, status, version, fields


def _evidence(
    page: ExtractedPage,
    gate_reason: str,
    frames: tuple[str, ...],
    lines: tuple[str, ...],
    ids: ExtractedIds,
    guarded: GuardedPage,
    ancestry: _Ancestry,
    relation: str,
    status: str,
    version: str,
    stale: list[str],
    forbidden: list[str] | tuple[str, ...],
) -> tuple[PublicEvidence, EvidenceView]:
    request_id = guarded.model_calls[-1].request_id if guarded.model_calls else ""
    item = PublicEvidence(
        url=page.url,
        title=page.title,
        frames_matched=list(frames),
        matched_lines=_withhold(lines, forbidden, "matched line withheld"),
        cve_ids=list(ids.cve_ids),
        ghsa_ids=list(ids.ghsa_ids),
        patched_versions=list(ids.patched_versions),
        mentioned_commits=list(ids.fix_commits),
        relation=relation,
        upstream_status=status,
        upstream_version=version,
        ancestry=ancestry.ancestry,
        checked_tag=ancestry.tag,
        checked_commit=ancestry.commit,
        stale_fields=stale,
        quotes=_withhold(guarded.supporting_quotes, forbidden, "quote withheld"),
        dispute=guarded.dispute,
        match_reason=gate_reason,
        model_request_id=request_id,
    )
    claimed = guarded.upstream_status == "FIXED" or bool(
        ids.patched_versions or guarded.upstream_version
    )
    view = EvidenceView(
        True,
        relation,
        status,
        ancestry.ancestry
        if ancestry.ancestry in {CONTAINS_FIX, DOES_NOT_CONTAIN_FIX}
        else NOT_CHECKABLE,
        guarded.dispute,
        claimed,
    )
    return item, view


def _sentence(item: PublicEvidence) -> str:
    if item.dispute and item.ancestry != CONTAINS_FIX:
        head = "This page disputes the recorded upstream status."
    elif item.ancestry == DOES_NOT_CONTAIN_FIX and item.checked_tag:
        head = (
            "This page matches a related crash. "
            f"Git ancestry shows tag {item.checked_tag} does not contain the recorded fix."
        )
    elif item.ancestry == CONTAINS_FIX and item.checked_tag and item.upstream_version:
        head = (
            "This page matches this crash. "
            f"Git ancestry shows tag {item.checked_tag} contains the recorded fix."
        )
    elif item.ancestry == CONTAINS_FIX and item.checked_commit:
        head = "This page matches this crash. The extracted text names the recorded fix commit."
    elif item.relation == "SAME_BUG" and item.upstream_status == "OPEN":
        head = "This page matches this crash. No containing fix was verified."
    elif item.relation == "SAME_BUG":
        head = "This page matches this crash. The upstream fix was not verified."
    else:
        head = "This page is a related public report. It is not recorded as the fix."
    parts = [head]
    if item.stale_fields:
        parts.append("Stale field: " + ", ".join(item.stale_fields) + ".")
    if item.ghsa_ids:
        parts.append("GHSA ids in the extracted text: " + ", ".join(item.ghsa_ids) + ".")
    if item.cve_ids:
        parts.append("CVE ids in the extracted text: " + ", ".join(item.cve_ids) + ".")
    return " ".join(parts)


def _drafts(
    evidence: list[PublicEvidence],
    retrieved_on: str,
    forbidden: list[str] | tuple[str, ...],
    failed: list[str],
) -> list[PublicDraftLine]:
    lines: list[PublicDraftLine] = []
    for item in evidence:
        if item.relation not in {"SAME_BUG", "RELATED_VARIANT"}:
            continue
        confidence = "high" if item.ancestry in {CONTAINS_FIX, DOES_NOT_CONTAIN_FIX} else "medium"
        try:
            drafted = build_draft_line(
                sentence=_sentence(item),
                source_url=item.url,
                source_date=retrieved_on,
                confidence=confidence,
                forbidden=forbidden,
            )
        except DraftRejected:
            failed.append("a draft line was withheld")
            continue
        lines.append(
            PublicDraftLine(
                text=drafted.text,
                source_url=drafted.source_url,
                source_date=drafted.source_date,
                confidence=drafted.confidence,  # type: ignore[arg-type]
            )
        )
    return lines


def _crawl_targets(owner: str, repo: str) -> tuple[str, ...]:
    if not _repo_ok(owner, repo):
        return ()
    return (
        f"https://github.com/{owner}/{repo}/blob/HEAD/SECURITY.md",
        f"https://github.com/{owner}/{repo}/releases",
    )


def _reject_search(search: SearchOutcome) -> dict[str, int]:
    counts = {"host": 0, "snippet": 0, "source_file": 0}
    for item in search.rejected:
        if item.reason == "snippet":
            counts["snippet"] += 1
        elif item.reason == "source_file":
            counts["source_file"] += 1
        elif item.reason.startswith("host:"):
            counts["host"] += 1
    return counts


def _tavily_calls(calls: list[TavilyCall]) -> list[PublicTavilyCall]:
    return [
        PublicTavilyCall(
            operation=call.operation,
            request_id=call.request_id or "missing",
            credits=call.credits,
            query=call.query,
        )
        for call in calls
    ]


def _empty_extract() -> ExtractOutcome:
    return ExtractOutcome((), (), (), "", {})


def lookup_public_status(
    *,
    project: str,
    crash_type: str,
    frames: list[str] | tuple[str, ...],
    owner: str = "",
    repo: str = "",
    fix_commits: list[str] | tuple[str, ...] = (),
    project_site: str = "",
    tavily_client: Any | None = None,
    model_client: Any | None = None,
    ledger: CreditLedger | None = None,
    model_budget: ModelBudget | None = None,
    transport: GitHubTransport | None = None,
    retrieved_on: str,
    forbidden: list[str] | tuple[str, ...] = (),
    crawl_fallback: bool = False,
) -> PublicStatus:
    """Run the stage. Inject the clients, ledger, budget, and git transport in tests."""

    started = time.perf_counter()
    book = ledger if ledger is not None else CreditLedger()
    budget = model_budget if model_budget is not None else ModelBudget()
    call_start = len(book.calls)
    domains = list(default_domains(project_site))
    extra_hosts = _site_hosts(project_site)
    commits = _fix_commits(fix_commits)
    failed: list[str] = []
    model_calls: list[ModelCall] = []
    evidence: list[PublicEvidence] = []
    views: list[EvidenceView] = []
    counts = {"host": 0, "snippet": 0, "frame": 0, "quote": 0, "unrelated": 0, "source_file": 0}
    queries: tuple[str, ...] = ()
    query_source = ""
    unverified: list[str] = []
    usable = _usable(frames)

    def finish(state: str | None = None) -> PublicStatus:
        draft = _drafts(evidence, retrieved_on, forbidden, failed) if evidence else []
        new_calls = book.calls[call_start:]
        decided = state if state is not None else decide_state(views)
        if usable:
            note = sources_note(
                queries=queries,
                domains=domains,
                failed_sources=failed,
                host_rejected=counts["host"],
                frame_rejected=counts["frame"],
                quote_rejected=counts["quote"],
                unverified_versions=unverified,
            )
            note += (
                f" Search snippets rejected: {counts['snippet']}."
                f" Source files rejected: {counts['source_file']}."
                f" Unrelated pages rejected: {counts['unrelated']}."
            )
        else:
            note = "No measured crash frame was available, so no search was sent."
        tavily = _tavily_calls(new_calls)
        return PublicStatus(
            state=decided,  # type: ignore[arg-type]
            evidence=list(evidence),
            queries_sent=list(queries),
            query_source=query_source,
            domains=list(domains),
            failed_sources=list(failed),
            note=note,
            tavily_request_ids=[call.request_id for call in tavily if call.request_id != "missing"],
            tavily_calls=tavily,
            tavily_credits=sum(call.credits for call in new_calls),
            model_calls=list(model_calls),
            draft=draft,
            host_rejected=counts["host"],
            snippet_rejected=counts["snippet"],
            frame_rejected=counts["frame"],
            quote_rejected=counts["quote"],
            unrelated_rejected=counts["unrelated"],
            source_file_rejected=counts["source_file"],
            latency_seconds=round(time.perf_counter() - started, 6),
        )

    if not usable:
        return finish(LOOKUP_UNAVAILABLE)

    try:
        plan = plan_queries(project, crash_type, usable, client=model_client, budget=budget)
    except PublicModelError as exc:
        if exc.model_call is not None:
            model_calls.append(exc.model_call)
        failed.append(_clean(f"query planner: {exc}"))
        planned = fallback_queries(project, crash_type, usable)
        plan = QueryPlan(planned, "deterministic_fallback", 0, (), ())
    model_calls.extend(plan.model_calls)
    queries = plan.queries
    query_source = plan.query_source
    if plan.rejected:
        reasons = ", ".join(sorted({reason for _query, reason in plan.rejected}))
        failed.append(f"rejected query reasons: {reasons}")

    try:
        search = perform_search(
            queries=queries,
            project=project,
            frames=usable,
            crash_type=crash_type,
            owner=owner,
            repo=repo,
            include_domains=domains,
            extra_hosts=extra_hosts,
            client=tavily_client,
            ledger=book,
        )
    except TavilyApiError as exc:
        # No search response survived, so no planned query is reported as searched.
        queries = ()
        failed.append(_clean(f"search failed: {exc}"))
        return finish(LOOKUP_UNAVAILABLE)
    # The note and card list only queries that were sent, not every planned query.
    queries = search.queries_sent
    search_counts = _reject_search(search)
    counts["host"] += search_counts["host"]
    counts["snippet"] += search_counts["snippet"]
    counts["source_file"] += search_counts["source_file"]
    if search.stopped:
        # A stop can carry an exception's text, so it is scrubbed like any other failure.
        failed.append(_clean(f"search stopped: {search.stopped}"))
    if search.responses_read == 0:
        # Every query was refused, stopped, or answered without a result list.
        return finish(LOOKUP_UNAVAILABLE)

    titles = {hit.url: hit.title for hit in search.hits}
    try:
        extracted = perform_extract(
            urls=[hit.url for hit in search.hits],
            frames=usable,
            client=tavily_client,
            ledger=book,
        )
    except TavilyApiError as exc:
        failed.append(_clean(f"extract failed: {exc}"))
        extracted = _empty_extract()
    if extracted.stopped:
        failed.append(_clean(f"extract stopped: {extracted.stopped}"))
    for url in extracted.failed_urls:
        failed.append(f"extract failed url: {url}")

    passed_frame = _take_pages(
        extracted.pages,
        titles,
        project=project,
        crash_type=crash_type,
        frames=usable,
        owner=owner,
        repo=repo,
        extra_hosts=extra_hosts,
        commits=commits,
        transport=transport,
        model_client=model_client,
        budget=budget,
        forbidden=forbidden,
        counts=counts,
        failed=failed,
        model_calls=model_calls,
        evidence=evidence,
        views=views,
        unverified=unverified,
    )
    pages_read = len(extracted.pages)
    if crawl_fallback and not passed_frame:
        pages_read += _crawl(
            owner,
            repo,
            extra_hosts,
            tavily_client,
            book,
            project=project,
            crash_type=crash_type,
            frames=usable,
            commits=commits,
            transport=transport,
            model_client=model_client,
            budget=budget,
            forbidden=forbidden,
            counts=counts,
            failed=failed,
            model_calls=model_calls,
            evidence=evidence,
            views=views,
            unverified=unverified,
            seen={item.url for item in evidence},
        )
    if search.hits and pages_read == 0 and decide_state(views) == NO_PUBLIC_FINDINGS:
        # Search returned pages and none could be read, so "nothing public" is not known.
        return finish(LOOKUP_UNAVAILABLE)
    return finish()


def _take_pages(
    pages: tuple[ExtractedPage, ...],
    titles: dict[str, str],
    *,
    project: str,
    crash_type: str,
    frames: list[str],
    owner: str,
    repo: str,
    extra_hosts: tuple[str, ...],
    commits: tuple[str, ...],
    transport: GitHubTransport | None,
    model_client: Any | None,
    budget: ModelBudget,
    forbidden: list[str] | tuple[str, ...],
    counts: dict[str, int],
    failed: list[str],
    model_calls: list[ModelCall],
    evidence: list[PublicEvidence],
    views: list[EvidenceView],
    unverified: list[str],
) -> bool:
    passed = False
    stop = False
    for page in pages:
        if stop:
            break
        title = page.title or titles.get(page.url, "")
        shown = page if page.title else ExtractedPage(page.url, page.text, title)
        kept, halt = _judge_page(
            shown,
            project=project,
            crash_type=crash_type,
            frames=frames,
            owner=owner,
            repo=repo,
            extra_hosts=extra_hosts,
            commits=commits,
            transport=transport,
            model_client=model_client,
            budget=budget,
            forbidden=forbidden,
            counts=counts,
            failed=failed,
            model_calls=model_calls,
            unverified=unverified,
        )
        if kept is not None:
            item, view = kept
            evidence.append(item)
            views.append(view)
            passed = True
        elif halt == "passed_frame":
            passed = True
        if halt == "stop":
            stop = True
    return passed


def _judge_page(
    page: ExtractedPage,
    *,
    project: str,
    crash_type: str,
    frames: list[str],
    owner: str,
    repo: str,
    extra_hosts: tuple[str, ...],
    commits: tuple[str, ...],
    transport: GitHubTransport | None,
    model_client: Any | None,
    budget: ModelBudget,
    forbidden: list[str] | tuple[str, ...],
    counts: dict[str, int],
    failed: list[str],
    model_calls: list[ModelCall],
    unverified: list[str],
) -> tuple[tuple[PublicEvidence, EvidenceView] | None, str]:
    decision = host_allowed(
        page.url,
        owner=owner,
        repo=repo,
        project=project,
        text=page.text,
        extra_hosts=extra_hosts,
    )
    if not decision.allowed:
        counts["host"] += 1
        return None, ""
    gate = match_frames(page.text, frames, crash_type)
    if not gate.passes:
        counts["frame"] += 1
        return None, ""
    try:
        guarded = classify_page(
            page.text,
            project=project,
            crash_type=crash_type,
            frames=frames,
            client=model_client,
            budget=budget,
        )
    except PublicModelError as exc:
        if exc.model_call is not None:
            model_calls.append(exc.model_call)
        failed.append(_clean(f"classification failed: {exc}"))
        return None, "stop"
    model_calls.extend(guarded.model_calls)
    if not guarded.accepted:
        if guarded.rejection == "unrelated":
            counts["unrelated"] += 1
        elif guarded.rejection in _QUOTE_REJECTIONS:
            counts["quote"] += 1
        elif guarded.rejection == "budget_exhausted":
            failed.append("classification stopped: budget")
            return None, "stop"
        elif guarded.rejection:
            failed.append(f"classification rejected: {guarded.rejection}")
        return None, "passed_frame"
    ids = extract_ids(page.text)
    ancestry = assess_ancestry(
        page.text,
        ids,
        guarded,
        commits,
        owner=owner,
        repo=repo,
        transport=transport,
        failed=failed,
    )
    relation, status, version, stale = _apply(guarded, ancestry, page.text)
    if ancestry.ancestry not in {CONTAINS_FIX, DOES_NOT_CONTAIN_FIX}:
        for stated in _stated_versions(ids, guarded.upstream_version):
            if stated not in unverified:
                unverified.append(stated)
    item, view = _evidence(
        page,
        gate.reason,
        gate.frames_matched,
        gate.matched_lines,
        ids,
        guarded,
        ancestry,
        relation,
        status,
        version,
        stale,
        forbidden,
    )
    return (item, view), ""


def _crawl(
    owner: str,
    repo: str,
    extra_hosts: tuple[str, ...],
    tavily_client: Any | None,
    book: CreditLedger,
    *,
    project: str,
    crash_type: str,
    frames: list[str],
    commits: tuple[str, ...],
    transport: GitHubTransport | None,
    model_client: Any | None,
    budget: ModelBudget,
    forbidden: list[str] | tuple[str, ...],
    counts: dict[str, int],
    failed: list[str],
    model_calls: list[ModelCall],
    evidence: list[PublicEvidence],
    views: list[EvidenceView],
    unverified: list[str],
    seen: set[str],
) -> int:
    """Judge crawled pages until one passes the frame gate. Return how many pages were judged."""

    judged = 0
    for url in _crawl_targets(owner, repo):
        try:
            crawled = perform_crawl(
                url=url,
                owner=owner,
                repo=repo,
                extra_hosts=extra_hosts,
                client=tavily_client,
                ledger=book,
            )
        except TavilyRejected as exc:
            failed.append(f"crawl refused: {exc}")
            continue
        except TavilyApiError as exc:
            failed.append(_clean(f"crawl failed: {exc}"))
            return judged
        if crawled.stopped:
            failed.append(f"crawl stopped: {crawled.stopped}")
            return judged
        fresh = tuple(page for page in crawled.pages if page.url not in seen)
        judged += len(fresh)
        found = _take_pages(
            fresh,
            {},
            project=project,
            crash_type=crash_type,
            frames=frames,
            owner=owner,
            repo=repo,
            extra_hosts=extra_hosts,
            commits=commits,
            transport=transport,
            model_client=model_client,
            budget=budget,
            forbidden=forbidden,
            counts=counts,
            failed=failed,
            model_calls=model_calls,
            evidence=evidence,
            views=views,
            unverified=unverified,
        )
        if found:
            return judged
    return judged


def attach_public_status(card: TriageCard, status: PublicStatus) -> TriageCard:
    """Copy public-status model calls onto the card so their USD cost is included.

    Tavily credits stay on `public_status`. They are not added to `total_cost_usd`.
    """

    seen = {call.request_id for call in card.model_calls}
    merged = list(card.model_calls)
    for call in status.model_calls:
        if call.request_id not in seen:
            merged.append(call)
            seen.add(call.request_id)
    model_cost = sum(call.cost_usd for call in merged)
    return card.model_copy(
        update={
            "model_calls": merged,
            "model_cost_usd": model_cost,
            "total_cost_usd": model_cost + card.sandbox_cost_usd,
            "public_status": status,
        }
    )
