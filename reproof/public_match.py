"""Deterministic public-status checks.

No network and no model call. A page becomes evidence only through the frame
gate. A model quote, version, or id is kept only when that exact string is in
the extracted page. Git ancestry, not the page's own patched-version field,
decides whether a named release contains the recorded fix.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

QUERY_CHAR_LIMIT = 400
FRAME_MIN_LENGTH = 4
SNIPPET_FRAME_MIN_LENGTH = 6

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_GHSA = re.compile(r"\bGHSA(?:-[a-z0-9]{4}){3}\b", re.IGNORECASE)
_COMMIT = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
_SIZE_SUFFIX = re.compile(r"\s+\{\d+\}\s*$")
_ACCESS_SUFFIX = re.compile(r"\s+(?:READ|WRITE)\s+\d+\s*$", re.IGNORECASE)
_PATCHED_VERSION = re.compile(
    r"(?i)\b(?:patched(?:\s+versions?)?|fixed\s+in|upgrade\s+to)\b"
    r"\s*[:\-]?\s*(?:[A-Za-z][\w.-]*\s+)?v?(\d+\.\d+(?:\.\d+){0,3})"
)
_PATCHED_NONE = re.compile(r"(?i)\bpatched\s+versions?\b\s*[:\-]?\s*none\b")
_VERSION_TOKEN = re.compile(r"^\d+\.\d+(?:\.\d+){0,3}$")

ADVISORY_HOSTS = frozenset({"nvd.nist.gov", "cve.org", "www.cve.org"})
OSS_SECURITY_HOSTS = frozenset({"openwall.com", "www.openwall.com"})

CONTAINS_FIX = "CONTAINS_FIX"
DOES_NOT_CONTAIN_FIX = "DOES_NOT_CONTAIN_FIX"
NOT_CHECKABLE = "NOT_CHECKABLE"
NO_FIX_COMMIT = "NO_FIX_COMMIT"

PUBLICLY_KNOWN_FIXED = "PUBLICLY_KNOWN_FIXED"
PUBLICLY_KNOWN_OPEN = "PUBLICLY_KNOWN_OPEN"
RELATED_VARIANTS_ONLY = "RELATED_VARIANTS_ONLY"
SOURCE_DISPUTE = "SOURCE_DISPUTE"
NO_PUBLIC_FINDINGS = "NO_PUBLIC_FINDINGS"
# No page was read, so nothing is claimed either way. Never shown as "no findings".
LOOKUP_UNAVAILABLE = "LOOKUP_UNAVAILABLE"

SAME_BUG = "SAME_BUG"
RELATED_VARIANT = "RELATED_VARIANT"
UNRELATED = "UNRELATED"
FIXED = "FIXED"
OPEN = "OPEN"
UNKNOWN = "UNKNOWN"

_CONFIDENCE = frozenset({"high", "medium", "low"})


class DraftRejected(ValueError):
    """A draft line is missing its citation or contains a forbidden blob."""


@dataclass(frozen=True, slots=True)
class FrameMatch:
    """Result of the frame gate. `reason` is empty when the page is rejected."""

    passes: bool
    reason: str
    frames_matched: tuple[str, ...]
    matched_lines: tuple[str, ...]
    crash_type_matched: bool
    crash_type_line: str


@dataclass(frozen=True, slots=True)
class ExtractedIds:
    cve_ids: tuple[str, ...]
    ghsa_ids: tuple[str, ...]
    patched_versions: tuple[str, ...]
    fix_commits: tuple[str, ...]
    patched_versions_none: bool


@dataclass(frozen=True, slots=True)
class HostDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class EvidenceView:
    """One page after the guards, as the state machine sees it."""

    accepted: bool
    relation: str
    upstream_status: str
    ancestry: str
    dispute: bool
    claimed_fix: bool


@dataclass(frozen=True, slots=True)
class DraftLine:
    text: str
    source_url: str
    source_date: str
    confidence: str


def crash_type_keyword(crash_type: str) -> str:
    """Drop a trailing access size so the family name can match a title.

    `Heap-buffer-overflow WRITE 1` and `Stack-buffer-overflow {16}` both keep
    the family token. The token is matched later as a case-insensitive substring.
    """

    text = " ".join(crash_type.split())
    text = _SIZE_SUFFIX.sub("", text)
    text = _ACCESS_SUFFIX.sub("", text)
    return text.strip()


def _usable_frames(frames: Sequence[str], *, minimum: int) -> tuple[str, ...]:
    seen: list[str] = []
    for frame in frames:
        cleaned = frame.strip()
        if len(cleaned) < minimum or cleaned in seen:
            continue
        seen.append(cleaned)
    return tuple(seen)


def _matching_lines(text: str, needle: str) -> tuple[str, ...]:
    folded = needle.casefold()
    return tuple(line for line in text.splitlines() or (text,) if folded in line.casefold())


def match_frames(text: str, frames: Sequence[str], crash_type: str) -> FrameMatch:
    """Evidence gate: top frame plus crash-type keyword, or two measured frames.

    Both comparisons are exact case-insensitive substrings. A non-top frame
    plus the crash type is not enough: jq's advisory names only `decNaNs`, so
    the top-frame rule is what keeps that page, and a second-frame-only page
    still fails.
    """

    usable = _usable_frames(frames, minimum=FRAME_MIN_LENGTH)
    if not usable:
        return FrameMatch(False, "", (), (), False, "")
    matched: list[str] = []
    lines: list[str] = []
    for frame in usable:
        hits = _matching_lines(text, frame)
        if not hits:
            continue
        matched.append(frame)
        lines.append(hits[0])
    keyword = crash_type_keyword(crash_type)
    type_hits = _matching_lines(text, keyword) if keyword else ()
    top_matched = usable[0] in matched
    type_matched = bool(type_hits)
    two_frames = len(matched) >= 2
    passes = (top_matched and type_matched) or two_frames
    if not passes:
        return FrameMatch(
            False,
            "",
            tuple(matched),
            tuple(lines),
            type_matched,
            type_hits[0] if type_hits else "",
        )
    reason = "top_frame_and_crash_type" if top_matched and type_matched else "two_frames"
    type_line = type_hits[0] if type_hits else ""
    return FrameMatch(True, reason, tuple(matched), tuple(lines), type_matched, type_line)


def snippet_worth_extract(snippet: str, frames: Sequence[str], crash_type: str) -> bool:
    """True when a search snippet is specific enough to spend an extract call."""

    keyword = crash_type_keyword(crash_type)
    if keyword and keyword.casefold() in snippet.casefold():
        return True
    return any(
        frame.casefold() in snippet.casefold()
        for frame in _usable_frames(frames, minimum=SNIPPET_FRAME_MIN_LENGTH)
    )


def _collapse_whitespace(text: str) -> str:
    return " ".join(text.split())


def quote_is_exact(quote: str, extracted: str) -> bool:
    """Keep a quote only when it is on the page character for character.

    A run of whitespace, line breaks included, compares as one space on both
    sides, because extraction and the model lay out the same lines differently.
    Nothing else is relaxed: case, punctuation, word order, and every character
    inside a word must match.
    """

    collapsed = _collapse_whitespace(quote)
    return bool(collapsed) and collapsed in _collapse_whitespace(extracted)


def identifier_in_text(identifier: str, extracted: str) -> bool:
    """True when a model-supplied id or version actually appears on the page.

    A dotted version must be its own token. `1.7.1` is not present in `1.7.10`.
    CVE and GHSA ids and commit hashes must match character for character.
    """

    if not identifier:
        return False
    if _VERSION_TOKEN.fullmatch(identifier):
        pattern = rf"(?<![\d.]){re.escape(identifier)}(?!\d)(?!\.\d)"
        return re.search(pattern, extracted) is not None
    return identifier in extracted


def split_quotes(quotes: Sequence[str], extracted: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    kept = tuple(quote for quote in quotes if quote_is_exact(quote, extracted))
    rejected = tuple(quote for quote in quotes if not quote_is_exact(quote, extracted))
    return kept, rejected


def classification_accepted(
    *,
    quotes: Sequence[str],
    versions: Sequence[str],
    ids: Sequence[str],
    commits: Sequence[str],
    extracted: str,
) -> bool:
    """A classification stands only with a real quote and no invented id.

    An empty quote list is a rejection: the model must quote the page. One
    rejected quote, version, id, or commit rejects the whole classification.
    """

    if not quotes or any(not quote_is_exact(quote, extracted) for quote in quotes):
        return False
    supplied = (*versions, *ids, *commits)
    return all(identifier_in_text(value, extracted) for value in supplied)


def extract_ids(text: str) -> ExtractedIds:
    """Pull CVE, GHSA, stated versions, and 40-hex commits with regex only."""

    versions = tuple(dict.fromkeys(_PATCHED_VERSION.findall(text)))
    commits = tuple(dict.fromkeys(match.group(0).lower() for match in _COMMIT.finditer(text)))
    return ExtractedIds(
        cve_ids=tuple(dict.fromkeys(match.group(0).upper() for match in _CVE.finditer(text))),
        ghsa_ids=tuple(dict.fromkeys(match.group(0).lower() for match in _GHSA.finditer(text))),
        patched_versions=versions,
        fix_commits=commits,
        patched_versions_none=_PATCHED_NONE.search(text) is not None,
    )


def host_allowed(
    url: str,
    *,
    owner: str,
    repo: str,
    project: str,
    text: str,
    extra_hosts: Sequence[str] = (),
) -> HostDecision:
    """Allow the project's own GitHub repo, or an advisory host that names it.

    `github.com/advisories/...` and `github.com/google/oss-fuzz/...` are other
    repositories and are rejected. NVD, cve.org, and oss-security count only
    when the extracted text names the project. Extra hosts are project sites
    the caller already knows, under the same naming rule.
    """

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or parsed.scheme not in {"http", "https"}:
        return HostDecision(False, "unusable_url")
    names_project = bool(project) and project.casefold() in text.casefold()
    if host == "github.com":
        parts = [part for part in parsed.path.split("/") if part]
        if (
            len(parts) >= 2
            and owner
            and repo
            and parts[0].casefold() == owner.casefold()
            and parts[1].casefold() == repo.casefold()
        ):
            return HostDecision(True, "project_repo")
        return HostDecision(False, "other_github_repo")
    if host in ADVISORY_HOSTS:
        if names_project:
            return HostDecision(True, "advisory_host")
        return HostDecision(False, "advisory_host_missing_project")
    if host in OSS_SECURITY_HOSTS and "/oss-security" in parsed.path:
        if names_project:
            return HostDecision(True, "oss_security")
        return HostDecision(False, "oss_security_missing_project")
    allowed_extra = {item.lower() for item in extra_hosts}
    if host in allowed_extra:
        if names_project:
            return HostDecision(True, "project_site")
        return HostDecision(False, "project_site_missing_project")
    return HostDecision(False, "host_not_allowed")


def query_rejection(query: str, project: str, frames: Sequence[str]) -> str:
    """Return a rejection reason, or an empty string when the query may be sent."""

    if not query.strip():
        return "empty"
    if len(query) >= QUERY_CHAR_LIMIT:
        return "too_long"
    folded = query.casefold()
    has_project = bool(project) and project.casefold() in folded
    has_frame = any(
        frame.casefold() in folded for frame in _usable_frames(frames, minimum=FRAME_MIN_LENGTH)
    )
    if not has_project and not has_frame:
        return "missing_project_and_frame"
    return ""


def fallback_queries(project: str, crash_type: str, frames: Sequence[str]) -> tuple[str, ...]:
    """Two deterministic queries that already pass `query_rejection`."""

    keyword = crash_type_keyword(crash_type)
    usable = _usable_frames(frames, minimum=FRAME_MIN_LENGTH)
    first_bits = [bit for bit in (project, keyword, usable[0] if usable else "") if bit]
    rest = [bit for bit in (project, *usable[:3]) if bit]
    queries: list[str] = []
    for bits in (first_bits, rest):
        query = " ".join(bits)[: QUERY_CHAR_LIMIT - 1].strip()
        if query and query not in queries and not query_rejection(query, project, frames):
            queries.append(query)
    return tuple(queries)


def interpret_compare(status: str, ahead_by: int, behind_by: int) -> str:
    """Read a GitHub compare of tag (base) against the fix commit (head).

    `ahead_by == 0` with status `identical` or `behind` means every commit in
    the fix is already in the tag. `ahead` or `diverged` means the tag does
    not contain it. Any other shape is not checkable.
    """

    if ahead_by < 0 or behind_by < 0:
        return NOT_CHECKABLE
    if status in {"identical", "behind"} and ahead_by == 0:
        return CONTAINS_FIX
    if status == "ahead" and ahead_by > 0:
        return DOES_NOT_CONTAIN_FIX
    if status == "diverged" and ahead_by > 0 and behind_by > 0:
        return DOES_NOT_CONTAIN_FIX
    return NOT_CHECKABLE


def matching_tags(version: str, tags: Sequence[str]) -> tuple[str, ...]:
    """Tags that are the version, `v` plus the version, or end in `-`/`_` plus it."""

    cleaned = version.strip()
    if not _VERSION_TOKEN.fullmatch(cleaned):
        return ()
    found: list[str] = []
    for tag in tags:
        if tag in found:
            continue
        if tag == cleaned or tag == f"v{cleaned}":
            found.append(tag)
            continue
        if tag.endswith(f"-{cleaned}") or tag.endswith(f"_{cleaned}"):
            found.append(tag)
    return tuple(found)


def resolve_tag(version: str, tags: Sequence[str]) -> tuple[str, str]:
    """Return `(tag, reason)`. Zero or multiple matches are not checkable."""

    matches = matching_tags(version, tags)
    if len(matches) == 1:
        return matches[0], "resolved"
    if not matches:
        return "", "no_tag"
    return "", "ambiguous"


def named_fix_commit(text: str, fix_commits: Sequence[str]) -> str:
    """Return the recorded fix hash when the page contains that exact commit."""

    folded = text.casefold()
    for commit in fix_commits:
        cleaned = commit.strip().lower()
        if len(cleaned) == 40 and cleaned in folded:
            return commit.strip()
    return ""


def apply_ancestry(
    *,
    relation: str,
    claimed_status: str,
    ancestry: str,
    stated_version: str,
) -> tuple[str, str, str, tuple[str, ...]]:
    """Return relation, verified status, upstream version, and stale fields.

    A version whose tag does not contain the recorded fix demotes SAME_BUG to
    RELATED_VARIANT. A claimed fix that git could not check is not recorded
    as FIXED and its version stays off `upstream_version`.
    """

    if ancestry == DOES_NOT_CONTAIN_FIX:
        stale = (f"patched_version:{stated_version}",) if stated_version else ()
        relation_out = RELATED_VARIANT if relation == SAME_BUG else relation
        return relation_out, UNKNOWN, "", stale
    if ancestry == CONTAINS_FIX and relation in {SAME_BUG, RELATED_VARIANT}:
        return SAME_BUG, FIXED, stated_version, ()
    if relation == SAME_BUG and claimed_status == OPEN:
        return SAME_BUG, OPEN, "", ()
    if claimed_status == FIXED or relation == SAME_BUG:
        return relation, UNKNOWN, "", ()
    return relation, "", "", ()


def none_field_is_stale(text: str, ancestry: str) -> bool:
    """A 'Patched versions: None' line is stale when git shows a containing fix."""

    return ancestry == CONTAINS_FIX and _PATCHED_NONE.search(text) is not None


def decide_state(items: Sequence[EvidenceView]) -> str:
    """Pick the card state from pages that already passed the guards.

    PUBLICLY_KNOWN_FIXED requires a same-bug page whose ancestry contains the
    recorded fix. A same-bug page that claims a fix git could not check stays
    off that state: its verified status is UNKNOWN, and the card says the fix
    was not verified. PUBLICLY_KNOWN_OPEN is that unknown case and an actually
    open report, never a verified fix.
    """

    accepted = [
        item for item in items if item.accepted and item.relation in {SAME_BUG, RELATED_VARIANT}
    ]
    if not accepted:
        return NO_PUBLIC_FINDINGS
    if any(item.relation == SAME_BUG and item.ancestry == CONTAINS_FIX for item in accepted):
        return PUBLICLY_KNOWN_FIXED
    if any(item.dispute for item in accepted):
        return SOURCE_DISPUTE
    if any(
        item.relation == SAME_BUG and item.upstream_status in {OPEN, UNKNOWN} for item in accepted
    ):
        return PUBLICLY_KNOWN_OPEN
    return RELATED_VARIANTS_ONLY


def unverified_fix_note(version: str) -> str:
    shown = version or "a version"
    return (
        f"A public page states {shown}. Git ancestry could not verify it. "
        "That version is not recorded as the fix."
    )


def sources_note(
    *,
    queries: Sequence[str],
    domains: Sequence[str],
    failed_sources: Sequence[str] = (),
    host_rejected: int = 0,
    frame_rejected: int = 0,
    quote_rejected: int = 0,
    unverified_versions: Sequence[str] = (),
) -> str:
    """Say exactly what was searched. This note is the no-finding explanation."""

    # A search that raised may still have reached Tavily: empty means no response, not no request.
    query_text = "; ".join(queries) if queries else "(no search response)"
    domain_text = ", ".join(domains) if domains else "(no domain)"
    parts = [f"Searched queries: {query_text}.", f"Domains: {domain_text}."]
    if failed_sources:
        parts.append("Failed sources: " + "; ".join(failed_sources) + ".")
    parts.append(
        "Rejected before the card: "
        f"{host_rejected} by host, {frame_rejected} by the frame gate, "
        f"{quote_rejected} by the quote guard."
    )
    for version in unverified_versions:
        parts.append(unverified_fix_note(version))
    return " ".join(parts)


def build_draft_line(
    *,
    sentence: str,
    source_url: str,
    source_date: str,
    confidence: str,
    forbidden: Sequence[str] = (),
) -> DraftLine:
    """One maintainer-facing line that carries its own source, date, and confidence."""

    if not source_url or not source_date or confidence not in _CONFIDENCE:
        raise DraftRejected("a draft line needs a source URL, a date, and a confidence")
    if not sentence.strip():
        raise DraftRejected("a draft line needs a sentence")
    text = (
        f"{sentence.strip()} Source: {source_url}. Date: {source_date}. Confidence: {confidence}."
    )
    for blob in forbidden:
        if blob and blob in text:
            raise DraftRejected("a draft line contains a forbidden blob")
    return DraftLine(text, source_url, source_date, confidence)
