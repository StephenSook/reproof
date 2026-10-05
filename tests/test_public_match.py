"""Deterministic public-status gates. No network."""

from __future__ import annotations

import pytest

from reproof.public_match import (
    CONTAINS_FIX,
    DOES_NOT_CONTAIN_FIX,
    FIXED,
    NO_FIX_COMMIT,
    NO_PUBLIC_FINDINGS,
    NOT_CHECKABLE,
    OPEN,
    PUBLICLY_KNOWN_FIXED,
    PUBLICLY_KNOWN_OPEN,
    RELATED_VARIANT,
    RELATED_VARIANTS_ONLY,
    SAME_BUG,
    SOURCE_DISPUTE,
    UNKNOWN,
    DraftRejected,
    EvidenceView,
    apply_ancestry,
    build_draft_line,
    classification_accepted,
    crash_type_keyword,
    decide_state,
    extract_ids,
    fallback_queries,
    host_allowed,
    identifier_in_text,
    interpret_compare,
    match_frames,
    named_fix_commit,
    none_field_is_stale,
    query_rejection,
    quote_is_exact,
    resolve_tag,
    snippet_worth_extract,
    sources_note,
    unverified_fix_note,
)

JQ_PAGE = """\
[oss-fuzz] Issue 64771: Stack-buffer-overflow in decNaNs
GHSA-7hmr-442f-qc8j
CVE-2023-50268
Patched versions: 1.7.1
"""

JQ_FRAMES = ("decNaNs", "decNumberCopy", "decCompareOp")
WASM_FRAMES = ("ForEachModule", "Runtime_Release", "m3_FreeRuntime")
FIX_42531223 = "b86ff49f46a4a37e5a8e75a140cb5fd6e1331384"


def test_top_frame_and_crash_type_keeps_jq_advisory() -> None:
    """GHSA-7hmr names only decNaNs. A two-frame rule would drop it."""

    matched = match_frames(JQ_PAGE, JQ_FRAMES, "Stack-buffer-overflow")
    assert matched.passes
    assert matched.reason == "top_frame_and_crash_type"
    assert matched.frames_matched == ("decNaNs",)
    assert "decNaNs" in matched.matched_lines[0]
    assert matched.crash_type_matched
    assert "Stack-buffer-overflow" in matched.crash_type_line


def test_two_frames_pass_without_the_crash_type_keyword() -> None:
    text = "Use-After-Free in ForEachModule\nRuntime_Release\nm3_FreeRuntime"
    matched = match_frames(text, WASM_FRAMES, "Heap-use-after-free READ 8")
    assert matched.passes
    assert matched.reason == "two_frames"
    assert matched.frames_matched == WASM_FRAMES
    assert not matched.crash_type_matched


def test_crash_type_with_only_a_lower_frame_is_rejected() -> None:
    text = "Stack-buffer-overflow in decNumberCopy"
    matched = match_frames(text, JQ_FRAMES, "Stack-buffer-overflow")
    assert not matched.passes
    assert matched.frames_matched == ("decNumberCopy",)


def test_top_frame_alone_is_rejected() -> None:
    matched = match_frames("see decNaNs", JQ_FRAMES, "Stack-buffer-overflow")
    assert not matched.passes


def test_frame_match_is_case_insensitive_and_quotes_the_page_line() -> None:
    matched = match_frames("STACK-BUFFER-OVERFLOW in DECNANS", JQ_FRAMES, "Stack-buffer-overflow")
    assert matched.passes
    assert matched.matched_lines == ("STACK-BUFFER-OVERFLOW in DECNANS",)


def test_hyphenless_crash_type_does_not_match() -> None:
    text = "stack buffer overflow in decNaNs"
    matched = match_frames(text, JQ_FRAMES, "Stack-buffer-overflow")
    assert not matched.passes


def test_crash_type_keyword_strips_access_and_size() -> None:
    assert crash_type_keyword("Heap-buffer-overflow WRITE 1") == "Heap-buffer-overflow"
    assert crash_type_keyword("Heap-use-after-free READ 8") == "Heap-use-after-free"
    assert crash_type_keyword("Stack-buffer-overflow {16}") == "Stack-buffer-overflow"


def test_short_frames_do_not_count() -> None:
    matched = match_frames("ab cd", ("ab", "cd"), "Heap-buffer-overflow")
    assert not matched.passes
    assert matched.frames_matched == ()


def test_quote_must_be_exact_substring() -> None:
    page = "Stack-buffer-overflow in decNaNs"
    assert quote_is_exact("Stack-buffer-overflow in decNaNs", page)
    assert not quote_is_exact("stack-buffer-overflow in decNaNs", page)
    assert not quote_is_exact("", page)
    assert not quote_is_exact("decNaNs patched in 9.9.9", page)


def test_version_token_is_not_a_prefix() -> None:
    assert identifier_in_text("1.7.1", "patched in jq 1.7.1.")
    assert not identifier_in_text("1.7.1", "patched in jq 1.7.10")
    assert identifier_in_text("CVE-2023-50268", JQ_PAGE)
    assert not identifier_in_text("CVE-2024-00000", JQ_PAGE)
    assert not identifier_in_text("cve-2023-50268", JQ_PAGE)


def test_classification_rejects_a_quote_or_id_missing_from_the_page() -> None:
    assert classification_accepted(
        quotes=("Stack-buffer-overflow in decNaNs",),
        versions=("1.7.1",),
        ids=("GHSA-7hmr-442f-qc8j", "CVE-2023-50268"),
        commits=(),
        extracted=JQ_PAGE,
    )
    assert not classification_accepted(
        quotes=("this sentence was composed",),
        versions=("1.7.1",),
        ids=(),
        commits=(),
        extracted=JQ_PAGE,
    )
    assert not classification_accepted(
        quotes=("Stack-buffer-overflow in decNaNs",),
        versions=("9.9.9",),
        ids=(),
        commits=(),
        extracted=JQ_PAGE,
    )
    assert not classification_accepted(
        quotes=(),
        versions=(),
        ids=(),
        commits=(),
        extracted=JQ_PAGE,
    )


def test_extract_ids_reads_the_jq_advisory_and_a_none_field() -> None:
    found = extract_ids(JQ_PAGE)
    assert found.cve_ids == ("CVE-2023-50268",)
    assert found.ghsa_ids == ("ghsa-7hmr-442f-qc8j",)
    assert found.patched_versions == ("1.7.1",)
    assert not found.patched_versions_none
    none_page = "Patched versions: None\nfixed in jq 1.8.0"
    none_found = extract_ids(none_page)
    assert none_found.patched_versions_none
    assert none_found.patched_versions == ("1.8.0",)


def test_project_repo_is_allowed_and_other_github_repos_are_not() -> None:
    advisory = "https://github.com/jqlang/jq/security/advisories/GHSA-7hmr-442f-qc8j"
    assert host_allowed(advisory, owner="jqlang", repo="jq", project="jq", text=JQ_PAGE).allowed
    global_advisory = "https://github.com/advisories/GHSA-7hmr-442f-qc8j"
    rejected = host_allowed(global_advisory, owner="jqlang", repo="jq", project="jq", text=JQ_PAGE)
    assert not rejected.allowed
    assert rejected.reason == "other_github_repo"
    oss_fuzz = "https://github.com/google/oss-fuzz/issues/13193"
    assert not host_allowed(
        oss_fuzz, owner="jqlang", repo="jq", project="jq", text="jq dispute"
    ).allowed


def test_advisory_hosts_must_name_the_project() -> None:
    nvd = "https://nvd.nist.gov/vuln/detail/CVE-2023-50268"
    assert host_allowed(nvd, owner="jqlang", repo="jq", project="jq", text="jq 1.7.1").allowed
    assert not host_allowed(
        nvd, owner="jqlang", repo="jq", project="jq", text="unrelated library"
    ).allowed
    oss = "https://www.openwall.com/lists/oss-security/2024/01/01/1"
    assert host_allowed(oss, owner="jqlang", repo="jq", project="jq", text="jq issue").allowed
    assert not host_allowed(
        "https://www.openwall.com/lists/oss-security",
        owner="jqlang",
        repo="jq",
        project="jq",
        text="no project here",
    ).allowed
    site = "https://jqlang.github.io/jq/news/"
    assert host_allowed(
        site,
        owner="jqlang",
        repo="jq",
        project="jq",
        text="jq release",
        extra_hosts=("jqlang.github.io",),
    ).allowed


def test_query_guard_and_fallback_queries() -> None:
    assert query_rejection("jq decNaNs", "jq", JQ_FRAMES) == ""
    assert query_rejection("decNaNs", "jq", JQ_FRAMES) == ""
    assert query_rejection("jq", "jq", JQ_FRAMES) == ""
    assert query_rejection("stack overflow bug", "jq", JQ_FRAMES) == "missing_project_and_frame"
    assert query_rejection("", "jq", JQ_FRAMES) == "empty"
    assert query_rejection("jq " + ("x" * 400), "jq", JQ_FRAMES) == "too_long"
    queries = fallback_queries("jq", "Stack-buffer-overflow", JQ_FRAMES)
    assert len(queries) == 2
    assert all(not query_rejection(query, "jq", JQ_FRAMES) for query in queries)
    assert all(len(query) < 400 for query in queries)
    assert "decNaNs" in queries[0]


def test_jq_1_7_1_does_not_contain_the_later_fix() -> None:
    """Measured: b86ff49 is 102 commits ahead of tag jq-1.7.1."""

    assert interpret_compare("ahead", 102, 0) == DOES_NOT_CONTAIN_FIX
    assert interpret_compare("behind", 0, 5) == CONTAINS_FIX
    assert interpret_compare("identical", 0, 0) == CONTAINS_FIX
    assert interpret_compare("diverged", 2, 3) == DOES_NOT_CONTAIN_FIX
    assert interpret_compare("behind", 1, 4) == NOT_CHECKABLE
    assert resolve_tag("1.7.1", ("jq-1.7.1",)) == ("jq-1.7.1", "resolved")
    assert resolve_tag("1.7.1", ("jq-1.7.1", "v1.7.1")) == ("", "ambiguous")
    assert resolve_tag("1.7.1", ("jq-1.7.10",)) == ("", "no_tag")


def test_ancestry_demotes_a_version_that_misses_the_fix() -> None:
    relation, status, version, stale = apply_ancestry(
        relation=SAME_BUG,
        claimed_status=FIXED,
        ancestry=DOES_NOT_CONTAIN_FIX,
        stated_version="1.7.1",
    )
    assert relation == RELATED_VARIANT
    assert status == UNKNOWN
    assert version == ""
    assert stale == ("patched_version:1.7.1",)


def test_ancestry_confirms_a_fix_and_does_not_record_an_unchecked_one() -> None:
    relation, status, version, stale = apply_ancestry(
        relation=SAME_BUG,
        claimed_status=FIXED,
        ancestry=CONTAINS_FIX,
        stated_version="1.8.0",
    )
    assert (relation, status, version, stale) == (SAME_BUG, FIXED, "1.8.0", ())
    unchecked = apply_ancestry(
        relation=SAME_BUG,
        claimed_status=FIXED,
        ancestry=NOT_CHECKABLE,
        stated_version="1.8.0",
    )
    assert unchecked[1] == UNKNOWN
    assert unchecked[2] == ""
    assert named_fix_commit(f"fixed by {FIX_42531223}", (FIX_42531223,)) == FIX_42531223
    assert named_fix_commit("fixed by abc", (FIX_42531223,)) == ""


def test_none_field_is_stale_only_when_git_contradicts_it() -> None:
    text = "Patched versions: None"
    assert none_field_is_stale(text, CONTAINS_FIX)
    assert not none_field_is_stale(text, DOES_NOT_CONTAIN_FIX)
    assert not none_field_is_stale(text, NO_FIX_COMMIT)


def test_state_requires_ancestry_for_a_verified_fix() -> None:
    verified = EvidenceView(True, SAME_BUG, FIXED, CONTAINS_FIX, False, True)
    assert decide_state((verified,)) == PUBLICLY_KNOWN_FIXED
    variant = EvidenceView(True, RELATED_VARIANT, UNKNOWN, DOES_NOT_CONTAIN_FIX, False, True)
    assert decide_state((variant,)) == RELATED_VARIANTS_ONLY
    open_issue = EvidenceView(True, SAME_BUG, OPEN, NO_FIX_COMMIT, False, False)
    assert decide_state((open_issue,)) == PUBLICLY_KNOWN_OPEN
    dispute = EvidenceView(True, SAME_BUG, OPEN, NO_FIX_COMMIT, True, False)
    assert decide_state((dispute,)) == SOURCE_DISPUTE
    assert decide_state((dispute, verified)) == PUBLICLY_KNOWN_FIXED
    assert decide_state(()) == NO_PUBLIC_FINDINGS
    unchecked = EvidenceView(True, SAME_BUG, UNKNOWN, NOT_CHECKABLE, False, True)
    assert decide_state((unchecked,)) == PUBLICLY_KNOWN_OPEN
    assert decide_state((unchecked,)) != PUBLICLY_KNOWN_FIXED
    assert "not recorded as the fix" in unverified_fix_note("1.7.1")


def test_sources_note_lists_the_search_and_the_rejections() -> None:
    note = sources_note(
        queries=("jq Stack-buffer-overflow decNaNs",),
        domains=("github.com", "nvd.nist.gov"),
        failed_sources=("extract: timeout",),
        host_rejected=2,
        frame_rejected=4,
        quote_rejected=1,
        unverified_versions=("1.7.1",),
    )
    assert "jq Stack-buffer-overflow decNaNs" in note
    assert "github.com" in note
    assert "extract: timeout" in note
    assert "2 by host" in note
    assert "4 by the frame gate" in note
    assert "1.7.1" in note


def test_draft_line_carries_the_citation_and_rejects_a_reproducer() -> None:
    line = build_draft_line(
        sentence="A public advisory names decNaNs and states 1.7.1.",
        source_url="https://github.com/jqlang/jq/security/advisories/GHSA-7hmr-442f-qc8j",
        source_date="2026-10-05",
        confidence="high",
        forbidden=("BEGIN-REPRODUCER",),
    )
    assert line.source_url in line.text
    assert "2026-10-05" in line.text
    assert "Confidence: high." in line.text
    with pytest.raises(DraftRejected):
        build_draft_line(
            sentence="Input BEGIN-REPRODUCER still crashes.",
            source_url="https://github.com/jqlang/jq/issues/3196",
            source_date="2026-10-05",
            confidence="low",
            forbidden=("BEGIN-REPRODUCER",),
        )


def test_snippet_filter_requires_a_frame_or_the_crash_type() -> None:
    assert snippet_worth_extract(
        "Stack-buffer-overflow somewhere", JQ_FRAMES, "Stack-buffer-overflow"
    )
    assert snippet_worth_extract("called decNaNs", JQ_FRAMES, "Stack-buffer-overflow")
    assert not snippet_worth_extract("unrelated changelog", JQ_FRAMES, "Stack-buffer-overflow")
    assert not snippet_worth_extract("ab", ("ab",), "Heap-buffer-overflow")


def test_open_same_bug_keeps_open_status() -> None:
    assert apply_ancestry(
        relation=SAME_BUG,
        claimed_status=OPEN,
        ancestry=NO_FIX_COMMIT,
        stated_version="",
    ) == (SAME_BUG, OPEN, "", ())
