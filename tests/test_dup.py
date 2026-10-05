from __future__ import annotations

import json
import zipfile
from pathlib import Path

from reproof.crash import parse_crash
from reproof.dup import OsvIndex, frames_match, parse_osv_record


def raw_record(
    record_id: str,
    project: str,
    issue: int,
    state: tuple[str, ...],
    fixed: tuple[str, ...] = (),
) -> dict[str, object]:
    events = [{"fixed": commit} for commit in fixed]
    return {
        "id": record_id,
        "summary": f"summary {record_id}",
        "details": "Crash type: Heap-buffer-overflow READ 1\nCrash state:\n"
        + "\n".join(state)
        + "\n```",
        "references": [{"url": f"https://issues.oss-fuzz.com/issues/{issue}"}],
        "affected": [
            {
                "package": {"name": project},
                "ranges": [{"type": "GIT", "events": events}],
            }
        ],
    }


def test_exact_inline_and_required_non_match() -> None:
    ours = ("decToString", "decNumberToString", "jvp_literal_number_literal")
    groups = {
        "jvp_literal_number_literal": frozenset(
            {"jvp_literal_number_literal", "jv_number_get_literal"}
        )
    }
    assert frames_match(ours, ours)
    assert frames_match(ours, ("decToString", "decNumberToString", "jv_number_get_literal"), groups)
    assert not frames_match(ours, ("decToString", "decNumberToString", "jv_dump_term"), groups)
    assert not frames_match(ours, tuple(reversed(ours)), groups)
    assert not frames_match(ours, ours[:2], groups)
    assert not frames_match((), ())


def test_parse_fixed_commits_preserves_zero_one_and_many() -> None:
    no_fix = parse_osv_record(raw_record("OSV-1", "p", 1, ("a",)))
    one_fix = parse_osv_record(raw_record("OSV-2", "p", 2, ("a",), ("abc",)))
    many = parse_osv_record(raw_record("OSV-3", "p", 3, ("a",), ("abc", "def", "abc")))
    assert no_fix is not None and no_fix.fixed_commits == ()
    assert one_fix is not None and one_fix.fixed_commits == ("abc",)
    assert many is not None and many.fixed_commits == ("abc", "def")


def test_index_returns_all_same_project_candidates(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "42530604-vul.txt"
    crash = parse_crash(fixture.read_text(encoding="utf-8"))
    records = [
        parse_osv_record(raw_record("OSV-1", "jq", 64574, crash.state, ("a",))),
        parse_osv_record(
            raw_record(
                "OSV-2",
                "jq",
                64575,
                ("decToString", "decNumberToString", "jv_number_get_literal"),
                ("b", "c"),
            )
        ),
        parse_osv_record(raw_record("OSV-3", "other", 64576, crash.state)),
    ]
    index = OsvIndex([record for record in records if record is not None], {64574: 42530604})
    candidates = index.find_candidates("jq", crash, excluded_osv_ids=[])
    assert [(candidate.id, candidate.match_kind) for candidate in candidates] == [
        ("OSV-1", "exact"),
        ("OSV-2", "inline_tolerant"),
    ]
    assert [record.id for record in index.for_issue(42530604)] == ["OSV-1"]

    archive = tmp_path / "osv.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("OSV-1.json", json.dumps(raw_record("OSV-1", "jq", 64574, crash.state)))
    mapping = tmp_path / "mapping.csv"
    mapping.write_text("64574,42530604\n", encoding="utf-8")
    rebuilt = OsvIndex.from_archive(archive, mapping)
    assert rebuilt.for_issue(42530604)[0].report_text.startswith("summary OSV-1")


def test_index_excludes_current_issue_records_but_keeps_independent_match() -> None:
    fixture = Path(__file__).parent / "fixtures" / "42530604-vul.txt"
    crash = parse_crash(fixture.read_text(encoding="utf-8"))
    records = [
        parse_osv_record(raw_record("OSV-SELF-1", "jq", 64574, crash.state)),
        parse_osv_record(raw_record("OSV-SELF-2", "jq", 64574, crash.state)),
        parse_osv_record(raw_record("OSV-INDEPENDENT", "jq", 64575, crash.state)),
    ]
    index = OsvIndex([record for record in records if record is not None], {64574: 42530604})
    excluded_osv_ids = [record.id for record in index.for_issue(42530604)]

    candidates = index.find_candidates(
        "jq",
        crash,
        excluded_osv_ids=excluded_osv_ids,
    )

    assert excluded_osv_ids == ["OSV-SELF-1", "OSV-SELF-2"]
    assert [candidate.id for candidate in candidates] == ["OSV-INDEPENDENT"]


def test_index_does_not_match_unsanitized_fatal_state() -> None:
    crash = parse_crash(
        "==1== ERROR: libFuzzer: deadly signal\n"
        "    #0 0x1234 in parse_item /src/demo.c:3:2\n"
        "SUMMARY: libFuzzer: deadly signal\n"
    )
    record = parse_osv_record(raw_record("OSV-1", "demo", 1, crash.state))
    assert record is not None
    index = OsvIndex([record], {1: 1})

    assert crash.state == ("parse_item",)
    assert not crash.crashed
    assert index.find_candidates("demo", crash, excluded_osv_ids=["OSV-1"]) == []
