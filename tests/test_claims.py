from __future__ import annotations

from reproof.claims import compare_claim
from reproof.crash import parse_crash
from reproof.models import Claim


def test_claim_comparison_matches_bug_family_and_top_frame() -> None:
    log = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
WRITE of size 1
    #0 0x1234 in parse_item /src/demo.c:3:2
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/demo.c:3 in parse_item
"""
    claim = Claim(
        project="demo",
        bug_class="heap buffer overflow",
        functions=["parse_item(const char *)"],
        files=["demo.c"],
        trigger="input",
        poc_attached=True,
        affected_version="1.0",
        missing_details=[],
    )
    rows = compare_claim(claim, parse_crash(log))
    assert [row.matches for row in rows] == [True, True]


def test_claim_comparison_rejects_different_function() -> None:
    log = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1
READ of size 8
    #0 0x1234 in release_item /src/demo.c:3:2
SUMMARY: AddressSanitizer: heap-use-after-free /src/demo.c:3 in release_item
"""
    claim = Claim(
        project="demo",
        bug_class="heap-use-after-free",
        functions=["parse_item"],
        files=[],
        trigger="input",
        poc_attached=False,
        affected_version="",
        missing_details=["PoC"],
    )
    rows = compare_claim(claim, parse_crash(log))
    assert rows[0].matches
    assert not rows[1].matches
