from __future__ import annotations

import pytest

from reproof.models import Verdict
from reproof.triage import _verdict


@pytest.mark.parametrize(
    ("crashed", "vulnerable_clean", "fix_clean", "duplicates", "expected"),
    [
        (True, False, True, 0, Verdict.REPRODUCED),
        (True, False, True, 1, Verdict.DUPLICATE),
        (False, True, True, 0, Verdict.NOT_REPRODUCED),
        (False, True, True, 1, Verdict.NEEDS_INFO),
        (False, False, True, 0, Verdict.NEEDS_INFO),
        (False, False, True, 1, Verdict.NEEDS_INFO),
        (True, False, False, 0, Verdict.NEEDS_INFO),
        (True, False, False, 1, Verdict.NEEDS_INFO),
        (False, True, False, 0, Verdict.NEEDS_INFO),
        (False, True, False, 1, Verdict.NEEDS_INFO),
    ],
)
def test_verdict_truth_table(
    crashed: bool,
    vulnerable_clean: bool,
    fix_clean: bool,
    duplicates: int,
    expected: Verdict,
) -> None:
    assert _verdict(crashed, vulnerable_clean, fix_clean, duplicates) is expected
