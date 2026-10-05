from __future__ import annotations

import pytest

from reproof.models import Verdict
from reproof.triage import _verdict


@pytest.mark.parametrize(
    ("crashed", "fix_clean", "duplicates", "expected"),
    [
        (True, True, 0, Verdict.REPRODUCED),
        (True, True, 1, Verdict.DUPLICATE),
        (False, True, 0, Verdict.NOT_REPRODUCED),
        (False, True, 1, Verdict.NEEDS_INFO),
        (True, False, 0, Verdict.NEEDS_INFO),
        (True, False, 1, Verdict.NEEDS_INFO),
        (False, False, 0, Verdict.NEEDS_INFO),
        (False, False, 1, Verdict.NEEDS_INFO),
    ],
)
def test_verdict_truth_table(
    crashed: bool,
    fix_clean: bool,
    duplicates: int,
    expected: Verdict,
) -> None:
    assert _verdict(crashed, fix_clean, duplicates) is expected
