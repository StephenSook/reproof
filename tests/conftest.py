from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.getenv("REPROOF_LIVE") == "1":
        return
    skip_live = pytest.mark.skip(reason="set REPROOF_LIVE=1 to run paid live tests")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
