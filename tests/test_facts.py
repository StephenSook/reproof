from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
FACTS = ROOT / "FACTS.md"
JSON_SOURCE = re.compile(r"`(?P<path>[^`]+\.json)#(?P<key>[^`]+)`")
KEY_PART = re.compile(r"(?P<name>[^\[\]]+)(?P<indexes>(?:\[\d+\])*)")
INDEX = re.compile(r"\[(\d+)\]")


def _rows() -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for line in FACTS.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = tuple(cell.strip() for cell in line.strip("|").split("|"))
        if len(cells) == 4 and cells[3] == "MEASURED":
            rows.append(cells)
    return rows


def _read_key(document: Any, key: str) -> Any:
    value = document
    for part in key.split("."):
        match = KEY_PART.fullmatch(part)
        assert match is not None, f"invalid fact key: {key}"
        assert isinstance(value, dict), f"{part} does not follow an object in {key}"
        value = value[match.group("name")]
        for raw_index in INDEX.findall(match.group("indexes")):
            assert isinstance(value, list), f"index does not follow a list in {key}"
            value = value[int(raw_index)]
    return value


def _display(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def _literal(cell: str) -> str:
    assert cell.startswith("`") and cell.endswith("`"), f"fact value is not literal: {cell}"
    return cell[1:-1]


def test_measured_json_facts_match_sources() -> None:
    checked = 0
    for claim, exact, source, _tag in _rows():
        for match in JSON_SOURCE.finditer(source):
            path = ROOT / match.group("path")
            document = json.loads(path.read_text(encoding="utf-8"))
            actual = _display(_read_key(document, match.group("key")))
            assert actual == _literal(exact), f"FACTS.md drift for {claim}: {actual}"
            checked += 1
    assert checked >= 30
