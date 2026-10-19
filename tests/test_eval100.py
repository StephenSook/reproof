from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from reproof.eval100 import (
    ARVO10_PROJECTS,
    Eval100InputPaths,
    load_eval100_selection,
    select_eval100,
)
from reproof.provenance import file_sha256

PREREG = Path("eval/eval100_prereg.json")
EXPECTED_NEW_IDS = (
    42477302,
    42481221,
    42523942,
    42481224,
    42481945,
    42525192,
    42520614,
    42504114,
    42497241,
    42500367,
    42518269,
    42471044,
    42522233,
    42504387,
    42501162,
    42532259,
    42486565,
    42470538,
    42513620,
    42471105,
    42501200,
    42471108,
    42475782,
    42481193,
    42498970,
    42477222,
    42496936,
    42475195,
    42499827,
    42510753,
    42501143,
    42474141,
    42533590,
    42517374,
    42490025,
    42517725,
    42476618,
    42496031,
    42522531,
    42488737,
    42483517,
    42477355,
    42513189,
    42522285,
    42517205,
    42513988,
    420198855,
    42479852,
    42532046,
    42509841,
    42534483,
    42517450,
    42499939,
    42517796,
    42525816,
    42523860,
    396777457,
    42512228,
    42498959,
    42522804,
    42501136,
    42507220,
    379418968,
    42517530,
    42517784,
    42481233,
    42532885,
    42498712,
    42536328,
    42488172,
    411460530,
    42501148,
    42528883,
    42513361,
    42526388,
    42513154,
    42481492,
    42532225,
    42471287,
    42487660,
    42523626,
    42479408,
    42487077,
    42499964,
    42497297,
    42523506,
    42527431,
    42533290,
    42530151,
    42536751,
)


def test_committed_fixture_reproduces_the_registered_draw() -> None:
    selection = load_eval100_selection(PREREG)
    assert selection.selected_new_arvo_ids == EXPECTED_NEW_IDS
    assert selection.walked == 159
    assert selection.skipped == {"over_size_cap": 31, "project_cap": 38}
    assert len(selection.population) == 927
    assert len(selection.draw_order) == 927
    assert len(selection.selected_arvo_ids) == 100


def test_selected_tasks_obey_size_and_combined_project_caps() -> None:
    selection = load_eval100_selection(PREREG)
    by_id = selection.population_by_id
    project_counts = Counter(ARVO10_PROJECTS.values())
    for task_id in selection.selected_new_arvo_ids:
        row = by_id[task_id]
        assert row.vul_bytes is not None
        assert row.fix_bytes is not None
        assert max(row.vul_bytes, row.fix_bytes) <= 1_500_000_000
        project_counts[row.project] += 1
        assert project_counts[row.project] <= 3
    assert len({by_id[task_id].project for task_id in selection.selected_new_arvo_ids}) == 48


def _local_prereg(tmp_path: Path) -> tuple[Path, Eval100InputPaths]:
    raw = json.loads(PREREG.read_text(encoding="utf-8"))
    fixture = Path(raw["inputs"]["population_fixture"]["path"]).resolve()
    raw["inputs"]["population_fixture"]["path"] = str(fixture)
    paths = Eval100InputPaths(
        arvo_database=tmp_path / "arvo.db",
        osv_archive=tmp_path / "osv.zip",
        monorail_mapping=tmp_path / "mapping.csv",
    )
    named = {
        "arvo_database": paths.arvo_database,
        "osv_archive": paths.osv_archive,
        "monorail_mapping": paths.monorail_mapping,
    }
    for name, path in named.items():
        path.write_text(f"{name}\n", encoding="utf-8")
        raw["inputs"][name]["sha256"] = file_sha256(path)
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps(raw), encoding="utf-8")
    return prereg, paths


def test_select_eval100_verifies_all_inputs_without_large_ci_files(tmp_path: Path) -> None:
    prereg, paths = _local_prereg(tmp_path)
    selection = select_eval100(prereg, inputs=paths)
    assert selection.selected_new_arvo_ids == EXPECTED_NEW_IDS


@pytest.mark.parametrize("changed", ["arvo_database", "osv_archive", "monorail_mapping"])
def test_select_eval100_refuses_an_input_hash_mismatch(tmp_path: Path, changed: str) -> None:
    prereg, paths = _local_prereg(tmp_path)
    path = getattr(paths, changed)
    path.write_text("changed after preregistration\n", encoding="utf-8")
    with pytest.raises(ValueError, match=rf"{changed} sha256 mismatch"):
        select_eval100(prereg, inputs=paths)


def test_selection_refuses_a_fixture_hash_mismatch(tmp_path: Path) -> None:
    raw = json.loads(PREREG.read_text(encoding="utf-8"))
    source = Path(raw["inputs"]["population_fixture"]["path"])
    fixture = tmp_path / "population.tsv"
    fixture.write_bytes(source.read_bytes() + b"\n")
    raw["inputs"]["population_fixture"]["path"] = str(fixture)
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="population fixture sha256 mismatch"):
        load_eval100_selection(prereg)
