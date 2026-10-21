from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from reproof.crash import parse_crash
from reproof.door import PublicLookupRequest, _public_request, run_cached_triage, task_repository
from reproof.door_data import ASSETS_DIR, load_catalog, load_manifest, load_project_index
from reproof.door_prepared import (
    NEVER_COMPLETED,
    NO_CRASH,
    NO_PAIR,
    OFFERED_VERDICTS,
    PREPARED_CATALOG,
    PREPARED_CHECKPOINTS,
    PREPARED_OSV,
    RUN1_PATH,
    RUN2_PATH,
    _failure_note,
    load_door_catalog,
    load_door_manifest,
    load_door_project_index,
    load_prepared_catalog,
    merge_project_indexes,
)
from reproof.dup import OsvIndex
from reproof.models import (
    Claim,
    Eval100Report,
    EvalRunFailure,
    ModelCall,
    PublicStatus,
    SandboxOperation,
    TriageCard,
)
from reproof.provenance import file_sha256, text_sha256

ROOT = Path(__file__).resolve().parents[1]
# 53 tasks met the rule when the assets were built on 2026-10-21. The floor stops a build that
# walked nothing from passing as a clean, smaller catalog.
OFFERED_FLOOR = 53


def _report(path: str) -> Eval100Report:
    return Eval100Report.model_validate_json((ROOT / path).read_text(encoding="utf-8"))


def _card(path: str) -> TriageCard:
    return TriageCard.model_validate_json((ROOT / path).read_text(encoding="utf-8"))


def test_every_eval100_draw_task_is_offered_or_has_a_reason() -> None:
    run2 = _report(RUN2_PATH)
    prepared = load_prepared_catalog()
    offered = [int(row["arvo_id"]) for row in prepared["tasks"]]
    refused = [int(row["arvo_id"]) for row in prepared["not_offered"]]
    assert len(offered) >= OFFERED_FLOOR
    assert sorted(offered + refused) == sorted(run2.random_draw_arvo_ids)
    assert not set(offered) & set(run2.historical_arvo_ids)
    assert {row["reason"] for row in prepared["not_offered"]} <= {
        NO_PAIR,
        NEVER_COMPLETED,
        NO_CRASH,
    }
    assert all(row["detail"].endswith(".") for row in prepared["not_offered"])
    assert prepared["sources"] == {
        RUN2_PATH: file_sha256(ROOT / RUN2_PATH),
        RUN1_PATH: file_sha256(ROOT / RUN1_PATH),
    }
    for name in (PREPARED_CATALOG, PREPARED_CHECKPOINTS, PREPARED_OSV):
        completed = subprocess.run(
            ["git", "check-ignore", "-q", "--", f"reproof/assets/{name}"], cwd=ROOT, check=False
        )
        assert completed.returncode == 1


def test_no_crash_rows_are_the_eval_rows_without_a_crash() -> None:
    run2 = _report(RUN2_PATH)
    by_id = {task.arvo_id: task for task in run2.tasks}
    prepared = load_prepared_catalog()
    no_crash = [row for row in prepared["not_offered"] if row["reason"] == NO_CRASH]
    assert no_crash
    for row in no_crash:
        task = by_id[row["arvo_id"]]
        assert task.verdict not in OFFERED_VERDICTS
        assert f"exited {task.vulnerable_exit_code}" in row["detail"]
    thirty_two_bit = [row for row in no_crash if "ELFCLASS64" in row["detail"]]
    # README and FACTS: 6 of run 2's 7 NEEDS_INFO tasks are 32-bit targets.
    assert len(thirty_two_bit) == 6


def test_committed_prepared_assets_match_their_cards() -> None:
    prepared = load_prepared_catalog()
    manifest = load_manifest(ASSETS_DIR / PREPARED_CHECKPOINTS)
    index = load_door_project_index()
    assert set(manifest["tasks"]) == {str(row["arvo_id"]) for row in prepared["tasks"]}
    for row in prepared["tasks"]:
        raw = json.loads((ROOT / row["recorded_in"]).read_text(encoding="utf-8"))
        recorded = next(task for task in raw["tasks"] if task["arvo_id"] == row["arvo_id"])
        assert row["recorded"] == recorded
        assert row["recorded"]["verdict"] in {verdict.value for verdict in OFFERED_VERDICTS}
        card = _card(recorded["card_path"])
        assert card.verdict.value == recorded["verdict"]
        assert row["report_text"] == card.report_text
        assert row["report_source"] == card.report_source
        assert row["report_sha256"] == text_sha256(row["report_text"])
        assert row["report_sha256"] == card.provenance.report_sha256
        assert row["osv_record_id"] == card.provenance.osv_record_id
        assert row["arvo_task_sha256"] == card.provenance.arvo_task_sha256
        checkpoint = manifest["tasks"][str(row["arvo_id"])]
        for operation in card.sandbox_operations:
            block = checkpoint[operation.kind]
            assert block["checkpoint_uuid"] == operation.checkpoint_uuid
            assert block["create_operation_uuid"] == operation.checkpoint_operation_uuid
            assert block["manifest_sha256"] == card.slice_manifest_sha256[operation.kind]
        excluded = sorted(record.id for record in index.index.for_issue(row["arvo_id"]))
        assert excluded == sorted(card.evidence.excluded_osv_ids)
        vulnerable = next(item for item in card.sandbox_operations if item.kind == "vul")
        found = index.index.find_candidates(
            row["project"], parse_crash(vulnerable.stderr), excluded_osv_ids=excluded
        )
        assert [candidate.id for candidate in found] == recorded["duplicate_candidates"]


class ReplayRunner:
    """Answers run_pair with the operations a committed card recorded."""

    def __init__(self, card: TriageCard) -> None:
        self.card = card
        self.opened: dict[str, str] = {}

    def open_checkpoint(self, kind: str, record: dict[str, object]) -> SimpleNamespace:
        self.opened[kind] = str(record["checkpoint_uuid"])
        return SimpleNamespace(uuid=str(record["checkpoint_uuid"]))

    def run_pair(
        self,
        task_id: int,
        vulnerable_checkpoint: SimpleNamespace,
        fixed_checkpoint: SimpleNamespace,
    ) -> tuple[SandboxOperation, SandboxOperation]:
        assert task_id == self.card.arvo_id
        by_kind = {operation.kind: operation for operation in self.card.sandbox_operations}
        assert vulnerable_checkpoint.uuid == by_kind["vul"].checkpoint_uuid
        assert fixed_checkpoint.uuid == by_kind["fix"].checkpoint_uuid
        return by_kind["vul"], by_kind["fix"]


def _extractor(card: TriageCard) -> Callable[[str], tuple[Claim, ModelCall]]:
    claimed = {row.field: row.claimed for row in card.evidence.claim_vs_evidence}
    functions = claimed.get("functions", [])

    def extract(_text: str) -> tuple[Claim, ModelCall]:
        claim = Claim(
            project=card.project,
            bug_class=str(claimed.get("bug_class", "")),
            functions=list(functions) if isinstance(functions, list) else [functions],
            files=[],
            trigger="",
            poc_attached=True,
            affected_version="",
            missing_details=[],
        )
        return claim, card.model_calls[0]

    return extract


def _no_lookup(_request: PublicLookupRequest) -> PublicStatus:
    return PublicStatus(
        state="LOOKUP_UNAVAILABLE",
        evidence=[],
        queries_sent=[],
        query_source="",
        domains=[],
        failed_sources=[],
        note="replay",
        tavily_request_ids=[],
        tavily_calls=[],
        model_calls=[],
        draft=[],
    )


def test_every_offered_task_replays_its_recorded_verdict_through_the_door() -> None:
    """The committed door assets alone turn each recorded run into the recorded verdict."""

    prepared = load_prepared_catalog()
    manifest = load_door_manifest()
    for row in prepared["tasks"]:
        card = _card(row["recorded"]["card_path"])
        runner = ReplayRunner(card)
        result = run_cached_triage(
            row["arvo_id"],
            runner=runner,  # type: ignore[arg-type]
            extractor=_extractor(card),
            public_lookup=_no_lookup,
        )
        assert result.verdict == card.verdict, row["arvo_id"]
        assert result.card is not None
        assert [item.id for item in result.card.evidence.duplicate_candidates] == (
            row["recorded"]["duplicate_candidates"]
        )
        assert result.card.evidence.excluded_osv_ids == card.evidence.excluded_osv_ids
        assert result.card.slice_manifest_sha256 == card.slice_manifest_sha256
        expected = manifest["tasks"][str(row["arvo_id"])]
        assert runner.opened == {kind: expected[kind]["checkpoint_uuid"] for kind in ("vul", "fix")}


def test_the_door_catalog_is_the_featured_ten_then_the_prepared_tasks() -> None:
    featured = load_catalog()["tasks"]
    door = load_door_catalog()["tasks"]
    assert door[: len(featured)] == featured
    assert door[len(featured) :] == load_prepared_catalog()["tasks"]
    assert set(load_door_manifest()["tasks"]) == {str(row["arvo_id"]) for row in door}
    index = load_door_project_index()
    assert set(load_project_index().projects) <= set(index.projects)
    assert {row["project"] for row in door} <= set(index.projects)


def test_a_repeated_arvo_id_is_refused(tmp_path: Path) -> None:
    for name in ("catalog.json", "checkpoints.json"):
        (tmp_path / name).write_bytes((ASSETS_DIR / name).read_bytes())
    featured = load_catalog()["tasks"]
    (tmp_path / PREPARED_CATALOG).write_text(json.dumps({"tasks": [featured[0]]}), encoding="utf-8")
    with pytest.raises(ValueError, match="repeats"):
        load_door_catalog(tmp_path)
    first = next(iter(load_manifest()["tasks"]))
    (tmp_path / PREPARED_CHECKPOINTS).write_text(
        json.dumps({"tasks": {first: {}}}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="repeats"):
        load_door_manifest(tmp_path)


def test_indexes_from_different_archives_are_not_merged() -> None:
    base = load_project_index()
    other = SimpleNamespace(
        index=OsvIndex([]), archive_sha256="0" * 64, mapping_sha256=base.mapping_sha256, projects=()
    )
    with pytest.raises(ValueError, match="different OSV archives"):
        merge_project_indexes(base, other)  # type: ignore[arg-type]


def test_a_prepared_row_names_its_own_repository_and_a_featured_row_uses_the_map() -> None:
    assert task_repository({"project": "jq"}) == ("jqlang", "jq", "https://jqlang.github.io/jq")
    assert task_repository({"project": "libgit2", "owner": "libgit2", "repo": "libgit2"}) == (
        "libgit2",
        "libgit2",
        "",
    )
    # An OSV record with no github.com range keeps an empty owner, so GitHub pages are refused.
    assert task_repository({"project": "libavc", "owner": "", "repo": ""}) == ("", "", "")
    index = load_door_project_index()
    request = _public_request(
        project="libgit2",
        crash_type="Heap-buffer-overflow",
        frames=("frame_one",),
        arvo_id=1,
        index=index,
        repository=("libgit2", "libgit2", ""),
    )
    assert (request.owner, request.repo, request.project_site) == ("libgit2", "libgit2", "")


def test_prepared_rows_without_github_are_the_ones_without_a_github_range() -> None:
    prepared = load_prepared_catalog()
    prereg = json.loads((ROOT / "eval/public_status_prereg_100.json").read_text(encoding="utf-8"))
    by_id = {row["task_id"]: row for row in prereg["tasks"]}
    for row in prepared["tasks"]:
        planned = by_id[row["arvo_id"]]
        if planned["osv_record_id"] == row["osv_record_id"]:
            assert (row["owner"], row["repo"]) == (planned["owner"], planned["repo"])


def test_a_run_failure_note_names_its_step() -> None:
    failure = EvalRunFailure.model_validate(
        {
            "arvo_id": 1,
            "project": "p",
            "attempts": 1,
            "error_type": "TriageExecutionError",
            "error": "x: CheckpointError: ConTree checkpoint creation failed: status=500, error",
            "request_ids": [],
            "operation_uuids": {},
            "checkpoint_uuids": {},
            "checkpoint_operation_uuids": {},
            "attempt_evidence": [
                {
                    "arvo_id": 1,
                    "project": "p",
                    "attempt": 1,
                    "error_type": "TriageExecutionError",
                    "error": "e",
                    "request_ids": [],
                    "operation_uuids": {},
                    "checkpoint_uuids": {},
                    "checkpoint_operation_uuids": {},
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "model_cost_usd": 0,
                    "sandbox_cost_usd": 0,
                    "cost_usd": 0,
                    "wall_seconds": 0,
                }
            ],
        }
    )
    assert _failure_note(failure, "run 2") == (
        "run 2: checkpoint creation failed with HTTP 500 from ConTree"
    )
    assert _failure_note(None, "run 1") == "run 1 did not attempt it"


PREVIEW_STEM = ROOT / "eval/results/door-preview-42475195"


def test_the_live_preview_triage_of_a_prepared_task_matches_its_eval_row() -> None:
    """One paid triage of a newly offered report through the deployed preview, byte for byte."""

    from hashlib import sha256

    from reproof.door import DoorResult, DoorStep

    receipt = json.loads(PREVIEW_STEM.with_suffix(".json").read_text(encoding="utf-8"))
    raw = PREVIEW_STEM.with_suffix(".ndjson").read_bytes()
    assert receipt["ndjson_sha256"] == sha256(raw).hexdigest()
    assert receipt["http_status"] == 200
    lines = [json.loads(line) for line in raw.decode("utf-8").split("\n") if line.strip()]
    assert receipt["events"] == lines
    for name in ("NEBIUS_API_KEY", "NEBIUS_PROJECT_ID", "TAVILY_API_KEY", "_vercel_share"):
        assert name not in raw.decode("utf-8")
        assert name not in json.dumps(receipt)
    for event in lines[:-1]:
        DoorStep.model_validate(event["step"])
    result = DoorResult.model_validate(lines[-1]["result"])
    row = next(task for task in load_prepared_catalog()["tasks"] if task["arvo_id"] == 42475195)
    assert receipt["request_body"] == {"arvo_id": row["arvo_id"]}
    assert result.card is not None
    assert result.verdict.value == row["recorded"]["verdict"]
    assert [item.id for item in result.card.evidence.duplicate_candidates] == (
        row["recorded"]["duplicate_candidates"]
    )
    expected = load_door_manifest()["tasks"][str(row["arvo_id"])]
    assert {op.kind: op.checkpoint_uuid for op in result.card.sandbox_operations} == {
        kind: expected[kind]["checkpoint_uuid"] for kind in ("vul", "fix")
    }
