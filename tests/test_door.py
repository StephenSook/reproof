from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from contree_sdk.sdk.exceptions import NotFoundError

from reproof.claims import PRICE_SOURCE
from reproof.crash import parse_crash
from reproof.door import iter_cached_triage, public_payload, run_cached_triage
from reproof.door_data import (
    ASSETS_DIR,
    DOOR_PROJECTS,
    ProjectIndex,
    load_catalog,
    load_manifest,
    load_project_index,
)
from reproof.dup import OsvIndex, parse_osv_record
from reproof.models import Claim, EvalReport, ModelCall, SandboxOperation, Verdict
from reproof.provenance import source_sha256, text_sha256
from reproof.sandbox import CheckpointError, CheckpointRegistry, SandboxRunner

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "42530604-vul.txt"
EVAL_PATH = ROOT / "eval" / "results" / "arvo10.json"
TASK_ID = 42530604
API_SENTINEL = "SENTINEL-API-KEY-VALUE-XYZ"
PROJECT_SENTINEL = "SENTINEL-PROJECT-ID-VALUE-XYZ"
TASK_HASH = "c" * 64
ARCHIVE_HASH = "a" * 64
MAPPING_HASH = "b" * 64
VUL_SLICE = "d" * 64
FIX_SLICE = "e" * 64


def _raw_record(
    record_id: str,
    project: str,
    issue: int,
    state: tuple[str, ...],
) -> dict[str, object]:
    return {
        "id": record_id,
        "summary": f"summary {record_id}",
        "details": "Crash type: Heap-buffer-overflow\nCrash state:\n" + "\n".join(state) + "\n```",
        "references": [{"url": f"https://issues.oss-fuzz.com/issues/{issue}"}],
        "affected": [
            {
                "package": {"name": project},
                "ranges": [{"type": "GIT", "events": [{"fixed": "abc"}]}],
            }
        ],
    }


def _model_call() -> ModelCall:
    return ModelCall(
        model="nvidia/nemotron-3-super-120b-a12b",
        latency_seconds=0.01,
        input_tokens=10,
        output_tokens=5,
        total_tokens=15,
        input_price_per_million=0.30,
        output_price_per_million=0.90,
        price_source=PRICE_SOURCE,
        cost_usd=0.0000075,
        request_id="test-request",
    )


def _claim() -> Claim:
    return Claim(
        project="jq",
        bug_class="heap-buffer-overflow",
        functions=["decToString"],
        files=[],
        trigger="",
        poc_attached=True,
        affected_version="",
        missing_details=[],
    )


class FakeRunner:
    def __init__(self, stderr: str, *, leak_credentials: bool = False) -> None:
        self.stderr = stderr
        self.leak_credentials = leak_credentials
        self.opened: list[str] = []
        self.ensured = False
        self.ran = False

    def ensure_checkpoint(self, *_args: object, **_kwargs: object) -> None:
        self.ensured = True
        raise AssertionError("ensure_checkpoint must not run")

    def open_checkpoint(self, kind: str, record: dict[str, object]) -> SimpleNamespace:
        self.opened.append(kind)
        return SimpleNamespace(uuid=str(record["checkpoint_uuid"]))

    def run_pair(
        self,
        task_id: int,
        vulnerable_checkpoint: SimpleNamespace,
        fixed_checkpoint: SimpleNamespace,
        candidate_input: bytes | None = None,
    ) -> tuple[SandboxOperation, SandboxOperation]:
        self.ran = True
        if candidate_input is not None:
            raise AssertionError("cached triage must not upload a new input")
        if self.leak_credentials:
            raise RuntimeError(os.environ["NEBIUS_API_KEY"] + " " + os.environ["NEBIUS_PROJECT_ID"])
        checkpoints = {"vul": vulnerable_checkpoint, "fix": fixed_checkpoint}
        costs = {"vul": 0.00001, "fix": 0.00002}
        exits = {"vul": 1, "fix": 0}
        stderrs = {"vul": self.stderr, "fix": ""}
        checkpoint_costs = {"vul": 0.000061, "fix": 0.000062}

        def operation(kind: str) -> SandboxOperation:
            return SandboxOperation(
                task_id=task_id,
                kind=kind,
                checkpoint_uuid=str(checkpoints[kind].uuid),
                checkpoint_operation_uuid=f"test-{kind}-checkpoint-operation",
                checkpoint_wall_seconds=0.5,
                checkpoint_cost_usd=checkpoint_costs[kind],
                operation_uuid=f"test-{kind}-operation",
                exit_code=exits[kind],
                stdout="",
                stderr=stderrs[kind],
                wall_seconds=0.2,
                server_elapsed_seconds=0.2,
                cost_usd=costs[kind],
                disposable=True,
            )

        return operation("vul"), operation("fix")


def _world(stderr: str, *, leak_credentials: bool = False) -> dict[str, object]:
    crash = parse_crash(stderr)
    records = [
        parse_osv_record(_raw_record("OSV-SELF", "jq", TASK_ID, crash.state)),
        parse_osv_record(_raw_record("OSV-OTHER", "jq", 999, crash.state)),
    ]
    parsed = [record for record in records if record is not None]
    assert [record.id for record in parsed] == ["OSV-SELF", "OSV-OTHER"]
    report_text = parsed[0].report_text
    catalog = {
        "tasks": [
            {
                "arvo_id": TASK_ID,
                "project": "jq",
                "osv_record_id": "OSV-SELF",
                "report_source": (
                    "public OSS-Fuzz OSV report OSV-SELF; this is not a private report"
                ),
                "report_sha256": text_sha256(report_text),
                "report_text": report_text,
                "arvo_task_sha256": TASK_HASH,
            }
        ]
    }
    manifest = {
        "tasks": {
            str(TASK_ID): {
                "vul": {
                    "checkpoint_uuid": "checkpoint-vul",
                    "manifest_sha256": VUL_SLICE,
                    "create_operation_uuid": "test-vul-checkpoint-operation",
                    "checkpoint_wall_seconds": 0.5,
                    "checkpoint_cost_usd": 0.000061,
                },
                "fix": {
                    "checkpoint_uuid": "checkpoint-fix",
                    "manifest_sha256": FIX_SLICE,
                    "create_operation_uuid": "test-fix-checkpoint-operation",
                    "checkpoint_wall_seconds": 0.5,
                    "checkpoint_cost_usd": 0.000062,
                },
            }
        }
    }
    return {
        "catalog": catalog,
        "manifest": manifest,
        "index": ProjectIndex(
            index=OsvIndex(parsed, {}),
            archive_sha256=ARCHIVE_HASH,
            mapping_sha256=MAPPING_HASH,
            projects=("jq",),
        ),
        "runner": FakeRunner(stderr, leak_credentials=leak_credentials),
        "calls": [],
    }


def _run(world: dict[str, object]) -> object:
    calls: list[str] = world["calls"]  # type: ignore[assignment]

    def extractor(report_text: str) -> tuple[Claim, ModelCall]:
        calls.append(report_text)
        return _claim(), _model_call()

    return run_cached_triage(
        TASK_ID,
        catalog=world["catalog"],  # type: ignore[arg-type]
        manifest=world["manifest"],  # type: ignore[arg-type]
        project_index=world["index"],  # type: ignore[arg-type]
        runner=world["runner"],  # type: ignore[arg-type]
        extractor=extractor,
    )


def test_missing_checkpoint_returns_needs_info_without_calls() -> None:
    stderr = FIXTURE.read_text(encoding="utf-8")
    world = _world(stderr)
    manifest = world["manifest"]
    assert isinstance(manifest, dict)
    manifest["tasks"][str(TASK_ID)]["vul"]["checkpoint_uuid"] = ""
    result = _run(world)
    runner = world["runner"]
    assert isinstance(runner, FakeRunner)
    assert result.verdict is Verdict.NEEDS_INFO
    assert result.card is None
    assert "checkpoint" in result.reason
    assert "local slice" in result.reason
    assert world["calls"] == []
    assert runner.opened == []
    assert runner.ensured is False
    assert runner.ran is False


def test_unknown_task_returns_needs_info_without_calls() -> None:
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    calls: list[str] = []

    def extractor(report_text: str) -> tuple[Claim, ModelCall]:
        calls.append(report_text)
        return _claim(), _model_call()

    result = run_cached_triage(
        1,
        catalog=world["catalog"],  # type: ignore[arg-type]
        manifest=world["manifest"],  # type: ignore[arg-type]
        project_index=world["index"],  # type: ignore[arg-type]
        runner=world["runner"],  # type: ignore[arg-type]
        extractor=extractor,
    )
    assert result.verdict is Verdict.NEEDS_INFO
    assert result.card is None
    assert "local slice" in result.reason
    assert calls == []


def test_excluded_ids_are_not_duplicate_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    events = list(
        iter_cached_triage(
            TASK_ID,
            catalog=world["catalog"],  # type: ignore[arg-type]
            manifest=world["manifest"],  # type: ignore[arg-type]
            project_index=world["index"],  # type: ignore[arg-type]
            runner=world["runner"],  # type: ignore[arg-type]
            extractor=lambda _report: (_claim(), _model_call()),
        )
    )
    step_events = [event["step"] for event in events if event["type"] == "step"]
    steps = [event["step"] for event in step_events]
    assert steps == ["claim", "sandbox", "sandbox", "crash", "duplicates", "verdict"]
    sandbox_steps = [event for event in step_events if event["step"] == "sandbox"]
    assert [step["kind"] for step in sandbox_steps] == ["vul", "fix"]
    assert sandbox_steps[0]["payload"]["operation_uuid"] == "test-vul-operation"
    duplicates = next(event for event in step_events if event["step"] == "duplicates")
    assert duplicates["payload"]["excluded_osv_ids"] == ["OSV-SELF"]
    assert [candidate["id"] for candidate in duplicates["payload"]["candidates"]] == ["OSV-OTHER"]
    result = _run(world)
    assert result.card is not None
    assert result.verdict is Verdict.DUPLICATE
    candidate_ids = [candidate.id for candidate in result.card.evidence.duplicate_candidates]
    assert "OSV-SELF" not in candidate_ids
    assert candidate_ids == ["OSV-OTHER"]
    assert result.card.evidence.excluded_osv_ids == ["OSV-SELF"]
    assert result.card.provenance.execution_source_sha256 == source_sha256()
    assert result.card.provenance.derivation_method == "live-execution"
    assert not (tmp_path / "slices").exists()


def test_public_payload_omits_credential_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEBIUS_API_KEY", API_SENTINEL)
    monkeypatch.setenv("NEBIUS_PROJECT_ID", PROJECT_SENTINEL)
    leaked = _world(FIXTURE.read_text(encoding="utf-8"), leak_credentials=True)
    failed = _run(leaked)
    failed_text = json.dumps(public_payload(failed), sort_keys=True)
    assert API_SENTINEL not in failed_text
    assert PROJECT_SENTINEL not in failed_text
    assert "[redacted]" in failed.reason
    assert failed.card is None

    clean = _world(FIXTURE.read_text(encoding="utf-8"))
    succeeded = _run(clean)
    succeeded_text = json.dumps(public_payload(succeeded), sort_keys=True)
    assert API_SENTINEL not in succeeded_text
    assert PROJECT_SENTINEL not in succeeded_text
    assert "NEBIUS_API_KEY" not in succeeded_text
    assert "NEBIUS_PROJECT_ID" not in succeeded_text


def test_open_checkpoint_missing_uuid_does_not_call_the_client() -> None:
    calls: list[str] = []

    def use(*_args: object, **_kwargs: object) -> None:
        calls.append("use")
        raise AssertionError("client was called")

    runner = SandboxRunner(client=SimpleNamespace(images=SimpleNamespace(use=use)))  # type: ignore[arg-type]
    with pytest.raises(CheckpointError, match="local slice"):
        runner.open_checkpoint("fix", {})
    assert calls == []


def test_open_checkpoint_not_found_does_not_rebuild(tmp_path: Path) -> None:
    registry = CheckpointRegistry(tmp_path / "checkpoints.json")
    registry.write({"keep": {"checkpoint_uuid": "stay"}})
    calls: list[str] = []

    def use(reference: str, strict: bool = True) -> None:
        assert strict is True
        calls.append(reference)
        raise NotFoundError(error="missing")

    runner = SandboxRunner(
        client=SimpleNamespace(images=SimpleNamespace(use=use)),  # type: ignore[arg-type]
        registry=registry,
    )
    with pytest.raises(CheckpointError, match="local slice"):
        runner.open_checkpoint(
            "vul",
            {
                "checkpoint_uuid": "missing-uuid",
                "create_operation_uuid": "create-op",
                "checkpoint_wall_seconds": 0.5,
                "checkpoint_cost_usd": 0.0001,
            },
        )
    assert calls == ["missing-uuid"]
    assert registry.read() == {"keep": {"checkpoint_uuid": "stay"}}


def test_committed_door_assets_match_the_eval() -> None:
    report = EvalReport.model_validate_json(EVAL_PATH.read_text(encoding="utf-8"))
    manifest = load_manifest()
    catalog = load_catalog()
    index = load_project_index()
    assert set(manifest["tasks"]) == {str(task_id) for task_id in report.selected_arvo_ids}
    assert index.archive_sha256 == report.provenance.osv_archive_sha256
    assert index.mapping_sha256 == report.provenance.monorail_mapping_sha256
    assert index.projects == tuple(sorted(DOOR_PROJECTS))
    by_id = {task.arvo_id: task for task in report.tasks}
    for row in catalog["tasks"]:
        task = by_id[row["arvo_id"]]
        assert row["report_sha256"] == text_sha256(row["report_text"])
        assert row["report_sha256"] == task.card_provenance.report_sha256
        assert row["osv_record_id"] == task.card_provenance.osv_record_id
        checkpoint = manifest["tasks"][str(task.arvo_id)]
        for kind in ("vul", "fix"):
            assert checkpoint[kind]["manifest_sha256"] == task.slice_manifest_sha256[kind]
            assert checkpoint[kind]["checkpoint_uuid"]
        excluded = {record.id for record in index.index.for_issue(task.arvo_id)}
        assert task.card_provenance.osv_record_id in excluded
        assert excluded.isdisjoint(task.duplicate_candidates)
    for name in ("checkpoints.json", "catalog.json", "osv_projects.json"):
        path = ASSETS_DIR / name
        assert path.is_file()
        completed = subprocess.run(
            ["git.exe", "check-ignore", "-q", "--", f"reproof/assets/{name}"],
            cwd=ROOT,
            check=False,
        )
        assert completed.returncode == 1
