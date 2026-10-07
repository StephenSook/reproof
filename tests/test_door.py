from __future__ import annotations

import functools
import itertools
import json
import os
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from contree_sdk.sdk.exceptions import NotFoundError

from reproof.claims import PRICE_SOURCE
from reproof.crash import parse_crash
from reproof.door import (
    BUDGET_SPENT_NOTE,
    LOOKUP_MAX_CREDITS,
    DoorResult,
    PublicLookupRequest,
    _usable_frames,
    iter_cached_triage,
    public_payload,
    run_cached_triage,
)
from reproof.door_asgi import iter_triage_lines
from reproof.door_data import (
    ASSETS_DIR,
    DOOR_PROJECTS,
    ProjectIndex,
    load_catalog,
    load_manifest,
    load_project_index,
    project_repository,
)
from reproof.door_limits import Limits, PublicBudget
from reproof.dup import OsvIndex, parse_osv_record
from reproof.models import (
    Claim,
    EvalReport,
    ModelCall,
    PublicDraftLine,
    PublicEvidence,
    PublicStatus,
    PublicTavilyCall,
    SandboxOperation,
    Verdict,
)
from reproof.provenance import source_sha256, text_sha256
from reproof.public_match import build_draft_line
from reproof.public_status import UrllibGitHub, _sentence
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


def _world(
    stderr: str, *, leak_credentials: bool = False, include_other: bool = True
) -> dict[str, object]:
    crash = parse_crash(stderr)
    records = [
        parse_osv_record(_raw_record("OSV-SELF", "jq", TASK_ID, crash.state)),
        parse_osv_record(_raw_record("OSV-OTHER", "jq", 999, crash.state)),
    ]
    parsed = [record for record in records if record is not None]
    assert [record.id for record in parsed] == ["OSV-SELF", "OSV-OTHER"]
    if not include_other:
        parsed = parsed[:1]
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


def _quiet_status(**overrides: object) -> PublicStatus:
    payload: dict[str, object] = {
        "state": "NO_PUBLIC_FINDINGS",
        "evidence": [],
        "queries_sent": [],
        "query_source": "test",
        "domains": [],
        "failed_sources": [],
        "note": "test stub",
        "tavily_request_ids": [],
        "tavily_calls": [],
        "model_calls": [],
        "draft": [],
    }
    payload.update(overrides)
    return PublicStatus.model_validate(payload)


def _quiet_lookup(_request: PublicLookupRequest) -> PublicStatus:
    return _quiet_status()


def _block_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(**_kwargs: object) -> PublicStatus:
        raise AssertionError("lookup_public_status must not be called")

    monkeypatch.setattr("reproof.door.lookup_public_status", refuse)


def _run(
    world: dict[str, object],
    *,
    public_lookup: Callable[[PublicLookupRequest], PublicStatus] | None = _quiet_lookup,
    public_budget: PublicBudget | None = None,
) -> DoorResult:
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
        public_lookup=public_lookup,
        public_budget=public_budget,
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
    _block_lookup(monkeypatch)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    events = list(
        iter_cached_triage(
            TASK_ID,
            catalog=world["catalog"],  # type: ignore[arg-type]
            manifest=world["manifest"],  # type: ignore[arg-type]
            project_index=world["index"],  # type: ignore[arg-type]
            runner=world["runner"],  # type: ignore[arg-type]
            extractor=lambda _report: (_claim(), _model_call()),
            public_lookup=_quiet_lookup,
        )
    )
    step_events = [event["step"] for event in events if event["type"] == "step"]
    steps = [event["step"] for event in step_events]
    assert steps == [
        "claim",
        "sandbox",
        "sandbox",
        "crash",
        "duplicates",
        "public_status",
        "verdict",
    ]
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
    _block_lookup(monkeypatch)
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
            ["git", "check-ignore", "-q", "--", f"reproof/assets/{name}"],
            cwd=ROOT,
            check=False,
        )
        assert completed.returncode == 1


FORBIDDEN_PAGE_TEXT = "NAN1000000000"
TAVILY_SENTINEL = "TAVILY-LEAK-SENTINEL-999"
PUBLIC_MODEL_COST = 0.0000123


def _public_model_call() -> ModelCall:
    return ModelCall(
        model="nvidia/nemotron-3-super-120b-a12b",
        latency_seconds=0.02,
        input_tokens=20,
        output_tokens=8,
        total_tokens=28,
        input_price_per_million=0.30,
        output_price_per_million=0.90,
        price_source=PRICE_SOURCE,
        cost_usd=PUBLIC_MODEL_COST,
        request_id="public-model",
    )


def _advisory_evidence() -> PublicEvidence:
    return PublicEvidence.model_validate(
        {
            "url": "https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22",
            "title": "Again, stack-buffer-overflow when comparing nan with payload",
            "frames_matched": ["decNaNs", "decNumberCopy"],
            "matched_lines": [FORBIDDEN_PAGE_TEXT],
            "cve_ids": [],
            "ghsa_ids": ["GHSA-x6c3-qv5r-7q22"],
            "patched_versions": [],
            "mentioned_commits": [],
            "relation": "SAME_BUG",
            "upstream_status": "OPEN",
            "upstream_version": "",
            "ancestry": "NOT_CHECKABLE",
            "checked_tag": "",
            "checked_commit": "",
            "stale_fields": [],
            "quotes": [FORBIDDEN_PAGE_TEXT],
            "dispute": False,
            "match_reason": "top frame and crash type",
            "model_request_id": "public-model",
        }
    )


def _rich_status() -> PublicStatus:
    return _quiet_status(
        state="PUBLICLY_KNOWN_OPEN",
        evidence=[_advisory_evidence()],
        queries_sent=["jq Heap-buffer-overflow decToString"],
        query_source="test",
        domains=["github.com"],
        note="One open advisory matched the measured frames.",
        tavily_request_ids=["tavily-req-1"],
        tavily_calls=[
            PublicTavilyCall(
                operation="search",
                request_id="tavily-req-1",
                credits=2,
                query="jq Heap-buffer-overflow decToString",
            )
        ],
        tavily_credits=2,
        model_calls=[_public_model_call()],
        draft=[
            PublicDraftLine(
                text="One public advisory is still open.",
                source_url="https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22",
                source_date="2026-10-05",
                confidence="medium",
            )
        ],
    )


def _public_step(result: DoorResult) -> dict[str, object]:
    found = next(step for step in result.steps if step.step == "public_status")
    return found.payload


def test_project_repository_uses_the_oss_fuzz_map() -> None:
    assert project_repository("jq") == ("jqlang", "jq", "https://jqlang.github.io/jq")
    assert project_repository("libplist") == ("libimobiledevice", "libplist", "")
    assert project_repository("wasm3") == ("wasm3", "wasm3", "")
    assert project_repository("miniz") == ("richgel999", "miniz", "")
    assert project_repository("libspng") == ("randy408", "libspng", "https://libspng.org")
    assert project_repository("missing") == ("", "", "")


def test_missing_tavily_key_sends_no_search(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    _block_lookup(monkeypatch)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    result = _run(world, public_lookup=None)
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.tavily_credits == 0
    assert status.model_calls == []
    assert status.failed_sources == ["TAVILY_API_KEY is not set"]
    assert status.queries_sent == []

    monkeypatch.setenv("TAVILY_API_KEY", "short")
    short = _run(world, public_lookup=None)
    assert short.card is not None
    assert short.card.public_status is not None
    assert short.card.public_status.failed_sources == ["TAVILY_API_KEY is not set"]


def test_live_lookup_receives_the_jq_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def capture(**kwargs: object) -> PublicStatus:
        captured.update(kwargs)
        return _quiet_status()

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", capture)
    stderr = FIXTURE.read_text(encoding="utf-8")
    measured = parse_crash(stderr)
    world = _world(stderr)
    result = _run(world, public_lookup=None)
    assert result.verdict is Verdict.DUPLICATE
    assert captured["owner"] == "jqlang"
    assert captured["repo"] == "jq"
    assert captured["project_site"] == "https://jqlang.github.io/jq"
    assert captured["crawl_fallback"] is False
    assert captured["project"] == "jq"
    assert captured["crash_type"] == measured.crash_type
    assert captured["frames"] == _usable_frames(tuple(measured.state))
    assert captured["fix_commits"] == ("abc",)
    assert captured["retrieved_on"] == datetime.now(UTC).date().isoformat()


def test_injected_stub_replaces_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[PublicLookupRequest] = []

    def stub(request: PublicLookupRequest) -> PublicStatus:
        seen.append(request)
        return _quiet_status()

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    _block_lookup(monkeypatch)
    result = _run(_world(FIXTURE.read_text(encoding="utf-8")), public_lookup=stub)
    assert result.verdict is Verdict.DUPLICATE
    assert len(seen) == 1
    assert seen[0].owner == "jqlang"
    assert seen[0].repo == "jq"
    assert seen[0].project_site == "https://jqlang.github.io/jq"
    assert "abc" in seen[0].fix_commits


def _door_budget(store: Path, cap: int) -> PublicBudget:
    limits = Limits(
        in_flight_per_visitor=1,
        per_ip_per_hour=8,
        global_per_day=60,
        tavily_credits_per_day=cap,
        public_reuse_seconds=3600,
    )
    return PublicBudget(store=store, limits=limits)


def test_budget_reuses_a_recent_lookup_without_new_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: list[dict[str, object]] = []

    def capture(**kwargs: object) -> PublicStatus:
        captured.append(kwargs)
        return _quiet_status(
            tavily_credits=4,
            tavily_request_ids=["tavily-req-live"],
            model_calls=[_public_model_call()],
        )

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", capture)
    budget = _door_budget(tmp_path / "limits.json", 100)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    first = _run(world, public_lookup=None, public_budget=budget)
    assert len(captured) == 1
    ledger = captured[0]["ledger"]
    assert getattr(ledger, "limit", None) == LOOKUP_MAX_CREDITS == 5
    assert isinstance(captured[0]["transport"], UrllibGitHub)
    assert first.card is not None and first.card.public_status is not None
    assert first.card.public_status.reused_from == ""
    assert first.card.public_status.tavily_credits == 4

    second = _run(world, public_lookup=None, public_budget=budget)
    assert len(captured) == 1
    assert second.card is not None
    status = second.card.public_status
    assert status is not None
    assert status.reused_from
    assert status.tavily_credits == 0
    assert status.model_calls == []
    assert status.tavily_request_ids == ["tavily-req-live"]
    assert status.note.startswith("Reused the lookup made at ")
    assert "claim extraction above is this triage's own call" in status.note
    assert second.card.model_cost_usd == pytest.approx(
        first.card.model_cost_usd - PUBLIC_MODEL_COST, abs=1e-9
    )
    step = _public_step(second)
    assert step["reused_from"] == status.reused_from
    assert step["credits"] == 0
    assert step["caps"] == {
        "searches": 2,
        "extract_urls": 5,
        "tavily_credits": LOOKUP_MAX_CREDITS,
        "nemotron_calls": step["caps"]["nemotron_calls"],
        "tavily_credits_per_day": 100,
    }
    # Tavily reported 4, but the day is charged at least the hold of 5. The reuse added nothing.
    assert budget.reserve(95) is not None
    assert budget.reserve(1) is None


def test_a_card_from_other_lookup_code_is_not_reused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Measured 2026-10-06: after a lookup fix was deployed, the door kept answering
    # from a NO_PUBLIC_FINDINGS card the previous code had stored minutes earlier.
    captured: list[dict[str, object]] = []

    def capture(**kwargs: object) -> PublicStatus:
        captured.append(kwargs)
        return _quiet_status(tavily_credits=4, tavily_request_ids=["tavily-req-live"])

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", capture)
    budget = _door_budget(tmp_path / "limits.json", 100)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr("reproof.door.lookup_code_version", lambda: "code-before-fix")
    _run(world, public_lookup=None, public_budget=budget)
    monkeypatch.setattr("reproof.door.lookup_code_version", lambda: "code-after-fix")
    after = _run(world, public_lookup=None, public_budget=budget)
    assert len(captured) == 2
    assert after.card is not None and after.card.public_status is not None
    assert after.card.public_status.reused_from == ""


def test_lookup_code_version_hashes_the_lookup_modules() -> None:
    from reproof.door import lookup_code_version

    version = lookup_code_version()
    assert len(version) == 16
    assert all(char in "0123456789abcdef" for char in version)
    assert lookup_code_version() == version


def test_spent_budget_sends_no_search(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    _block_lookup(monkeypatch)
    budget = _door_budget(tmp_path / "limits.json", LOOKUP_MAX_CREDITS - 1)
    result = _run(
        _world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None, public_budget=budget
    )
    assert result.verdict is Verdict.DUPLICATE
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.failed_sources == [BUDGET_SPENT_NOTE]
    assert status.tavily_credits == 0


def test_unavailable_or_failed_lookups_are_not_reused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    outcomes: list[object] = [
        RuntimeError("lookup blew up"),
        _quiet_status(state="LOOKUP_UNAVAILABLE", tavily_credits=2),
        _quiet_status(tavily_credits=3),
    ]
    calls: list[int] = []

    def scripted(**_kwargs: object) -> PublicStatus:
        calls.append(1)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, PublicStatus)
        return outcome

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", scripted)
    budget = _door_budget(tmp_path / "limits.json", 100)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    states = []
    for _ in range(3):
        result = _run(world, public_lookup=None, public_budget=budget)
        assert result.card is not None and result.card.public_status is not None
        states.append((result.card.public_status.state, result.card.public_status.reused_from))
    assert len(calls) == 3
    assert states[0] == ("LOOKUP_UNAVAILABLE", "")
    assert states[1] == ("LOOKUP_UNAVAILABLE", "")
    assert states[2] == ("NO_PUBLIC_FINDINGS", "")
    # Each lookup is charged at least its hold of 5: 15 in all, so exactly 85 remain.
    assert budget.reserve(85) is not None
    assert budget.reserve(1) is None


def test_a_report_above_the_hold_is_charged_as_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def overbilled(**_kwargs: object) -> PublicStatus:
        return _quiet_status(tavily_credits=LOOKUP_MAX_CREDITS + 2)

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", overbilled)
    budget = _door_budget(tmp_path / "limits.json", 100)
    _run(_world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None, public_budget=budget)
    assert budget.reserve(100 - LOOKUP_MAX_CREDITS - 2) is not None
    assert budget.reserve(1) is None


def test_unanswered_estimates_are_charged_to_the_day(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def partly_answered(**_kwargs: object) -> PublicStatus:
        return _quiet_status(tavily_credits=4, tavily_unanswered_credits=2)

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", partly_answered)
    budget = _door_budget(tmp_path / "limits.json", 100)
    result = _run(
        _world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None, public_budget=budget
    )
    assert _public_step(result)["unanswered_credits"] == 2
    assert budget.reserve(94) is not None
    assert budget.reserve(1) is None


@pytest.mark.parametrize("method", ["reuse", "reserve"])
@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("door limit lock is held"),
        TypeError("can't compare offset-naive and offset-aware datetimes"),
        AttributeError("'NoneType' object has no attribute 'get'"),
    ],
)
def test_a_failing_budget_store_sends_no_search(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, method: str, error: Exception
) -> None:
    def broken(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    _block_lookup(monkeypatch)
    monkeypatch.setattr(PublicBudget, method, broken)
    budget = _door_budget(tmp_path / "limits.json", 100)
    result = _run(
        _world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None, public_budget=budget
    )
    assert result.verdict is Verdict.DUPLICATE
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.failed_sources[0].startswith("Tavily budget store failed:")


@pytest.mark.parametrize(
    "stored",
    [
        {"state": "BOGUS"},
        _quiet_status(state="LOOKUP_UNAVAILABLE").model_dump(mode="json"),
    ],
)
def test_an_unreadable_or_unavailable_stored_card_is_not_reused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stored: dict[str, object]
) -> None:
    calls: list[int] = []

    def live(**_kwargs: object) -> PublicStatus:
        calls.append(1)
        return _quiet_status(tavily_credits=4)

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", live)
    monkeypatch.setattr(PublicBudget, "reuse", lambda _self, _key: (stored, "t"))
    budget = _door_budget(tmp_path / "limits.json", 100)
    result = _run(
        _world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None, public_budget=budget
    )
    assert result.card is not None and result.card.public_status is not None
    # Ignored, so the triage looks up again under the same hold as a new lookup.
    assert calls == [1]
    assert result.card.public_status.reused_from == ""
    assert result.card.public_status.state == "NO_PUBLIC_FINDINGS"
    assert budget.reserve(95) is not None
    assert budget.reserve(1) is None


def test_a_failing_settle_keeps_the_result_and_the_hold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError("door limit lock is held")

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", lambda **_k: _quiet_status())
    monkeypatch.setattr(PublicBudget, "settle", broken)
    budget = _door_budget(tmp_path / "limits.json", 100)
    result = _run(
        _world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None, public_budget=budget
    )
    assert result.card is not None and result.card.public_status is not None
    assert result.card.public_status.state == "NO_PUBLIC_FINDINGS"
    assert budget.reserve(100 - LOOKUP_MAX_CREDITS) is not None
    assert budget.reserve(1) is None


def test_public_step_omits_page_text_and_counts_model_cost() -> None:
    result = _run(
        _world(FIXTURE.read_text(encoding="utf-8")),
        public_lookup=lambda _request: _rich_status(),
    )
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    assert status.evidence[0].matched_lines == [FORBIDDEN_PAGE_TEXT]
    payload = _public_step(result)
    payload_text = json.dumps(payload)
    assert FORBIDDEN_PAGE_TEXT not in payload_text
    evidence = payload["evidence"]
    assert isinstance(evidence, list)
    assert "matched_lines" not in evidence[0]
    assert "quotes" not in evidence[0]
    assert payload["project"] == "jq"
    assert evidence[0]["version_sources"] == []
    assert evidence[0]["checked_commit"] == ""
    draft = payload["draft"]
    assert isinstance(draft, list)
    assert FORBIDDEN_PAGE_TEXT not in draft[0]["text"]
    verdict = next(step for step in result.steps if step.step == "verdict")
    expected = _model_call().cost_usd + PUBLIC_MODEL_COST
    assert verdict.payload["model_cost_usd"] == pytest.approx(expected)
    assert result.card.model_cost_usd == pytest.approx(expected)
    assert any(call.request_id == "public-model" for call in result.card.model_calls)
    assert [step.step for step in result.steps].index("public_status") < [
        step.step for step in result.steps
    ].index("verdict")


def test_unknown_project_names_the_missing_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def capture(**kwargs: object) -> PublicStatus:
        captured.update(kwargs)
        return _quiet_status(note="searched")

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", capture)
    world = _world(FIXTURE.read_text(encoding="utf-8"))
    catalog = world["catalog"]
    assert isinstance(catalog, dict)
    catalog["tasks"][0]["project"] = "other"
    result = _run(world, public_lookup=None)
    assert captured["owner"] == ""
    assert captured["repo"] == ""
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    expected = (
        "GitHub repository for other is not in the OSS-Fuzz project map, "
        "so GitHub pages are not accepted."
    )
    assert expected in status.failed_sources
    assert expected in status.note
    assert expected in _public_step(result)["failed_sources"]


def test_no_measured_frame_sends_no_search(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_lookup(monkeypatch)
    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    result = _run(_world(""), public_lookup=None)
    assert result.verdict is Verdict.NEEDS_INFO
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert status.note == "No measured crash frame was available, so no search was sent."
    assert status.tavily_credits == 0
    assert status.model_calls == []
    assert status.queries_sent == []
    assert [call.request_id for call in result.card.model_calls] == ["test-request"]


def test_lookup_failure_keeps_the_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_kwargs: object) -> PublicStatus:
        raise RuntimeError(f"lookup blew up {TAVILY_SENTINEL}")

    monkeypatch.setenv("TAVILY_API_KEY", TAVILY_SENTINEL)
    monkeypatch.setattr("reproof.door.lookup_public_status", boom)
    result = _run(_world(FIXTURE.read_text(encoding="utf-8")), public_lookup=None)
    assert result.verdict is Verdict.DUPLICATE
    assert result.card is not None
    status = result.card.public_status
    assert status is not None
    assert status.state == "LOOKUP_UNAVAILABLE"
    assert "No Tavily search was sent" not in status.note
    assert status.failed_sources
    assert status.failed_sources[0].startswith("public status failed:")
    assert "[redacted]" in status.failed_sources[0]
    rendered = json.dumps(public_payload(result), sort_keys=True)
    assert TAVILY_SENTINEL not in rendered
    assert TAVILY_SENTINEL not in json.dumps(_public_step(result))


def test_public_status_redacts_the_tavily_key(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "TAVILY-NOTE-SENTINEL-999"
    monkeypatch.setenv("TAVILY_API_KEY", secret)

    def stub(_request: PublicLookupRequest) -> PublicStatus:
        return _quiet_status(note=f"see {secret}")

    _block_lookup(monkeypatch)
    result = _run(_world(FIXTURE.read_text(encoding="utf-8")), public_lookup=stub)
    rendered = json.dumps(public_payload(result), sort_keys=True)
    assert secret not in rendered
    assert "[redacted]" in json.dumps(_public_step(result))


WEB_STREAM_FIXTURE = ROOT / "web" / "tests" / "fixtures" / "door-stream.ndjson"
FIXED_ADVISORY = "https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc"


def _fixed_advisory_status() -> PublicStatus:
    """A CONTAINS_FIX lookup. The draft line is written by the producer's own sentence code."""

    evidence = PublicEvidence.model_validate(
        {
            "url": FIXED_ADVISORY,
            "title": "GHSA-686w-5m7m-54vc",
            "frames_matched": ["decToString", "decNumberToString"],
            "matched_lines": [FORBIDDEN_PAGE_TEXT],
            "cve_ids": ["CVE-2023-50246"],
            "ghsa_ids": ["GHSA-686w-5m7m-54vc"],
            "patched_versions": ["1.7.1"],
            "mentioned_commits": [],
            "relation": "SAME_BUG",
            "upstream_status": "FIXED",
            "upstream_version": "1.7.1",
            "ancestry": "CONTAINS_FIX",
            "checked_tag": "jq-1.7.1",
            "checked_commit": "71c2ab509a8628dbbad4bc7b3f98a64aa90d3297",
            "version_sources": ["github_advisory_api:1.7.1"],
            "stale_fields": [],
            "quotes": [FORBIDDEN_PAGE_TEXT],
            "dispute": False,
            "match_reason": "top frame and crash type",
            "model_request_id": "public-model",
        }
    )
    line = build_draft_line(
        sentence=_sentence(evidence, "jq"),
        source_url=FIXED_ADVISORY,
        source_date="2026-10-06",
        confidence="high",
    )
    calls = [
        PublicTavilyCall(operation="search", request_id="tavily-req-a", credits=2, query="q1"),
        PublicTavilyCall(operation="search", request_id="tavily-req-b", credits=2, query="q2"),
        PublicTavilyCall(operation="extract", request_id="tavily-req-c", credits=1, query="q3"),
    ]
    return _quiet_status(
        state="PUBLICLY_KNOWN_FIXED",
        evidence=[evidence],
        queries_sent=["jq heap buffer overflow decToString", "decNumberToString crash"],
        domains=["github.com"],
        note="One advisory version contains the recorded fix.",
        tavily_request_ids=[call.request_id for call in calls],
        tavily_calls=calls,
        tavily_credits=sum(call.credits for call in calls),
        model_calls=[_public_model_call()],
        draft=[
            PublicDraftLine(
                text=line.text,
                source_url=line.source_url,
                source_date=line.source_date,
                confidence="high",
            )
        ],
    )


def _web_stream(monkeypatch: pytest.MonkeyPatch) -> str:
    """The NDJSON the door sends, from the real producer and serializer with stubbed services."""

    world = _world(FIXTURE.read_text(encoding="utf-8"), include_other=False)
    clock = itertools.count(start=100.0, step=2.35)
    monkeypatch.setattr("reproof.door.time", SimpleNamespace(perf_counter=lambda: next(clock)))
    monkeypatch.setattr("reproof.door.source_sha256", lambda: "f" * 64)
    monkeypatch.setattr(
        "reproof.door_asgi.iter_cached_triage",
        functools.partial(
            iter_cached_triage,
            catalog=world["catalog"],
            manifest=world["manifest"],
            project_index=world["index"],
            runner=world["runner"],
            extractor=lambda _text: (_claim(), _model_call()),
            public_lookup=lambda _request: _fixed_advisory_status(),
        ),
    )
    return b"".join(iter_triage_lines(TASK_ID)).decode("utf-8")


def test_web_stream_fixture_matches_the_producer(monkeypatch: pytest.MonkeyPatch) -> None:
    text = _web_stream(monkeypatch)
    if os.environ.get("REPROOF_WRITE_WEB_FIXTURE") == "1":
        WEB_STREAM_FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        WEB_STREAM_FIXTURE.write_text(text, encoding="utf-8", newline="\n")
    stored = WEB_STREAM_FIXTURE.read_text(encoding="utf-8")
    assert stored == text, (
        "web/tests/fixtures/door-stream.ndjson is stale. Regenerate it with "
        "REPROOF_WRITE_WEB_FIXTURE=1 uv run pytest tests/test_door.py -k web_stream"
    )
    events = [json.loads(line) for line in text.splitlines()]
    steps = [event["step"] for event in events if event["type"] == "step"]
    assert [(step["step"], step["kind"]) for step in steps] == [
        ("claim", None),
        ("sandbox", "vul"),
        ("sandbox", "fix"),
        ("crash", None),
        ("duplicates", None),
        ("public_status", None),
        ("verdict", None),
    ]
    assert events[-1]["type"] == "result"
    assert events[-1]["result"]["verdict"] == "REPRODUCED"
    public = steps[5]["payload"]
    assert public["evidence"][0]["ancestry"] == "CONTAINS_FIX"
    assert public["draft"][0]["text"].startswith(
        "Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5."
    )
    assert FORBIDDEN_PAGE_TEXT not in json.dumps(public)
