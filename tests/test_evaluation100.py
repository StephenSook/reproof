from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import reproof.evaluation as legacy_evaluation
import reproof.evaluation100 as evaluation100
from reproof.cli import build_parser
from reproof.eval100 import Eval100InputPaths, Eval100Selection
from reproof.eval_prepare import (
    Eval100PrepLedger,
    PrepareAttempt,
    PrepareFailure,
)
from reproof.models import Eval100Report, EvalReport, EvalTaskResult

SOURCE_SHA256 = "f" * 64
INPUT_SHA256 = {
    "arvo_database": "c" * 64,
    "osv_archive": "d" * 64,
    "monorail_mapping": "e" * 64,
}


class FakeRepository:
    def get(self, task_id: int) -> Any:
        return SimpleNamespace(local_id=task_id, project=f"project-{task_id}", fuzz_target="target")


def _selection(tmp_path: Path) -> Eval100Selection:
    return Eval100Selection(
        prereg_path=tmp_path / "prereg.json",
        prereg_sha256="a" * 64,
        fixture_path=tmp_path / "fixture.tsv",
        fixture_sha256="b" * 64,
        expected_input_sha256=INPUT_SHA256,
        seed=20261019,
        size_cap_bytes=1_500_000_000,
        project_cap=3,
        target_new_tasks=90,
        historical_arvo_ids=tuple(range(1, 11)),
        draw_order=tuple(range(11, 102)),
        population=(),
        selected_new_arvo_ids=tuple(range(11, 101)),
        skipped={},
        walked=90,
    )


def _ledger(*, prepared: list[int] | None = None, prep_failure: bool = False) -> Eval100PrepLedger:
    attempted: list[PrepareAttempt] = []
    if prep_failure:
        attempted.append(
            PrepareAttempt(
                draw_index=90,
                arvo_id=101,
                project="project-101",
                status="failed",
                failure=PrepareFailure(
                    arvo_id=101,
                    project="project-101",
                    kind="vul",
                    reason="pull_error",
                    error_type="PullError",
                    error="scripted pull failure",
                ),
            )
        )
    return Eval100PrepLedger(
        prereg_sha256="a" * 64,
        population_fixture_sha256="b" * 64,
        input_sha256=INPUT_SHA256,
        draw_seed=20261019,
        target_prepared=90,
        prepared=list(range(11, 101)) if prepared is None else prepared,
        attempted=attempted,
    )


def _result(task_id: int, project: str) -> EvalTaskResult:
    payload = json.loads(Path("eval/results/arvo10.json").read_text(encoding="utf-8"))
    row = copy.deepcopy(payload["tasks"][0])
    row.update({"arvo_id": task_id, "project": project, "card_path": f"cards100/{task_id}.json"})
    row["card_provenance"].update(
        {
            "osv_archive_sha256": INPUT_SHA256["osv_archive"],
            "monorail_mapping_sha256": INPUT_SHA256["monorail_mapping"],
            "execution_source_sha256": SOURCE_SHA256,
            "derivation_source_sha256": SOURCE_SHA256,
            "derivation_method": "live-execution",
        }
    )
    return EvalTaskResult.model_validate(row)


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runner: Any,
    *,
    ledger: Eval100PrepLedger | None = None,
    output: Path | None = None,
    transport_wait: Any = None,
) -> Eval100Report:
    selection = _selection(tmp_path)
    active_ledger = ledger or _ledger()
    monkeypatch.setattr(evaluation100, "select_eval100", lambda *_args, **_kwargs: selection)
    monkeypatch.setattr(
        evaluation100,
        "load_eval100_prep_ledger",
        lambda *_args, **_kwargs: active_ledger,
    )
    monkeypatch.setattr(evaluation100, "source_sha256", lambda: SOURCE_SHA256)
    inputs = Eval100InputPaths(tmp_path / "db", tmp_path / "osv", tmp_path / "mapping")
    return evaluation100.run_eval100(
        selection.prereg_path,
        output or tmp_path / "arvo100.json",
        cards_dir=tmp_path / "cards100",
        inputs=inputs,
        repository=FakeRepository(),  # type: ignore[arg-type]
        index=SimpleNamespace(),  # type: ignore[arg-type]
        task_runner=runner,
        transport_wait=transport_wait or (lambda: 0.0),
    )


def test_transport_retry_waits_for_the_endpoint_once_per_failed_task(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: Counter[int] = Counter()
    order: list[str] = []

    def runner(task: Any, **_kwargs: Any) -> EvalTaskResult:
        calls[task.local_id] += 1
        order.append(f"run-{task.local_id}")
        if task.local_id in (1, 2) and calls[task.local_id] == 1:
            raise ConnectionError("connection refused")
        if task.local_id == 3:
            raise ValueError("invalid task evidence")
        return _result(task.local_id, task.project)

    def wait() -> float:
        order.append("wait")
        return 45.0

    report = _run(monkeypatch, tmp_path, runner, transport_wait=wait)
    assert order[:7] == ["run-1", "wait", "run-1", "run-2", "wait", "run-2", "run-3"]
    assert order.count("wait") == 2
    assert [failure.arvo_id for failure in report.run_failed] == [3]


def test_wait_for_token_factory_probes_until_the_endpoint_answers() -> None:
    now = [0.0]
    sleeps: list[float] = []
    probes = iter([ConnectionError("down"), ConnectionError("down"), None])

    class Models:
        def list(self) -> None:
            outcome = next(probes)
            if outcome is not None:
                raise outcome

    waited = evaluation100.wait_for_token_factory(
        client=SimpleNamespace(models=Models()),
        interval_seconds=30,
        sleep=lambda seconds: (sleeps.append(seconds), now.__setitem__(0, now[0] + seconds)),
        clock=lambda: now[0],
    )
    assert sleeps == [30, 30]
    assert waited == 60


def test_wait_for_token_factory_gives_up_at_the_limit() -> None:
    now = [0.0]

    class Models:
        def list(self) -> None:
            raise TimeoutError("still down")

    waited = evaluation100.wait_for_token_factory(
        client=SimpleNamespace(models=Models()),
        limit_seconds=90,
        interval_seconds=30,
        sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
        clock=lambda: now[0],
    )
    assert waited == 90


def test_wait_for_token_factory_does_not_wait_on_a_non_transport_error() -> None:
    sleeps: list[float] = []

    class Models:
        def list(self) -> None:
            raise PermissionError("401")

    waited = evaluation100.wait_for_token_factory(
        client=SimpleNamespace(models=Models()),
        sleep=sleeps.append,
        clock=lambda: 0.0,
    )
    assert sleeps == []
    assert waited == 0.0


def test_transport_error_gets_one_retry_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: Counter[int] = Counter()

    def runner(task: Any, **_kwargs: Any) -> EvalTaskResult:
        calls[task.local_id] += 1
        if task.local_id == 1 and calls[task.local_id] == 1:
            error = ConnectionError("temporary connection reset")
            error.request_ids = ["request-first"]  # type: ignore[attr-defined]
            error.input_tokens = 7  # type: ignore[attr-defined]
            error.output_tokens = 3  # type: ignore[attr-defined]
            error.model_cost_usd = 0.00001  # type: ignore[attr-defined]
            error.sandbox_cost_usd = 0.00002  # type: ignore[attr-defined]
            error.wall_seconds = 0.5  # type: ignore[attr-defined]
            raise error
        return _result(task.local_id, task.project)

    report = _run(monkeypatch, tmp_path, runner, ledger=_ledger(prep_failure=True))
    assert calls[1] == 2
    assert sum(calls.values()) == 101
    assert report.run_failed == []
    assert [failure.arvo_id for failure in report.prep_failed] == [101]
    assert report.totals.prep_failures == 1
    assert report.retry_attempts[0].request_ids == ["request-first"]
    assert report.retry_attempts[0].input_tokens == 7
    assert report.totals.total_input_tokens == sum(task.input_tokens for task in report.tasks) + 7
    assert report.totals.total_cost_usd == pytest.approx(
        sum(task.cost_usd for task in report.tasks) + 0.00003
    )
    assert (
        Eval100Report.model_validate_json((tmp_path / "arvo100.json").read_text(encoding="utf-8"))
        == report
    )


def test_retry_total_charges_checkpoint_creation_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: Counter[int] = Counter()

    def runner(task: Any, **_kwargs: Any) -> EvalTaskResult:
        calls[task.local_id] += 1
        if task.local_id == 1 and calls[task.local_id] == 1:
            error = ConnectionError("transport failed after checkpoint creation")
            error.sandbox_cost_usd = 0.15  # type: ignore[attr-defined]
            raise error
        result = _result(task.local_id, task.project)
        if task.local_id != 1:
            return result
        payload = result.model_dump()
        payload["sandbox_cost_usd"] = 0.04
        payload["cost_usd"] = payload["model_cost_usd"] + payload["sandbox_cost_usd"]
        return EvalTaskResult.model_validate(payload)

    report = _run(monkeypatch, tmp_path, runner)

    successful_cost = sum(task.sandbox_cost_usd for task in report.tasks)
    assert report.retry_attempts[0].sandbox_cost_usd == 0.15
    assert report.tasks[0].sandbox_cost_usd == 0.04
    assert report.totals.total_sandbox_cost_usd == pytest.approx(successful_cost + 0.15)


def test_second_transport_error_becomes_counted_run_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: Counter[int] = Counter()

    def runner(task: Any, **_kwargs: Any) -> EvalTaskResult:
        calls[task.local_id] += 1
        if task.local_id == 1:
            raise TimeoutError("scripted timeout")
        return _result(task.local_id, task.project)

    report = _run(monkeypatch, tmp_path, runner)
    assert calls[1] == 2
    assert sum(calls.values()) == 101
    assert [task.arvo_id for task in report.tasks] == list(range(2, 101))
    assert report.run_failed[0].arvo_id == 1
    assert report.run_failed[0].attempts == 2
    assert [row.attempt for row in report.run_failed[0].attempt_evidence] == [1, 2]
    assert report.totals.tasks_requested == 100
    assert report.totals.tasks_completed == 99
    assert report.totals.run_failures == 1


def test_nontransport_error_is_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: Counter[int] = Counter()

    def runner(task: Any, **_kwargs: Any) -> EvalTaskResult:
        calls[task.local_id] += 1
        if task.local_id == 1:
            raise ValueError("invalid task evidence")
        return _result(task.local_id, task.project)

    report = _run(monkeypatch, tmp_path, runner)
    assert calls[1] == 1
    assert sum(calls.values()) == 100
    assert report.run_failed[0].error_type == "ValueError"
    assert report.run_failed[0].attempts == 1


def test_incomplete_prepare_ledger_refuses_before_task_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def runner(*_args: Any, **_kwargs: Any) -> EvalTaskResult:
        pytest.fail("paid task runner was called")

    with pytest.raises(ValueError, match="finish eval-prepare"):
        _run(monkeypatch, tmp_path, runner, ledger=_ledger(prepared=[]))


def test_non10_selection_refuses_legacy_output_before_task_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def runner(*_args: Any, **_kwargs: Any) -> EvalTaskResult:
        pytest.fail("paid task runner was called")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        _run(monkeypatch, tmp_path, runner, output=evaluation100.LEGACY_EVAL_OUTPUT)


@pytest.mark.parametrize(
    "output",
    [Path("eval/results/arvo10.json"), evaluation100.LEGACY_EVAL_OUTPUT],
)
def test_legacy_eval_refuses_non10_output_before_selection(
    monkeypatch: pytest.MonkeyPatch, output: Path
) -> None:
    monkeypatch.setattr(
        legacy_evaluation,
        "select_tasks",
        lambda *_args, **_kwargs: pytest.fail("selection ran before the output guard"),
    )
    with pytest.raises(ValueError, match="refusing to overwrite"):
        legacy_evaluation.run_eval(11, output)


def test_schema_16_refuses_a_truncated_eval100_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _run(
        monkeypatch,
        tmp_path,
        lambda task, **_kwargs: _result(task.local_id, task.project),
    )
    payload = report.model_dump()
    payload["random_draw_arvo_ids"].pop()
    payload["selected_arvo_ids"].pop()
    payload["tasks"].pop()
    payload["totals"]["tasks_requested"] = 99
    payload["totals"]["tasks_completed"] = 99
    with pytest.raises(ValueError, match="exactly 90 random-draw"):
        Eval100Report.model_validate(payload)


def test_tracked_arvo10_remains_schema_15_and_not_schema_16() -> None:
    payload = json.loads(Path("eval/results/arvo10.json").read_text(encoding="utf-8"))
    assert EvalReport.model_validate(payload).schema_version == "1.5"
    with pytest.raises(ValueError):
        Eval100Report.model_validate(payload)


def test_cli_parses_registered_eval_with_separate_cards() -> None:
    args = build_parser().parse_args(
        [
            "eval",
            "--prereg",
            "eval/eval100_prereg.json",
            "--output",
            "eval/results/arvo100.json",
            "--cards-dir",
            "eval/results/cards100",
            "--resume",
        ]
    )
    assert args.prereg == Path("eval/eval100_prereg.json")
    assert args.cards_dir == Path("eval/results/cards100")
    assert args.resume is True
