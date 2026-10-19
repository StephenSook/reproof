from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from eval import run_public_status as runner


def _task(task_id: int, *, paid: bool) -> dict[str, Any]:
    return {
        "set": "draw",
        "task_id": task_id,
        "project": f"project-{task_id}",
        "crash_type": "Heap-buffer-overflow READ 1",
        "frames": [f"frame_{task_id}"],
        "owner": "owner",
        "repo": "repo",
        "project_site": "",
        "fix_commits": ["a" * 40],
        "osv_record_id": f"OSV-{task_id}",
        "label": "test task",
        "paid": paid,
    }


def _prereg(*, credit_cap: int, model_cap: int) -> dict[str, Any]:
    return {
        "schema_version": "public-status-prereg-2",
        "registered_on": "2026-10-19",
        "seed": 20261019,
        "task_count": 3,
        "paid_task_count": 2,
        "batch_crawl": False,
        "ledger_starts_at_recorded_credits": 0,
        "tavily_credit_budget": credit_cap,
        "max_tavily_credits_per_started_task": 5,
        "nemotron_call_budget": model_cap,
        "max_nemotron_calls_per_started_task": 1,
        "tasks": [_task(1, paid=True), _task(2, paid=True), _task(3, paid=False)],
    }


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        state="NO_PUBLIC_FINDINGS",
        evidence=[],
        draft=[],
        queries_sent=[],
        query_source="model",
        failed_sources=[],
        note="no findings",
        tavily_request_ids=[],
        tavily_credits=5,
        tavily_calls=[],
        model_calls=[],
        host_rejected=0,
        snippet_rejected=0,
        frame_rejected=0,
        quote_rejected=0,
        unrelated_rejected=0,
        source_file_rejected=0,
        latency_seconds=0.1,
    )


def _run_capped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    credit_cap: int,
    model_cap: int,
    spend_credits: int,
    spend_calls: int,
) -> tuple[dict[str, Any], list[str]]:
    prereg = tmp_path / "prereg.json"
    output = tmp_path / "result.json"
    prereg.write_text(
        json.dumps(_prereg(credit_cap=credit_cap, model_cap=model_cap)),
        encoding="utf-8",
    )
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))
    monkeypatch.setenv("TAVILY_API_KEY", "tavily-test-key")
    monkeypatch.setenv("NEBIUS_API_KEY", "nebius-test-key")
    calls: list[str] = []

    class Transport:
        def compare(self, *_args: Any) -> SimpleNamespace:
            return SimpleNamespace(status="ahead", ahead_by=1, behind_by=0, error="")

    def lookup(**kwargs: Any) -> SimpleNamespace:
        calls.append(str(kwargs["project"]))
        assert kwargs["retrieved_on"] == "2026-10-20"
        kwargs["ledger"].used += spend_credits
        kwargs["model_budget"].used += spend_calls
        return _status()

    def baseline(task: dict[str, Any], *_args: Any) -> dict[str, Any]:
        return {
            "set": task["set"],
            "task_id": task["task_id"],
            "project": task["project"],
            "references": [],
            "host_rejected": 0,
            "frame_rejected": 0,
            "failed_sources": [],
            "latency_seconds": 0,
        }

    monkeypatch.setattr(runner, "UrllibGitHub", Transport)
    monkeypatch.setattr(runner, "lookup_public_status", lookup)
    monkeypatch.setattr(runner, "baseline_task", baseline)
    monkeypatch.setattr(runner, "_utc_date", lambda: "2026-10-20")
    runner.main(["--prereg", str(prereg), "--out", str(output)])
    return json.loads(output.read_text(encoding="utf-8")), calls


def test_eval100_preregistration_has_the_registered_fallback_caps() -> None:
    prereg = runner.load_prereg(Path("eval/public_status_prereg_100.json"))
    tasks = runner.tasks_from(prereg)
    eval_prereg = json.loads(Path("eval/eval100_prereg.json").read_text(encoding="utf-8"))
    expected_ids = (
        eval_prereg["selection"]["historical_arvo_ids"]
        + eval_prereg["selection"]["selected_arvo_ids"]
    )
    assert len(tasks) == 100
    assert [int(task["task_id"]) for task in tasks] == expected_ids
    assert sum(task["paid"] for task in tasks) == 50
    assert all(task["paid"] for task in tasks[:50])
    assert not any(task["paid"] for task in tasks[50:])
    assert prereg["tavily_credit_budget"] == 250
    assert prereg["nemotron_call_budget"] == 200
    assert prereg["max_nemotron_calls_per_started_task"] == 12
    assert sum(not task["owner"] for task in tasks[10:]) == 11


def test_tavily_cap_marks_every_unstarted_task_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload, calls = _run_capped(
        monkeypatch,
        tmp_path,
        credit_cap=5,
        model_cap=10,
        spend_credits=5,
        spend_calls=1,
    )
    assert calls == ["project-1"]
    assert payload["tavily_credits_this_run"] == 5
    assert payload["tasks"][1]["not_run_reason"].endswith("Tavily credit cap")
    assert payload["tasks"][2]["not_run_reason"].endswith("preregistered paid subset")
    assert len(payload["baseline"]) == 3


def test_nemotron_cap_marks_every_unstarted_task_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload, calls = _run_capped(
        monkeypatch,
        tmp_path,
        credit_cap=10,
        model_cap=1,
        spend_credits=0,
        spend_calls=1,
    )
    assert calls == ["project-1"]
    assert payload["nemotron_calls"] == 1
    assert payload["tasks"][1]["not_run_reason"].endswith("Nemotron call cap")


def test_parameterized_runs_use_distinct_partial_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TEMP", str(tmp_path))
    first = runner.partial_path(tmp_path / "one.json", tmp_path / "one-out.json")
    second = runner.partial_path(tmp_path / "two.json", tmp_path / "two-out.json")
    assert first != second
    assert first.parent == tmp_path


def test_custom_prereg_refuses_the_legacy_default_output(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="legacy public-status output"):
        runner.main(["--prereg", str(tmp_path / "custom.json"), "--dry-run"])


def test_interrupted_paid_task_keeps_fail_closed_budget_holds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prereg = tmp_path / "prereg.json"
    output = tmp_path / "result.json"
    prereg.write_text(json.dumps(_prereg(credit_cap=5, model_cap=1)), encoding="utf-8")
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))
    monkeypatch.setenv("TAVILY_API_KEY", "tavily-test-key")
    monkeypatch.setenv("NEBIUS_API_KEY", "nebius-test-key")
    monkeypatch.setattr(runner, "_utc_date", lambda: "2026-10-20")
    calls: list[str] = []

    class Transport:
        def compare(self, *_args: Any) -> SimpleNamespace:
            return SimpleNamespace(status="ahead", ahead_by=1, behind_by=0, error="")

    def interrupted(**kwargs: Any) -> SimpleNamespace:
        calls.append(str(kwargs["project"]))
        raise KeyboardInterrupt

    def baseline(task: dict[str, Any], *_args: Any) -> dict[str, Any]:
        return {
            "set": task["set"],
            "task_id": task["task_id"],
            "project": task["project"],
            "references": [],
            "host_rejected": 0,
            "frame_rejected": 0,
            "failed_sources": [],
            "latency_seconds": 0,
        }

    monkeypatch.setattr(runner, "UrllibGitHub", Transport)
    monkeypatch.setattr(runner, "lookup_public_status", interrupted)
    monkeypatch.setattr(runner, "baseline_task", baseline)
    with pytest.raises(KeyboardInterrupt):
        runner.main(["--prereg", str(prereg), "--out", str(output)])
    partial = runner.partial_path(prereg.resolve(), output.resolve())
    saved = json.loads(partial.read_text(encoding="utf-8"))
    assert saved["in_progress"] == {
        "task_id": "1",
        "tavily_credits": 5,
        "nemotron_calls": 1,
    }

    monkeypatch.setattr(runner, "_utc_date", lambda: "2026-10-21")
    monkeypatch.setattr(
        runner,
        "lookup_public_status",
        lambda **_kwargs: pytest.fail("an interrupted paid task was repeated"),
    )
    runner.main(["--prereg", str(prereg), "--out", str(output)])
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert calls == ["project-1"]
    assert payload["retrieved_on"] == "2026-10-20"
    assert payload["tavily_unanswered_credits"] == 5
    assert payload["nemotron_calls"] == 1
    assert payload["nemotron_reserved_after_interruption"] == 1
    assert payload["tasks"][0]["not_run_reason"].startswith("not retried")
    assert payload["tasks"][1]["not_run_reason"].endswith("Tavily credit cap")


def test_baseline_still_queries_nvd_without_a_github_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = _task(1, paid=True)
    task["owner"] = ""
    task["repo"] = ""
    requested: list[str] = []

    def nvd(frame: str, *_args: Any) -> dict[str, Any]:
        requested.append(frame)
        return {"payload": {"vulnerabilities": []}, "error": "", "cached": False}

    monkeypatch.setattr(runner, "nvd_search", nvd)
    result = runner.baseline_task(
        task,
        SimpleNamespace(),
        {},
        {},
        {},
        [0.0],
        [""],
    )
    assert requested == ["frame_1"]
    assert result["failed_sources"] == ["GitHub baseline not checkable: missing repository"]
