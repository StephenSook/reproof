from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reproof import patch_eval
from reproof.claims import PRICE_SOURCE
from reproof.models import ModelCall
from reproof.patch_eval import (
    Budget,
    ExecResult,
    FrameRef,
    Harness,
    ModelReply,
    PatchEdit,
    TaskInput,
    TaskRecord,
    TokenFactoryModel,
    apply_edits,
    build_report,
    edit_path_error,
    evaluate_task,
    parse_frames,
    render_source,
    select_frames,
    source_windows,
    summary_row,
    unified_diff,
)

ROOT = Path(__file__).resolve().parents[1]
CRASH = (ROOT / "tests/fixtures/42530604-vul.txt").read_text(encoding="utf-8")
CLEAN = "INFO: Running with entropic power schedule (0xFF, 100).\nExecuted /tmp/poc in 0 ms\n"
WORKDIR = "/src/jq"
JV = "/src/jq/src/jv.c"
JV_TEXT = "\n".join(
    [*(f"// line {number}" for number in range(1, 647)), "    int len = digits + 14;", "x();"]
)


def _result(exit_code: int | None, text: str, *, timed_out: bool = False) -> ExecResult:
    return ExecResult(exit_code, text.encode(), b"", 0.5, timed_out)


def test_frames_come_from_the_crash_and_allocation_stacks() -> None:
    frames = parse_frames(CRASH)
    assert frames[0] == FrameRef(
        section="crash",
        index=0,
        function="decToString",
        path="/src/jq/src/decNumber/decNumber.c",
        line=3764,
    )
    assert any(
        frame.section == "allocated" and frame.function == "jv_mem_alloc" for frame in frames
    )
    chosen = select_frames(frames, WORKDIR)
    names = [(frame.section, frame.function) for frame in chosen]
    assert names == [
        ("crash", "decToString"),
        ("crash", "decNumberToString"),
        ("crash", "jvp_literal_number_literal"),
        ("crash", "jv_number_get_literal"),
        ("allocated", "jv_mem_alloc"),
        ("allocated", "jv_dump_term"),
    ]
    # The fuzz harness and libFuzzer frames are never offered as source to edit.
    assert all("tests/" not in frame.path and "llvm-project" not in frame.path for frame in chosen)


def test_an_edit_may_only_touch_project_source() -> None:
    assert edit_path_error("/src/jq/src/jv.c", WORKDIR) is None
    assert "outside" in str(edit_path_error("/src/other/x.c", WORKDIR))
    assert "outside" in str(edit_path_error("/src/jq/../other/x.c", WORKDIR))
    assert "absolute" in str(edit_path_error("src/jv.c", WORKDIR))
    assert "fuzz" in str(edit_path_error("/src/jq/tests/jq_fuzz_parse.c", WORKDIR))
    assert "fuzz" in str(edit_path_error("/src/jq/src/fuzzing_helpers.c", WORKDIR))
    assert "fuzz" in str(edit_path_error("/src/jq/test/check.c", WORKDIR))
    assert "build file" in str(edit_path_error("/src/jq/Makefile.am", WORKDIR))
    assert "build file" in str(edit_path_error("/src/jq/build.sh", WORKDIR))
    assert "build file" in str(edit_path_error("/src/jq/cmake/x.cmake", WORKDIR))


def test_edits_apply_only_when_old_text_occurs_exactly_once() -> None:
    originals = {JV: "a\nb\nb\nc\n"}
    changed, errors = apply_edits(
        originals, [PatchEdit(path=JV, old_text="a\n", new_text="A\n")], WORKDIR
    )
    assert errors == [] and changed == {JV: "A\nb\nb\nc\n"}
    _, errors = apply_edits(originals, [PatchEdit(path=JV, old_text="b\n", new_text="")], WORKDIR)
    assert errors == [f"edit 1: old_text occurs 2 times in {JV}; it must occur once"]
    _, errors = apply_edits(originals, [PatchEdit(path=JV, old_text="z", new_text="")], WORKDIR)
    assert "occurs 0 times" in errors[0]
    _, errors = apply_edits(originals, [PatchEdit(path=JV, old_text="", new_text="x")], WORKDIR)
    assert "empty" in errors[0]
    _, errors = apply_edits(
        originals, [PatchEdit(path="/src/jq/src/missing.c", old_text="a", new_text="b")], WORKDIR
    )
    assert "does not exist" in errors[0]
    # A second edit of the same file applies to the text the first edit produced.
    changed, errors = apply_edits(
        originals,
        [
            PatchEdit(path=JV, old_text="a\n", new_text="A\n"),
            PatchEdit(path=JV, old_text="A\nb", new_text="AB"),
        ],
        WORKDIR,
    )
    assert errors == [] and changed[JV] == "AB\nb\nc\n"
    # One refused edit refuses the whole proposal.
    changed, errors = apply_edits(
        originals,
        [
            PatchEdit(path=JV, old_text="a\n", new_text="A\n"),
            PatchEdit(path="/src/jq/tests/fuzz.c", old_text="x", new_text="y"),
        ],
        WORKDIR,
    )
    assert changed == {} and len(errors) == 1
    assert unified_diff(originals, {JV: "A\nb\nb\nc\n"}).startswith(f"--- a{JV}\n+++ b{JV}\n")


def test_source_windows_merge_and_respect_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    frames = [
        FrameRef(section="crash", index=0, function="f", path=JV, line=300),
        FrameRef(section="crash", index=1, function="g", path=JV, line=340),
        FrameRef(section="allocated", index=1, function="h", path="/src/jq/src/b.c", line=5),
    ]
    windows = source_windows(frames, {JV: 1000, "/src/jq/src/b.c": 10})
    assert [(w.path, w.start, w.end) for w in windows] == [
        (JV, 220, 380),
        ("/src/jq/src/b.c", 1, 10),
    ]
    assert len(windows[0].labels) == 2
    files = {JV: "\n".join(f"L{n}" for n in range(1, 1001)), "/src/jq/src/b.c": "B\n" * 10}
    text = render_source(windows, files)
    assert text.startswith(f"=== {JV}, lines 220 to 380 (crash frame #0 f line 300; ")
    assert "L220\n" in text and "L380\n" in text and "L381" not in text
    monkeypatch.setattr(patch_eval, "SOURCE_CHAR_CAP", 900)
    capped = render_source(windows, files)
    assert "/src/jq/src/b.c: not shown, the source cap was reached" in capped


class FakeWorkspace:
    workdir = WORKDIR

    def __init__(
        self,
        *,
        compiles: list[ExecResult],
        pocs: list[ExecResult],
        seeds: list[ExecResult] | None = None,
        seed_count: int = 0,
    ) -> None:
        self.files = {JV: JV_TEXT.encode()}
        for frame in select_frames(parse_frames(CRASH), WORKDIR):
            self.files.setdefault(frame.path, b"source\n" * 900)
        self.original = dict(self.files)
        self.compiles = compiles
        self.pocs = pocs
        self.seed_runs = seeds or []
        self.seed_count = seed_count
        self.written: list[str] = []
        self.seen_on_compile: list[bytes] = []

    def read(self, path: str) -> bytes | None:
        return self.files.get(path)

    def write(self, path: str, data: bytes) -> None:
        self.written.append(path)
        self.files[path] = data

    def compile(self) -> ExecResult:
        self.seen_on_compile.append(self.files[JV])
        return self.compiles.pop(0)

    def poc(self) -> ExecResult:
        return self.pocs.pop(0)

    def seeds(self) -> ExecResult | None:
        return self.seed_runs.pop(0) if self.seed_runs else None


class FakeModel:
    def __init__(self, replies: list[str]) -> None:
        self.replies = replies
        self.seen: list[list[dict[str, str]]] = []

    def propose(self, messages: list[dict[str, str]]) -> ModelReply:
        self.seen.append([dict(message) for message in messages])
        content = self.replies.pop(0)
        call = ModelCall(
            model="nvidia/nemotron-3-super-120b-a12b",
            latency_seconds=1.0,
            input_tokens=1000,
            output_tokens=100,
            total_tokens=1100,
            input_price_per_million=0.3,
            output_price_per_million=0.9,
            price_source=PRICE_SOURCE,
            cost_usd=0.00039,
            request_id=f"req-{len(self.seen)}",
        )
        return ModelReply(call, content, "", [call.request_id], call.cost_usd)


def _proposal(path: str, old: str, new: str) -> str:
    return json.dumps(
        {
            "rationale": "allocate one more byte",
            "edits": [{"path": path, "old_text": old, "new_text": new}],
        }
    )


TASK = TaskInput(42530604, "jq", "Heap-buffer-overflow in decToString", ["71c2ab5"])
HARNESS = Harness(
    baseline=_result(1, CRASH),
    control_compile=_result(0, "built"),
    control_poc=_result(1, CRASH),
    control_seeds=None,
)
GOOD = _proposal(JV, "    int len = digits + 14;", "    int len = digits + 15;")


def test_failed_attempts_feed_back_and_a_later_attempt_is_proven() -> None:
    workspace = FakeWorkspace(
        compiles=[_result(2, "jv.c:647: error: expected ';'"), _result(0, "ok")],
        pocs=[_result(0, CLEAN)],
    )
    model = FakeModel(
        [
            _proposal("/src/jq/tests/jq_fuzz_parse_extended.c", "x", "y"),
            _proposal(JV, "    int len = digits + 14;", "    int len = digits + 15"),
            GOOD,
        ]
    )
    attempts: list[Any] = []
    fields = evaluate_task(TASK, workspace, model, Budget(3.0), HARNESS, attempts)
    assert [attempt.outcome for attempt in attempts] == ["APPLY_FAILED", "COMPILE_FAILED", "PROVEN"]
    assert fields["outcome"] == "PROVEN" and fields["proven_attempt"] == 3
    assert attempts[2].regression_check == "PoC only: the image has no seed corpus"
    assert "+    int len = digits + 15;" in attempts[2].diff
    # Each attempt starts from the original tree, and the tree is restored after each one.
    assert all(b"digits + 14" not in seen for seen in workspace.seen_on_compile)
    assert workspace.files == workspace.original
    # The model saw each failure before its next try.
    second, third = model.seen[1], model.seen[2]
    assert "fuzz harness" in second[-1]["content"]
    assert "error: expected ';'" in third[-1]["content"]
    assert [message["role"] for message in third] == [
        "system",
        "user",
        "assistant",
        "user",
        "assistant",
        "user",
    ]
    context = model.seen[0][1]["content"]
    assert "int len = digits + 14;" in context
    assert "decToString" in context and "LLVMFuzzerTestOneInput" in context


def test_a_patch_that_still_crashes_is_not_proven_after_the_last_attempt() -> None:
    workspace = FakeWorkspace(
        compiles=[_result(0, "ok")] * 3, pocs=[_result(1, CRASH)] * 2 + [_result(1, "Killed")]
    )
    model = FakeModel([GOOD, GOOD, GOOD])
    attempts: list[Any] = []
    fields = evaluate_task(TASK, workspace, model, Budget(3.0), HARNESS, attempts)
    assert [attempt.outcome for attempt in attempts] == [
        "STILL_CRASHES",
        "STILL_CRASHES",
        "POC_NOT_CLEAN",
    ]
    assert attempts[0].poc_crash_type.startswith("Heap-buffer-overflow")
    assert "heap-buffer-overflow" in model.seen[1][-1]["content"]
    assert fields["outcome"] == "NOT_PROVEN"
    assert fields["detail"] == "3 attempts; last: POC_NOT_CLEAN"


def test_a_seed_corpus_failure_after_the_patch_is_a_regression() -> None:
    harness = Harness(
        HARNESS.baseline, HARNESS.control_compile, HARNESS.control_poc, _result(0, CLEAN)
    )
    workspace = FakeWorkspace(
        compiles=[_result(0, "ok")] * 2,
        pocs=[_result(0, CLEAN)] * 2,
        seeds=[_result(1, CRASH)] * 2,
        seed_count=12,
    )
    attempts: list[Any] = []
    fields = evaluate_task(
        TASK,
        workspace,
        FakeModel([GOOD, "not json", GOOD]),
        Budget(3.0),
        harness,
        attempts,
    )
    assert attempts[0].outcome == "REGRESSION"
    assert attempts[0].regression_check == "seed corpus, 12 files"
    assert attempts[1].outcome == "MODEL_ERROR"
    assert attempts[2].outcome == "REGRESSION"
    assert fields["outcome"] == "NOT_PROVEN"


def test_the_harness_must_reproduce_before_the_model_is_called() -> None:
    for harness, detail in [
        (Harness(_result(0, CLEAN), _result(0, ""), _result(1, CRASH), None), "did not crash"),
        (Harness(_result(1, CRASH), _result(2, "boom"), _result(1, CRASH), None), "exited 2"),
        (Harness(_result(1, CRASH), _result(0, ""), _result(0, CLEAN), None), "rebuilt"),
    ]:
        model = FakeModel([])
        attempts: list[Any] = []
        fields = evaluate_task(
            TASK, FakeWorkspace(compiles=[], pocs=[]), model, Budget(3), harness, attempts
        )
        assert fields["outcome"] == "HARNESS_FAILED"
        assert detail in fields["detail"]
        assert model.seen == [] and attempts == []


def test_the_budget_stops_calls_before_they_are_made() -> None:
    model = FakeModel([GOOD])
    attempts: list[Any] = []
    fields = evaluate_task(
        TASK,
        FakeWorkspace(compiles=[], pocs=[]),
        model,
        Budget(3.0, spent_usd=3.0),
        HARNESS,
        attempts,
    )
    assert fields["outcome"] == "BUDGET_STOPPED" and model.seen == []


def test_the_token_factory_call_is_strict_and_retries_one_transport_error() -> None:
    class APIConnectionError(Exception):
        pass

    calls: list[dict[str, Any]] = []
    response = SimpleNamespace(
        _request_id="req-ok",
        usage=SimpleNamespace(prompt_tokens=2000, completion_tokens=300, total_tokens=2300),
        choices=[SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content=GOOD))],
    )
    outcomes: list[Any] = [APIConnectionError("reset"), response]

    def create(**kwargs: Any) -> Any:
        calls.append(kwargs)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    waits: list[float] = []
    reply = TokenFactoryModel(client, sleep=waits.append).propose(
        [{"role": "user", "content": "x"}]
    )
    assert waits == [30]
    assert reply.error == "" and reply.content == GOOD
    assert reply.request_ids == ["req-ok"]
    assert reply.cost_usd == pytest.approx(2000 * 0.3e-6 + 300 * 0.9e-6)
    assert calls[1]["temperature"] == 0
    assert calls[1]["model"] == "nvidia/nemotron-3-super-120b-a12b"
    assert calls[1]["response_format"]["json_schema"]["strict"] is True
    assert calls[1]["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}


def test_the_report_counts_outcomes_and_shows_proven_edits() -> None:
    workspace = FakeWorkspace(compiles=[_result(0, "ok")], pocs=[_result(0, CLEAN)])
    attempts: list[Any] = []
    budget = Budget(3.0)
    fields = evaluate_task(TASK, workspace, FakeModel([GOOD]), budget, HARNESS, attempts)
    base = patch_eval._empty_task(TASK, "n132/arvo:42530604-vul", "HARNESS_FAILED", "")
    record = TaskRecord.model_validate(
        {
            **base.model_dump(),
            **patch_eval._dumped(fields),
            "attempts": [attempt.model_dump() for attempt in attempts],
            "model_calls": 1,
            "model_cost_usd": attempts[0].model_cost_usd,
        }
    )
    other = patch_eval._empty_task(
        TaskInput(1, "p", "r", []), "n132/arvo:1-vul", "HARNESS_FAILED", "pull failed"
    )
    report = build_report(
        [record, other],
        prereg={"path": "eval/PATCH-PREREG.md", "sha256": "0" * 64, "commit": "c", "head": "h"},
        started_at="s",
        finished_at="f",
        execution_source="e",
        budget=budget,
    )
    assert report["totals"]["proven"] == 1
    assert report["totals"]["harness_failed"] == 1
    assert report["totals"]["attempts_per_proven"] == [1]
    assert report["totals"]["model_cost_usd"] == pytest.approx(0.00039)
    row = summary_row(record, "eval/results/patch-cards/42530604.json")
    assert row["outcome"] == "PROVEN"
    assert "+    int len = digits + 15;" in row["proven_diff"]
    assert row["request_ids"] == ["req-1"]


def test_line_numbers_count_newlines_only() -> None:
    text = "one\n\x0ctwo\r\nthree\n"
    assert patch_eval.line_count(text) == 3
    frames = [FrameRef(section="crash", index=0, function="f", path=JV, line=3)]
    windows = source_windows(frames, {JV: patch_eval.line_count(text)})
    rendered = render_source(windows, {JV: text})
    # The form feed stays inside line 2 and the carriage return is kept, so old_text can match.
    assert rendered.endswith("one\n\x0ctwo\r\nthree\n")


def test_text_that_cannot_be_written_is_an_apply_failure() -> None:
    reply = json.dumps(
        {"rationale": "r", "edits": [{"path": JV, "old_text": "x();", "new_text": "\ud800"}]}
    )
    workspace = FakeWorkspace(compiles=[], pocs=[])
    attempts: list[Any] = []
    evaluate_task(TASK, workspace, FakeModel([reply, reply, reply]), Budget(3.0), HARNESS, attempts)
    assert [attempt.outcome for attempt in attempts] == ["APPLY_FAILED"] * 3
    assert "UTF-8" in attempts[0].detail
    assert workspace.files == workspace.original


def test_a_harness_error_inside_an_attempt_keeps_the_call_and_its_cost() -> None:
    class BrokenWrite(FakeWorkspace):
        def write(self, path: str, data: bytes) -> None:
            raise RuntimeError("disk full")

    attempts: list[Any] = []
    budget = Budget(3.0)
    with pytest.raises(RuntimeError, match="disk full"):
        evaluate_task(
            TASK, BrokenWrite(compiles=[], pocs=[]), FakeModel([GOOD]), budget, HARNESS, attempts
        )
    assert [attempt.outcome for attempt in attempts] == ["HARNESS_ERROR"]
    assert attempts[0].model_cost_usd == pytest.approx(0.00039)
    assert budget.spent_usd == pytest.approx(0.00039)


def test_the_client_has_no_hidden_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    import openai

    seen: dict[str, Any] = {}

    class Recorder:
        def __init__(self, **kwargs: Any) -> None:
            seen.update(kwargs)

    monkeypatch.setattr(openai, "OpenAI", Recorder)
    monkeypatch.setenv("NEBIUS_API_KEY", "k" * 40)
    TokenFactoryModel()
    assert seen["max_retries"] == 0
