import { describe, expect, it } from "vitest";
import {
  attemptText,
  blockedSentence,
  outcomeText,
  patchHeadline,
  upstreamCommitUrl,
  type PatchReport,
  type PatchRow,
} from "../src/lib/patchEval";

function row(overrides: Partial<PatchRow>): PatchRow {
  return {
    arvo_id: 1,
    project: "demo",
    outcome: "NOT_PROVEN",
    detail: "3 attempts; last: STILL_CRASHES",
    proven_attempt: null,
    attempt_outcomes: ["APPLY_FAILED", "COMPILE_FAILED", "STILL_CRASHES"],
    model_calls: 3,
    model_cost_usd: 0.003,
    input_tokens: 30000,
    output_tokens: 600,
    wall_seconds: 300,
    request_ids: ["a", "b", "c"],
    baseline_crash_type: "Heap-buffer-overflow WRITE {*}",
    upstream_fix_commits: ["71c2ab509a8628dbbad4bc7b3f98a64aa90d3297"],
    upstream_repository: "https://github.com/jqlang/jq",
    proven_rationale: "",
    proven_diff: "",
    proven_regression_check: "",
    card_path: "eval/results/patch-cards/1.json",
    ...overrides,
  };
}

function report(tasks: PatchRow[], attempts: number[]): PatchReport {
  const count = (outcome: string) => tasks.filter((task) => task.outcome === outcome).length;
  return {
    prereg: { path: "eval/PATCH-PREREG.md", sha256: "0".repeat(64), commit: "abc1234def", head: "abc1234def" },
    started_at_utc: "s",
    finished_at_utc: "f",
    model: "nvidia/nemotron-3-super-120b-a12b",
    temperature: 0,
    max_attempts: 3,
    budget_usd: 3,
    task_ids: tasks.map((task) => task.arvo_id),
    tasks,
    totals: {
      tasks: 10,
      recorded: tasks.length,
      proven: count("PROVEN"),
      not_proven: count("NOT_PROVEN"),
      harness_failed: count("HARNESS_FAILED"),
      budget_stopped: count("BUDGET_STOPPED"),
      attempts_per_proven: attempts,
      model_calls: tasks.reduce((sum, task) => sum + task.model_calls, 0),
      input_tokens: 0,
      output_tokens: 0,
      model_cost_usd: 0.0123,
      wall_seconds: 0,
    },
  };
}

describe("patch evaluation headline", () => {
  it("states proven of total, the attempts, and every other outcome", () => {
    const tasks = [
      row({ arvo_id: 1, outcome: "PROVEN", proven_attempt: 1, attempt_outcomes: ["PROVEN"], model_calls: 1 }),
      row({ arvo_id: 2, outcome: "PROVEN", proven_attempt: 3, attempt_outcomes: ["APPLY_FAILED", "STILL_CRASHES", "PROVEN"] }),
      row({ arvo_id: 3 }),
      row({ arvo_id: 4, outcome: "HARNESS_FAILED", attempt_outcomes: [], model_calls: 0 }),
    ];
    const headline = patchHeadline(report(tasks, [1, 3]));
    expect(headline.proven).toBe(2);
    expect(headline.total).toBe(10);
    expect(headline.attempts).toBe("Proven on attempt 1 and 3 of 3.");
    expect(headline.calls).toBe(7);
    expect(headline.costUsd).toBe(0.0123);
    expect(headline.breakdown.map((item) => item.text)).toEqual(["2 proven", "1 not proven", "1 harness failed"]);
  });

  it("shows zero as zero", () => {
    const headline = patchHeadline(report([row({})], []));
    expect(headline.proven).toBe(0);
    expect(headline.sentence).toBe("bugs got a patch that rebuilt and no longer crashed on the stored input.");
    expect(headline.attempts).toBe("No fix was proven within 3 attempts.");
  });

  it("names outcomes in words and links the upstream fix only on GitHub", () => {
    expect(outcomeText("HARNESS_FAILED")).toBe("Harness failed");
    expect(attemptText("COMPILE_FAILED")).toBe("build failed");
    expect(attemptText("SOMETHING_NEW")).toBe("SOMETHING_NEW");
    expect(upstreamCommitUrl(row({}))).toBe("https://github.com/jqlang/jq/commit/71c2ab509a8628dbbad4bc7b3f98a64aa90d3297");
    expect(upstreamCommitUrl(row({ upstream_repository: "https://example.org/x" }))).toBeNull();
    expect(upstreamCommitUrl(row({ upstream_fix_commits: [] }))).toBeNull();
  });
});

describe("the committed patch evaluation", () => {
  it("reads its headline and notes from the committed files", async () => {
    const committed = (await import("../src/content/patch-eval.json")).default as unknown as PatchReport;
    const notes = (await import("../src/content/patch-eval-notes.json")).default as unknown as {
      totals: { attempts: number };
    };
    const headline = patchHeadline(committed);
    expect(headline.proven).toBe(committed.tasks.filter((task) => task.outcome === "PROVEN").length);
    expect(headline.total).toBe(10);
    expect(headline.calls).toBe(notes.totals.attempts);
    expect(blockedSentence([1, 2, 3], "mkdir: x")).toBe(
      'Attempts 1, 2 and 3 never tested the edit: the build script stopped at "mkdir: x" because the control build had already run it.',
    );
    expect(blockedSentence([2], "m")).toMatch(/^Attempt 2 never/);
    expect(blockedSentence([], "m")).toBe("");
  });
});
