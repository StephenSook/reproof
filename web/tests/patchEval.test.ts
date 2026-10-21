import { describe, expect, it } from "vitest";
import {
  attemptText,
  blockedSentence,
  harnessSentence,
  outcomeText,
  pairTasks,
  patchHeadline,
  PLAIN_PATCH,
  plainPatch,
  provenList,
  runWindow,
  upstreamCommitUrl,
  type PatchNotes,
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

function notes(blocked: number, built: number, attempts: number): PatchNotes {
  return {
    method: "m",
    tasks: [{ arvo_id: 1, blocked_attempts: blocked ? [1] : [], blocking_line: blocked ? "mkdir: x" : "", built_attempts: [] }],
    totals: {
      attempts,
      blocked_attempts: blocked,
      tasks_with_blocked_attempts: blocked ? 1 : 0,
      attempts_that_built: built,
      tasks_where_an_edit_built: built ? 2 : 0,
    },
  };
}

describe("two registered runs side by side", () => {
  it("reads the run window from the report's own UTC timestamps", () => {
    const base = report([row({})], []);
    expect(runWindow({ ...base, started_at_utc: "2026-10-21T15:21:12+00:00", finished_at_utc: "2026-10-21T15:42:59+00:00" })).toBe(
      "October 21, 15:21 to 15:42 UTC",
    );
    expect(runWindow({ ...base, started_at_utc: "2026-10-21T23:50:00+00:00", finished_at_utc: "2026-10-22T00:20:00+00:00" })).toBe(
      "October 21, 23:50 to October 22, 00:20 UTC",
    );
  });

  it("names each proven task with its attempt, and nothing when none was proven", () => {
    const tasks = [
      row({ arvo_id: 7, project: "jq", outcome: "PROVEN", proven_attempt: 2 }),
      row({ arvo_id: 8 }),
      row({ arvo_id: 9, project: "libplist", outcome: "PROVEN", proven_attempt: 3 }),
    ];
    expect(provenList(report(tasks, [2, 3]))).toBe("jq ARVO 7 on attempt 2; libplist ARVO 9 on attempt 3");
    expect(provenList(report([row({})], []))).toBe("");
  });

  it("pairs every task with each run's row in the registered order", () => {
    const first = { key: "1", title: "Run 1", report: report([row({ arvo_id: 1 }), row({ arvo_id: 2 })], []), notes: notes(1, 0, 6) };
    const second = {
      key: "2",
      title: "Run 2",
      report: report([row({ arvo_id: 2, outcome: "PROVEN", proven_attempt: 1 }), row({ arvo_id: 1 })], [1]),
      notes: notes(0, 4, 4),
    };
    const pairs = pairTasks([first, second]);
    expect(pairs.map((pair) => pair.arvo_id)).toEqual([1, 2]);
    expect(pairs[1]?.cells.map((cell) => [cell.run.key, cell.row.outcome])).toEqual([
      ["1", "NOT_PROVEN"],
      ["2", "PROVEN"],
    ]);
    expect(pairs[0]?.cells[0]?.note?.blocked_attempts).toEqual([1]);
    expect(pairTasks([])).toEqual([]);
  });

  it("says whether any attempt stopped at a build script's mkdir", () => {
    expect(harnessSentence(notes(0, 4, 4))).toBe(
      "No attempt stopped at a build script's plain mkdir. 4 of the 4 attempts, in 2 tasks, built an edit.",
    );
    expect(harnessSentence(notes(1, 0, 6))).toBe(
      "1 of the 6 attempts stopped at a build script's plain mkdir, in 1 image, before testing their edit. 0 of the 6 attempts, in 0 tasks, built an edit.",
    );
  });
});

describe("the committed run 2", () => {
  it("recomputes its headline from its own rows and keeps run 1 beside it", async () => {
    const run1 = (await import("../src/content/patch-eval.json")).default as unknown as PatchReport;
    const run2 = (await import("../src/content/patch-eval-run2.json")).default as unknown as PatchReport;
    const run2Notes = (await import("../src/content/patch-eval-run2-notes.json")).default as unknown as PatchNotes;
    expect(run2.task_ids).toEqual(run1.task_ids);
    expect(run2.prereg.path).toBe("eval/PATCH-PREREG-RUN2.md");
    expect(run2.prereg.commit).not.toBe(run1.prereg.commit);
    const headline = patchHeadline(run2);
    expect(headline.total).toBe(10);
    expect(headline.proven).toBe(run2.tasks.filter((task) => task.outcome === "PROVEN").length);
    expect(headline.calls).toBe(run2.tasks.reduce((sum, task) => sum + task.model_calls, 0));
    expect(headline.calls).toBe(run2Notes.totals.attempts);
    expect(run2.totals.model_cost_usd).toBeCloseTo(
      run2.tasks.reduce((sum, task) => sum + task.model_cost_usd, 0),
      7,
    );
    expect(run2.totals.model_cost_usd).toBeLessThanOrEqual(run2.budget_usd);
    expect(run2.tasks.every((task) => task.card_path.startsWith("eval/results/patch-eval-run2-cards/"))).toBe(true);
  });
});

describe("plain sentences for proven edits", () => {
  it("has one for every proven row of both runs and none for any other row", async () => {
    const run1 = (await import("../src/content/patch-eval.json")).default as unknown as PatchReport;
    const run2 = (await import("../src/content/patch-eval-run2.json")).default as unknown as PatchReport;
    const proven = [
      ...run1.tasks.filter((task) => task.outcome === "PROVEN").map((task) => `1:${task.arvo_id}`),
      ...run2.tasks.filter((task) => task.outcome === "PROVEN").map((task) => `2:${task.arvo_id}`),
    ];
    expect(Object.keys(PLAIN_PATCH).sort()).toEqual(proven.sort());
    for (const key of proven) {
      const [run, id] = key.split(":");
      expect(plainPatch(run ?? "", Number(id)).length).toBeGreaterThan(20);
    }
    expect(plainPatch("2", 42530604)).toBe("");
  });
});
