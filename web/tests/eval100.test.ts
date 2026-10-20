import { describe, expect, it } from "vitest";
import { failureCause, missesOf, proofRows, runAgreement, runHeadline, type Eval100Report, type Eval100Task } from "../src/lib/eval100";

function task(arvoId: number, overrides: Partial<Eval100Task> = {}): Eval100Task {
  return {
    arvo_id: arvoId,
    project: `p${arvoId}`,
    verdict: "REPRODUCED",
    crash_state_agreement_with_osv: true,
    fix_clean: true,
    claim_agreement: true,
    crash_type: "Heap-buffer-overflow READ 1",
    vulnerable_exit_code: 1,
    fixed_exit_code: 0,
    duplicate_candidates: [],
    cost_usd: 0.001,
    wall_seconds: 10,
    card_path: `eval/results/cards/${arvoId}.json`,
    ...overrides,
  };
}

const report: Eval100Report = {
  selection_rule: "rule",
  historical_arvo_ids: [1, 2],
  random_draw_arvo_ids: [3, 4, 5],
  selected_arvo_ids: [1, 2, 3, 4, 5],
  prep_failed: [],
  run_failed: [
    {
      arvo_id: 4,
      project: "p4",
      attempts: 2,
      error_type: "TriageExecutionError",
      error: "Token Factory claim extraction failed: APIConnectionError: Connection error.",
    },
  ],
  tasks: [
    task(1),
    task(2, { fix_clean: false }),
    task(3, { verdict: "NEEDS_INFO", crash_state_agreement_with_osv: false, claim_agreement: false }),
    task(5, { verdict: "DUPLICATE" }),
  ],
  totals: { tasks_requested: 5, tasks_completed: 4, total_cost_usd: 0.05, total_wall_seconds: 50 },
};

describe("eval-100 proof rows", () => {
  it("puts runs that failed first, then misses with the most reasons, then the rest in run order", () => {
    const rows = proofRows(report);
    expect(rows.map((row) => (row.kind === "failed" ? row.failure.arvo_id : row.task.arvo_id))).toEqual([4, 3, 2, 1, 5]);
    expect(rows.map((row) => row.position)).toEqual([4, 3, 2, 1, 5]);
  });

  it("names every miss in words", () => {
    expect(missesOf(report.tasks[2])).toEqual([
      "The verdict is NEEDS_INFO, not a measured crash.",
      "The measured crash state differs from the one OSV recorded.",
      "The claim read from the report disagrees with the measured crash.",
    ]);
    expect(missesOf(report.tasks[3])).toEqual([]);
  });

  it("says a run that never reached the bug could not test it", () => {
    const stuck = task(9, { verdict: "NEEDS_INFO", vulnerable_exit_code: 127, fixed_exit_code: 127, fix_clean: false, crash_state_agreement_with_osv: false });
    expect(missesOf(stuck)).toEqual(["Both builds exited 127 without a sanitizer report, so this run could not test the bug."]);
  });

  it("counts against all selected tasks, failures included", () => {
    const headline = runHeadline(report);
    expect(headline).toMatchObject({
      requested: 5,
      completed: 4,
      crashMeasured: 3,
      osvAgree: 3,
      fixClean: 3,
      claimAgree: 3,
      failed: 1,
      failureCauses: [{ cause: "Lost the connection to Token Factory twice", count: 1 }],
    });
    expect(headline.costPerTaskUsd).toBeCloseTo(0.01);
  });

  it("refuses a selected task with neither a result nor a failure row", () => {
    expect(() => proofRows({ ...report, selected_arvo_ids: [...report.selected_arvo_ids, 6] })).toThrow("ARVO 6");
  });

  it("names a sandbox API status failure", () => {
    const error = "Triage failed after model request: CheckpointError: ConTree checkpoint creation failed: ApiStatusCodeError: ApiStatusCodeError(request=RequestInfo(url='https://api.tokenfactory.nebius.com/sandboxes/v1/files/x', method='POST'), response=ResponseInfo(headers={}), status=500, error='Internal Server Error')";
    expect(failureCause({ arvo_id: 1, project: "x", attempts: 1, error_type: "TriageExecutionError", error }))
      .toBe("The Nebius sandbox API answered HTTP 500");
  });

  it("counts tasks that completed in both runs and kept their verdict", () => {
    const later: Eval100Report = { ...report, tasks: [task(1), task(2, { verdict: "DUPLICATE" }), task(4)] };
    expect(runAgreement(report, later)).toEqual({ both: 2, sameVerdict: 1 });
  });

  it("names the decode failure and falls back to the error type", () => {
    expect(failureCause({ arvo_id: 1, project: "gpac", attempts: 1, error_type: "TriageExecutionError", error: "SandboxPairError: UnicodeDecodeError: 'utf-8'" }))
      .toBe("Sandbox output could not be decoded");
    expect(failureCause({ arvo_id: 1, project: "x", attempts: 1, error_type: "ValueError", error: "bad" }))
      .toBe("ValueError after 1 attempt");
  });
});
