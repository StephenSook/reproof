// Reads a committed eval-100 report (eval/results/eval100*.json) for the proof page. Every count on
// the page comes from these functions, so the page cannot disagree with the file it cites.

export type Eval100Task = {
  arvo_id: number;
  project: string;
  verdict: string;
  crash_state_agreement_with_osv: boolean;
  fix_clean: boolean;
  claim_agreement: boolean;
  crash_type: string | null;
  vulnerable_exit_code: number;
  fixed_exit_code: number;
  duplicate_candidates: string[];
  cost_usd: number;
  wall_seconds: number;
  card_path: string;
};

export type Eval100Failure = {
  arvo_id: number;
  project: string;
  attempts: number;
  error_type: string;
  error: string;
};

export type Eval100Report = {
  selection_rule: string;
  historical_arvo_ids: number[];
  random_draw_arvo_ids: number[];
  selected_arvo_ids: number[];
  prep_failed: { arvo_id: number; project: string; reason: string }[];
  run_failed: Eval100Failure[];
  tasks: Eval100Task[];
  totals: {
    tasks_requested: number;
    tasks_completed: number;
    total_cost_usd: number;
    total_wall_seconds: number;
  };
};

export type ProofRow =
  | { kind: "failed"; position: number; failure: Eval100Failure; cause: string }
  | { kind: "task"; position: number; task: Eval100Task; misses: string[] };

// A verdict that says the crash was measured. ARVO tasks are known crashes, so anything else is a miss.
const MEASURED_VERDICTS = new Set(["REPRODUCED", "DUPLICATE"]);

export function missesOf(task: Eval100Task): string[] {
  // Both builds stopping with the same non-zero code and no sanitizer report means the run never
  // reached the bug (in eval-100 run 2: a 64-bit libm loaded for the target, or the target exiting).
  // Saying "the fix is not clean" there would describe the bug, which was never tested.
  if (!MEASURED_VERDICTS.has(task.verdict) && task.vulnerable_exit_code === task.fixed_exit_code && task.fixed_exit_code !== 0) {
    return [`Both builds exited ${task.fixed_exit_code} without a sanitizer report, so this run could not test the bug.`];
  }
  const misses: string[] = [];
  if (!MEASURED_VERDICTS.has(task.verdict)) misses.push(`The verdict is ${task.verdict}, not a measured crash.`);
  if (!task.crash_state_agreement_with_osv) misses.push("The measured crash state differs from the one OSV recorded.");
  if (!task.fix_clean) misses.push("The fixed build did not run clean.");
  if (!task.claim_agreement) misses.push("The claim read from the report disagrees with the measured crash.");
  return misses;
}

export function failureCause(failure: Eval100Failure): string {
  if (/Token Factory/.test(failure.error) && /APIConnectionError|APITimeoutError/.test(failure.error)) {
    return "Lost the connection to Token Factory twice";
  }
  if (/UnicodeDecodeError/.test(failure.error)) return "Sandbox output could not be decoded";
  const status = /sandboxes\/v1\/.*?status=(5\d\d)/.exec(failure.error);
  if (status) return `The Nebius sandbox API answered HTTP ${status[1]}`;
  return `${failure.error_type} after ${failure.attempts} ${failure.attempts === 1 ? "attempt" : "attempts"}`;
}

function rank(row: ProofRow): number {
  if (row.kind === "failed") return 0;
  return row.misses.length > 0 ? 1 : 2;
}

/** Every selected task in run order, with failed runs first, then misses (most first), then clean rows. */
export function proofRows(report: Eval100Report): ProofRow[] {
  const tasks = new Map(report.tasks.map((task) => [task.arvo_id, task]));
  const failures = new Map(report.run_failed.map((failure) => [failure.arvo_id, failure]));
  const rows = report.selected_arvo_ids.map((arvoId, index): ProofRow => {
    const position = index + 1;
    const failure = failures.get(arvoId);
    if (failure) return { kind: "failed", position, failure, cause: failureCause(failure) };
    const task = tasks.get(arvoId);
    if (!task) throw new Error(`ARVO ${arvoId} is selected but has neither a result nor a failure row.`);
    return { kind: "task", position, task, misses: missesOf(task) };
  });
  return rows.sort((a, b) => {
    const byRank = rank(a) - rank(b);
    if (byRank !== 0) return byRank;
    const missCount = (row: ProofRow) => (row.kind === "task" ? row.misses.length : 0);
    return missCount(b) - missCount(a) || a.position - b.position;
  });
}

export type RunHeadline = {
  requested: number;
  completed: number;
  crashMeasured: number;
  osvAgree: number;
  fixClean: number;
  claimAgree: number;
  failed: number;
  failureCauses: { cause: string; count: number }[];
  totalCostUsd: number;
  costPerTaskUsd: number;
};

export function runHeadline(report: Eval100Report): RunHeadline {
  const count = (keep: (task: Eval100Task) => boolean) => report.tasks.filter(keep).length;
  const causes = new Map<string, number>();
  for (const failure of report.run_failed) {
    const cause = failureCause(failure);
    causes.set(cause, (causes.get(cause) ?? 0) + 1);
  }
  const requested = report.selected_arvo_ids.length;
  return {
    requested,
    completed: report.tasks.length,
    crashMeasured: count((task) => MEASURED_VERDICTS.has(task.verdict)),
    osvAgree: count((task) => task.crash_state_agreement_with_osv),
    fixClean: count((task) => task.fix_clean),
    claimAgree: count((task) => task.claim_agreement),
    failed: report.run_failed.length,
    failureCauses: [...causes].map(([cause, n]) => ({ cause, count: n })).sort((a, b) => b.count - a.count),
    totalCostUsd: report.totals.total_cost_usd,
    costPerTaskUsd: requested ? report.totals.total_cost_usd / requested : 0,
  };
}

/** Tasks that completed in both runs, and how many of them got the same verdict both times. */
export function runAgreement(first: Eval100Report, second: Eval100Report): { both: number; sameVerdict: number } {
  const earlier = new Map(first.tasks.map((task) => [task.arvo_id, task.verdict]));
  const shared = second.tasks.filter((task) => earlier.has(task.arvo_id));
  return { both: shared.length, sameVerdict: shared.filter((task) => earlier.get(task.arvo_id) === task.verdict).length };
}

export function dollars(value: number, digits = 2): string {
  return `$${value.toFixed(digits)}`;
}
