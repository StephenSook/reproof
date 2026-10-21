// Reads the committed offline patch evaluation (eval/results/patch-eval.json, copied byte for byte
// to web/src/content/patch-eval.json). Every number in the proof page's patch section comes from here.

export type PatchOutcome = "PROVEN" | "NOT_PROVEN" | "HARNESS_FAILED" | "BUDGET_STOPPED";

export type PatchRow = {
  arvo_id: number;
  project: string;
  outcome: PatchOutcome;
  detail: string;
  proven_attempt: number | null;
  attempt_outcomes: string[];
  model_calls: number;
  model_cost_usd: number;
  input_tokens: number;
  output_tokens: number;
  wall_seconds: number;
  request_ids: string[];
  baseline_crash_type: string;
  upstream_fix_commits: string[];
  upstream_repository: string;
  proven_rationale: string;
  proven_diff: string;
  proven_regression_check: string;
  card_path: string;
};

export type PatchReport = {
  prereg: { path: string; sha256: string; commit: string; head: string };
  started_at_utc: string;
  finished_at_utc: string;
  model: string;
  temperature: number;
  max_attempts: number;
  budget_usd: number;
  task_ids: number[];
  tasks: PatchRow[];
  totals: {
    tasks: number;
    recorded: number;
    proven: number;
    not_proven: number;
    harness_failed: number;
    budget_stopped: number;
    attempts_per_proven: number[];
    model_calls: number;
    input_tokens: number;
    output_tokens: number;
    model_cost_usd: number;
    wall_seconds: number;
  };
};

export type PatchHeadline = {
  proven: number;
  total: number;
  sentence: string;
  attempts: string;
  calls: number;
  costUsd: number;
  breakdown: { outcome: PatchOutcome; count: number; text: string }[];
};

const OUTCOME_TEXT: Record<PatchOutcome, string> = {
  PROVEN: "Proven",
  NOT_PROVEN: "Not proven",
  HARNESS_FAILED: "Harness failed",
  BUDGET_STOPPED: "Budget stopped",
};

const ATTEMPT_TEXT: Record<string, string> = {
  PROVEN: "proven",
  MODEL_ERROR: "no usable reply",
  APPLY_FAILED: "edit did not apply",
  COMPILE_FAILED: "build failed",
  STILL_CRASHES: "still crashed",
  POC_NOT_CLEAN: "run not clean",
  REGRESSION: "seed corpus failed",
};

export function outcomeText(outcome: PatchOutcome): string {
  return OUTCOME_TEXT[outcome] ?? outcome;
}

export function attemptText(outcome: string): string {
  return ATTEMPT_TEXT[outcome] ?? outcome;
}

/** "1, 1 and 3", or an empty string when nothing was proven. */
function joinCounts(values: number[]): string {
  if (values.length <= 1) return values.map(String).join("");
  return `${values.slice(0, -1).join(", ")} and ${values.at(-1)}`;
}

export function patchHeadline(report: PatchReport): PatchHeadline {
  const totals = report.totals;
  const order: PatchOutcome[] = ["PROVEN", "NOT_PROVEN", "HARNESS_FAILED", "BUDGET_STOPPED"];
  const breakdown = order
    .map((outcome) => ({ outcome, count: report.tasks.filter((row) => row.outcome === outcome).length }))
    .filter((row) => row.count > 0)
    .map((row) => ({ ...row, text: `${row.count} ${outcomeText(row.outcome).toLowerCase()}` }));
  const attempts = totals.attempts_per_proven.length
    ? `Proven on attempt ${joinCounts(totals.attempts_per_proven)} of ${report.max_attempts}.`
    : `No fix was proven within ${report.max_attempts} attempts.`;
  return {
    proven: totals.proven,
    total: totals.tasks,
    sentence: "bugs got a patch that rebuilt and no longer crashed on the stored input.",
    attempts,
    calls: totals.model_calls,
    costUsd: totals.model_cost_usd,
    breakdown,
  };
}

/** The upstream fix commit as a GitHub link, when the project's repository is known. */
export function upstreamCommitUrl(row: PatchRow): string | null {
  const commit = row.upstream_fix_commits[0];
  if (!commit || !row.upstream_repository.startsWith("https://github.com/")) return null;
  return `${row.upstream_repository}/commit/${commit}`;
}

/** Post-hoc notes recomputed from the cards (eval/results/patch-eval-notes.json). */
export type PatchNotes = {
  method: string;
  tasks: { arvo_id: number; blocked_attempts: number[]; blocking_line: string; built_attempts: number[] }[];
  totals: {
    attempts: number;
    blocked_attempts: number;
    tasks_with_blocked_attempts: number;
    attempts_that_built: number;
    tasks_where_an_edit_built: number;
  };
};

/** "1, 2 and 3" for attempt numbers. */
export function attemptList(values: number[]): string {
  return joinCounts(values);
}

export function blockedSentence(attempts: number[], line: string): string {
  if (!attempts.length) return "";
  const which = attempts.length === 1 ? `Attempt ${attempts[0]}` : `Attempts ${attemptList(attempts)}`;
  return `${which} never tested the edit: the build script stopped at "${line}" because the control build had already run it.`;
}
