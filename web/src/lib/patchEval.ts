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

/**
 * What each proven edit does, in one plain sentence written from its diff, keyed "run:arvo_id".
 * The test suite checks there is one for every proven row of every run and none for any other.
 */
export const PLAIN_PATCH: Record<string, string> = {
  "1:42530604":
    "Makes the buffer for a number's text in jv.c bigger: digits + 14 bytes becomes digits + 25. The upstream fix made it digits + 15.",
  "1:42508390":
    "Rewrites the JSON number parser in jplist.c by hand, reading digits in a loop that stops at the end of the token instead of calling strtol. Floats still go to atof.",
  "2:42507851":
    "Copies the number into a new buffer that ends in a NUL byte and runs strtol and the float checks on the copy, so parsing stops at the end of the token. Floats still go to atof on the original text.",
  "2:42508390":
    "Rejects a number that is a lone minus sign, or a minus sign not followed by a digit, before strtol runs. The rest of the parser is unchanged, only indented one level deeper.",
};

export function plainPatch(runKey: string, arvoId: number): string {
  return PLAIN_PATCH[`${runKey}:${arvoId}`] ?? "";
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

/** One registered run: its committed report and the notes recomputed from its cards. */
export type PatchRun = {
  key: string;
  title: string;
  report: PatchReport;
  notes: PatchNotes;
};

const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

/** "October 21, 15:21 to 15:42 UTC", read from the report's own UTC timestamps. */
export function runWindow(report: PatchReport): string {
  const day = (stamp: string) => `${MONTHS[Number(stamp.slice(5, 7)) - 1]} ${Number(stamp.slice(8, 10))}`;
  const time = (stamp: string) => stamp.slice(11, 16);
  const start = report.started_at_utc;
  const end = report.finished_at_utc;
  const endText = day(end) === day(start) ? time(end) : `${day(end)}, ${time(end)}`;
  return `${day(start)}, ${time(start)} to ${endText} UTC`;
}

/** "jq ARVO 42530604 on attempt 2; libplist ARVO 42508390 on attempt 3", or "" when none. */
export function provenList(report: PatchReport): string {
  return report.tasks
    .filter((row) => row.outcome === "PROVEN")
    .map((row) => `${row.project} ARVO ${row.arvo_id} on attempt ${row.proven_attempt}`)
    .join("; ");
}

export type PatchCell = { run: PatchRun; row: PatchRow; note: PatchNotes["tasks"][number] | undefined };

export type PatchTaskPair = { arvo_id: number; project: string; baseline_crash_type: string; cells: PatchCell[] };

/** One entry per task, in the registered order, with each run's row for it side by side. */
export function pairTasks(runs: PatchRun[]): PatchTaskPair[] {
  const first = runs[0];
  if (!first) return [];
  return first.report.task_ids.map((id) => {
    const cells = runs.flatMap((run) => {
      const row = run.report.tasks.find((task) => task.arvo_id === id);
      return row ? [{ run, row, note: run.notes.tasks.find((task) => task.arvo_id === id) }] : [];
    });
    const crash = cells.map((cell) => cell.row.baseline_crash_type).find(Boolean) ?? "";
    return { arvo_id: id, project: cells[0]?.row.project ?? "", baseline_crash_type: crash, cells };
  });
}

/** What a run's notes say about attempts a build script stopped before they tested an edit. */
export function harnessSentence(notes: PatchNotes): string {
  const totals = notes.totals;
  const tasks = totals.tasks_where_an_edit_built === 1 ? "task" : "tasks";
  const built = `${totals.attempts_that_built} of the ${totals.attempts} attempts, in ${totals.tasks_where_an_edit_built} ${tasks}, built an edit.`;
  if (!totals.blocked_attempts) return `No attempt stopped at a build script's plain mkdir. ${built}`;
  const images = totals.tasks_with_blocked_attempts === 1 ? "image" : "images";
  return `${totals.blocked_attempts} of the ${totals.attempts} attempts stopped at a build script's plain mkdir, in ${totals.tasks_with_blocked_attempts} ${images}, before testing their edit. ${built}`;
}

export function blockedSentence(attempts: number[], line: string): string {
  if (!attempts.length) return "";
  const which = attempts.length === 1 ? `Attempt ${attempts[0]}` : `Attempts ${attemptList(attempts)}`;
  return `${which} never tested the edit: the build script stopped at "${line}" because the control build had already run it.`;
}
