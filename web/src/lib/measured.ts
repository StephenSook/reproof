export const PHASE1_NOTE =
  "On 2026-10-05, review of the saved cards found that the phase 1 table counted four self-matches; the duplicate search now excludes every OSV record mapped to the task's own OSS-Fuzz issue.";

export type Limits = {
  in_flight_per_visitor: number;
  per_ip_per_hour: number;
  global_per_day: number;
  tavily_credits_per_day: number;
  public_reuse_seconds: number;
};

export type MeasuredEvaluation = {
  tasks: { verdict: string }[];
  totals: {
    tasks_completed: number;
    tasks_requested: number;
    crash_state_agreements: number;
    fixes_clean: number;
    claims_agree: number;
    total_duplicate_candidates: number;
    total_input_tokens: number;
    total_output_tokens: number;
    total_model_cost_usd: number;
    total_sandbox_cost_usd: number;
    total_cost_usd: number;
    total_wall_seconds: number;
  };
};

export function verdictCounts(tasks: { verdict: string }[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const task of tasks) counts[task.verdict] = (counts[task.verdict] ?? 0) + 1;
  return counts;
}

export function money(value: number): string {
  return value.toFixed(8);
}

export function seconds(value: number): string {
  return value.toFixed(6);
}

export function limitsSentence(limits: Limits): string {
  const running =
    limits.in_flight_per_visitor === 1
      ? "1 triage"
      : `${limits.in_flight_per_visitor} triages`;
  return [
    `This browser can run ${running} at a time.`,
    `This address can start ${limits.per_ip_per_hour} triages per hour.`,
    `Everyone shares ${limits.global_per_day} triages per day.`,
    `The public-status lookup spends at most ${limits.tavily_credits_per_day} Tavily credits per UTC day,`,
    `and a lookup of the same measured crash is reused for ${limits.public_reuse_seconds / 60} minutes.`,
    "On Vercel, each function instance keeps its own count file.",
    "Instances do not share a disk.",
  ].join(" ");
}

export function measuredSummary(evaluation: MeasuredEvaluation): string[] {
  const counts = verdictCounts(evaluation.tasks);
  const totals = evaluation.totals;
  return [
    ...Object.keys(counts)
      .sort()
      .map((verdict) => `${counts[verdict]} ${verdict}`),
    `${totals.tasks_completed} of ${totals.tasks_requested} tasks completed`,
    `${totals.crash_state_agreements} crash states agreed`,
    `${totals.fixes_clean} fixes clean`,
    `${totals.claims_agree} claims agreed`,
    `${totals.total_duplicate_candidates} duplicate candidates`,
    `${totals.total_input_tokens} input tokens`,
    `${totals.total_output_tokens} output tokens`,
    `${money(totals.total_model_cost_usd)} model USD`,
    `${money(totals.total_sandbox_cost_usd)} sandbox USD`,
    `${money(totals.total_cost_usd)} combined USD`,
    `${seconds(totals.total_wall_seconds)} seconds`,
    PHASE1_NOTE,
  ];
}
