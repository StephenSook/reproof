import { stepKey, type DoorStepEvent } from "@/lib/events";
import { NOT_IN_RECORDED_SUMMARY, type RecordedTask } from "@/lib/recorded";

export type SummarySource = "LIVE" | "RECORDED";

export type VulnerableState = "CRASHED" | "CLEAN" | "UNCLEAR";
export type FixedState = "CLEAN" | "NOT_CLEAN";

export type VulnerableTile = {
  state: VulnerableState | null;
  crashType: string | null;
  topFrame: string | null;
  sanitizer: string | null;
  exitCode: number | null;
};

export type FixedTile = {
  state: FixedState | null;
  exitCode: number | null;
};

export type AncestryRibbon = {
  ancestry: "CONTAINS_FIX" | "DOES_NOT_CONTAIN_FIX";
  tag: string;
  commit: string;
  shortCommit: string;
};

export type PublicLink = { href: string; label: string };

export type PublicSummary =
  | { kind: "NOT_RECORDED"; line: string }
  | { kind: "PENDING"; line: string }
  | { kind: "NOT_RUN"; line: string }
  | {
      kind: "STATUS";
      state: string;
      line: string;
      ancestrySentence: string | null;
      link: PublicLink | null;
      ribbon: AncestryRibbon | null;
      reusedFrom: string | null;
    };

export type SummaryTotals = {
  seconds: number | null;
  usd: number | null;
  tavilyCredits: number | null;
  tavilyUnanswered: number;
  modelCalls: number | null;
};

export type DoorSummary = {
  source: SummarySource;
  verdict: string | null;
  sentence: string;
  details: string[];
  duplicateIds: string[];
  vulnerable: VulnerableTile;
  fixed: FixedTile;
  publicStatus: PublicSummary;
  totals: SummaryTotals;
};

export type LiveResult = {
  verdict: string;
  reason: string;
  missing_details: string[];
  wall_seconds: number | null;
  card: Record<string, unknown> | null;
};

export const PUBLIC_UNAVAILABLE_LINE =
  "No page was read, so this says nothing either way about whether the crash is public.";
export const PUBLIC_NO_PAGE_LINE = "No public page passed the checks for this crash.";
export const PUBLIC_PENDING_LINE = "Waiting for the public-status step.";
export const PUBLIC_NOT_RUN_LINE = "This result has no public-status step.";
export const PUBLIC_NOT_RECORDED_LINE = `The public-status lookup is ${NOT_IN_RECORDED_SUMMARY}.`;
export const RUNNING_SENTENCE = "Triage is running. Each part of this summary fills in when its step arrives.";
export const ENDED_SENTENCE = "The stream ended before a verdict arrived.";

type Row = Record<string, unknown>;

function record(value: unknown): Row | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Row) : null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function bool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function texts(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function rows(value: unknown): Row[] {
  if (!Array.isArray(value)) return [];
  return value.map(record).filter((item): item is Row => item !== null);
}

export function safeHttpUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.href;
  } catch {
    return null;
  }
}

/** The card line for a CONTAINS_FIX row, in the same words the Python sentence uses. */
export function ancestrySentence(row: Row, projectName: string): string | null {
  const ancestry = text(row.ancestry) ?? "";
  const version = text(row.upstream_version) ?? "";
  const tag = text(row.checked_tag) ?? "";
  const commit = text(row.checked_commit) ?? "";
  if (ancestry !== "CONTAINS_FIX" || !version || !tag || commit.length < 7) return null;
  const name = projectName.trim() || "this project";
  return `Fixed in ${name} ${version}. Git ancestry: tag ${tag} contains OSV fix ${commit.slice(0, 7)}.`;
}

export function verdictSentence(verdict: string | null, duplicateIds: string[]): string {
  if (verdict === "REPRODUCED") return "The vulnerable build crashed and the fixed build was clean.";
  if (verdict === "DUPLICATE") {
    return duplicateIds.length
      ? `The crash matches another OSV report: ${duplicateIds.join(", ")}.`
      : "The crash matches another OSV report.";
  }
  if (verdict === "NOT_REPRODUCED") return "The vulnerable build ran clean, so the reported crash did not reproduce.";
  if (verdict === "NEEDS_INFO") return "A detail is missing, so this is not a conclusive verdict.";
  if (verdict) return "The service returned a verdict.";
  return RUNNING_SENTENCE;
}

/** Crash state counts as a conclusive crash only when every frame is real, as the evaluation schema requires. */
function hasConclusiveState(state: string[]): boolean {
  return state.length > 0 && !(state.length === 1 && state[0] === "NULL") && state.every((frame) => frame.trim());
}

export function recordedSummary(task: RecordedTask): DoorSummary {
  const crashed = hasConclusiveState(task.crash_state);
  const duplicateIds = [...task.duplicate_candidates];
  return {
    source: "RECORDED",
    verdict: task.verdict,
    sentence: verdictSentence(task.verdict, duplicateIds),
    details: [],
    duplicateIds,
    vulnerable: {
      state: crashed ? "CRASHED" : task.vulnerable_clean ? "CLEAN" : "UNCLEAR",
      crashType: crashed ? text(task.crash_type) : null,
      topFrame: crashed ? (task.crash_state[0] ?? null) : null,
      sanitizer: crashed ? text(task.sanitizer_kind) : null,
      exitCode: task.vulnerable_exit_code,
    },
    fixed: { state: task.fix_clean ? "CLEAN" : "NOT_CLEAN", exitCode: task.fixed_exit_code },
    publicStatus: { kind: "NOT_RECORDED", line: PUBLIC_NOT_RECORDED_LINE },
    totals: {
      seconds: task.wall_seconds,
      usd: task.cost_usd,
      tavilyCredits: null,
      tavilyUnanswered: 0,
      modelCalls: task.model_request_ids.length,
    },
  };
}

function findStep(steps: DoorStepEvent[], key: string): Row | null {
  const found = steps.find((step) => stepKey(step) === key);
  return found ? found.payload : null;
}

/** Public-status fields from the step payload, or from the card when no step was sent. */
type PublicFields = {
  state: string;
  project: string;
  credits: number | null;
  unanswered: number;
  reusedFrom: string | null;
  evidence: Row[];
  modelRequestIds: string[];
};

function publicFields(payload: Row, fallbackProject: string): PublicFields {
  return {
    state: text(payload.state) ?? "",
    project: text(payload.project) ?? fallbackProject,
    credits: num(payload.credits) ?? num(payload.tavily_credits),
    unanswered: num(payload.unanswered_credits) ?? num(payload.tavily_unanswered_credits) ?? 0,
    reusedFrom: text(payload.reused_from),
    evidence: rows(payload.evidence),
    modelRequestIds: texts(payload.model_request_ids).length
      ? texts(payload.model_request_ids)
      : rows(payload.model_calls)
          .map((call) => text(call.request_id))
          .filter((id): id is string => id !== null),
  };
}

function ribbonFor(row: Row): AncestryRibbon | null {
  const ancestry = text(row.ancestry);
  const tag = text(row.checked_tag);
  const commit = text(row.checked_commit);
  if ((ancestry !== "CONTAINS_FIX" && ancestry !== "DOES_NOT_CONTAIN_FIX") || !tag || !commit || commit.length < 7) {
    return null;
  }
  return { ancestry, tag, commit, shortCommit: commit.slice(0, 7) };
}

function linkFor(row: Row): PublicLink | null {
  const url = text(row.url);
  const href = url ? safeHttpUrl(url) : null;
  if (!href) return null;
  return { href, label: text(row.title) ?? href };
}

function pagesLine(count: number): string {
  return count === 1
    ? "1 public page passed the checks for this crash."
    : `${count} public pages passed the checks for this crash.`;
}

function publicSummary(fields: PublicFields): PublicSummary {
  const base = { kind: "STATUS" as const, state: fields.state, reusedFrom: fields.reusedFrom };
  if (fields.state === "LOOKUP_UNAVAILABLE") {
    return { ...base, line: PUBLIC_UNAVAILABLE_LINE, ancestrySentence: null, link: null, ribbon: null };
  }
  for (const row of fields.evidence) {
    const sentence = ancestrySentence(row, fields.project);
    if (sentence) {
      return { ...base, line: sentence, ancestrySentence: sentence, link: linkFor(row), ribbon: ribbonFor(row) };
    }
  }
  if (fields.evidence.length === 0) {
    return { ...base, line: PUBLIC_NO_PAGE_LINE, ancestrySentence: null, link: null, ribbon: null };
  }
  const decided = fields.evidence.find((row) => ribbonFor(row) !== null);
  const linked = decided ?? fields.evidence.find((row) => linkFor(row) !== null) ?? null;
  return {
    ...base,
    line: pagesLine(fields.evidence.length),
    ancestrySentence: null,
    link: linked ? linkFor(linked) : null,
    ribbon: decided ? ribbonFor(decided) : null,
  };
}

/** The result event as the page keeps it. Nothing is filled in that the event did not send. */
export function liveResultFrom(raw: Row): LiveResult {
  return {
    verdict: typeof raw.verdict === "string" ? raw.verdict : String(raw.verdict ?? ""),
    reason: typeof raw.reason === "string" ? raw.reason : "",
    missing_details: Array.isArray(raw.missing_details) ? raw.missing_details.map(String) : [],
    wall_seconds: num(raw.wall_seconds),
    card: record(raw.card),
  };
}

/** Build the answer-first summary from what the stream has sent so far. */
export function liveSummary(
  steps: DoorStepEvent[],
  result: LiveResult | null,
  { ended = false }: { ended?: boolean } = {},
): DoorSummary {
  const card = result?.card ?? null;
  const evidence = record(card?.evidence);
  const cardCrash = record(evidence?.crash);
  const operations = rows(card?.sandbox_operations);
  const operation = (kind: string) => operations.find((row) => row.kind === kind) ?? null;

  const claim = findStep(steps, "claim");
  const vul = findStep(steps, "sandbox:vul");
  const fix = findStep(steps, "sandbox:fix");
  const crash = findStep(steps, "crash");
  const duplicates = findStep(steps, "duplicates");
  const publicStep = findStep(steps, "public_status");
  const verdictStep = findStep(steps, "verdict");

  const verdict = text(result?.verdict) ?? text(verdictStep?.verdict);

  let vulnerableState: VulnerableState | null = null;
  if (crash && bool(crash.vulnerable_crashed) !== null) {
    vulnerableState = crash.vulnerable_crashed ? "CRASHED" : crash.vulnerable_clean === true ? "CLEAN" : "UNCLEAR";
  } else if (cardCrash) {
    vulnerableState = "CRASHED";
  }
  const crashed = vulnerableState === "CRASHED";
  const crashState = crash ? texts(crash.crash_state) : texts(cardCrash?.crash_state);
  const vulnerable: VulnerableTile = {
    state: vulnerableState,
    crashType: crashed ? (text(crash?.crash_type) ?? text(cardCrash?.crash_type)) : null,
    topFrame: crashed ? (crashState[0] ?? null) : null,
    sanitizer: crashed ? (text(crash?.sanitizer_kind) ?? text(cardCrash?.sanitizer_kind)) : null,
    exitCode: num(crash?.vulnerable_exit_code) ?? num(vul?.exit_code) ?? num(operation("vul")?.exit_code),
  };

  const fixClean = bool(crash?.fix_clean) ?? bool(evidence?.fix_clean);
  const fixed: FixedTile = {
    state: fixClean === null ? null : fixClean ? "CLEAN" : "NOT_CLEAN",
    exitCode: num(crash?.fixed_exit_code) ?? num(fix?.exit_code) ?? num(evidence?.fixed_exit_code) ?? num(operation("fix")?.exit_code),
  };

  const duplicateIds = (duplicates ? rows(duplicates.candidates) : rows(evidence?.duplicate_candidates))
    .map((row) => text(row.id))
    .filter((id): id is string => id !== null);

  const details = verdict === "NEEDS_INFO"
    ? [
        ...new Set([
          ...(result?.missing_details ?? []),
          ...texts(verdictStep?.missing_details),
          ...(result?.reason ? [result.reason] : []),
          ...(text(verdictStep?.reason) ? [String(verdictStep?.reason)] : []),
        ]),
      ].filter((detail) => detail.trim())
    : [];

  const cardPublic = record(card?.public_status);
  const projectName = text(card?.project) ?? "";
  const publicPayload = publicStep ?? cardPublic;
  const fields = publicPayload ? publicFields(publicPayload, projectName) : null;
  const finished = ended || result !== null || verdictStep !== null;
  let publicStatus: PublicSummary;
  if (fields) publicStatus = publicSummary(fields);
  else if (finished) publicStatus = { kind: "NOT_RUN", line: PUBLIC_NOT_RUN_LINE };
  else publicStatus = { kind: "PENDING", line: PUBLIC_PENDING_LINE };

  let modelCalls: number | null = null;
  const cardCalls = card && Array.isArray(card.model_calls) ? rows(card.model_calls) : null;
  if (cardCalls) {
    modelCalls = cardCalls.length;
  } else if (claim || fields) {
    const ids = new Set<string>();
    let unnamed = 0;
    if (claim) {
      const id = text(claim.request_id);
      if (id) ids.add(id);
      else unnamed += 1;
    }
    for (const id of fields?.modelRequestIds ?? []) ids.add(id);
    modelCalls = ids.size + unnamed;
  }

  return {
    source: "LIVE",
    verdict,
    sentence: verdict === null && ended ? ENDED_SENTENCE : verdictSentence(verdict, duplicateIds),
    details,
    duplicateIds,
    vulnerable,
    fixed,
    publicStatus,
    totals: {
      seconds: num(result?.wall_seconds) ?? num(card?.wall_seconds) ?? num(verdictStep?.wall_seconds),
      usd: num(card?.total_cost_usd) ?? num(verdictStep?.total_cost_usd),
      tavilyCredits: fields ? fields.credits : null,
      tavilyUnanswered: fields ? fields.unanswered : 0,
      modelCalls,
    },
  };
}
