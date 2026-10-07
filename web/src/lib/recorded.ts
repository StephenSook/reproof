import type { DoorStepEvent } from "@/lib/events";

export const NOT_IN_RECORDED_SUMMARY = "not in the recorded summary";

export type RecordedTask = {
  arvo_id: number;
  verdict: string;
  duplicate_candidates: string[];
  crash_type: string;
  crash_state: string[];
  sanitizer_kind: string;
  vulnerable_clean: boolean;
  fix_clean: boolean;
  vulnerable_exit_code: number;
  fixed_exit_code: number;
  model_request_ids: string[];
  input_tokens: number;
  output_tokens: number;
  model_cost_usd: number;
  sandbox_cost_usd: number;
  checkpoint_operation_uuids: string[];
  sandbox_operation_uuids: string[];
  cost_usd: number;
  wall_seconds: number;
};

export type RecordedView = {
  source: "RECORDED";
  card: null;
  verdict: string;
  reason: string;
  missing_details: string[];
  wall_seconds: number;
  model_cost_usd: number;
  sandbox_cost_usd: number;
  total_cost_usd: number;
  steps: DoorStepEvent[];
};

export function recordedView(task: RecordedTask): RecordedView {
  const sandbox = task.sandbox_operation_uuids;
  const checkpoint = task.checkpoint_operation_uuids;
  if (sandbox.length < 2 || checkpoint.length < 2) {
    throw new Error(`ARVO ${task.arvo_id} is missing a recorded branch operation id`);
  }
  const durationNote = "Per-branch duration is not in the recorded summary.";
  return {
    source: "RECORDED",
    card: null,
    verdict: task.verdict,
    reason: "",
    missing_details: [],
    wall_seconds: task.wall_seconds,
    model_cost_usd: task.model_cost_usd,
    sandbox_cost_usd: task.sandbox_cost_usd,
    total_cost_usd: task.cost_usd,
    steps: [
      {
        step: "claim",
        kind: null,
        payload: {
          request_id: task.model_request_ids[0] ?? "",
          input_tokens: task.input_tokens,
          output_tokens: task.output_tokens,
          cost_usd: task.model_cost_usd,
          model: NOT_IN_RECORDED_SUMMARY,
          bug_class: NOT_IN_RECORDED_SUMMARY,
        },
      },
      {
        step: "sandbox",
        kind: "vul",
        payload: {
          operation_uuid: sandbox[0],
          checkpoint_operation_uuid: checkpoint[0],
          wall_seconds: null,
          duration_note: durationNote,
        },
      },
      {
        step: "sandbox",
        kind: "fix",
        payload: {
          operation_uuid: sandbox[1],
          checkpoint_operation_uuid: checkpoint[1],
          wall_seconds: null,
          duration_note: durationNote,
        },
      },
      {
        step: "crash",
        kind: null,
        payload: {
          crash_type: task.crash_type,
          crash_state: task.crash_state,
          sanitizer_kind: task.sanitizer_kind,
          vulnerable_exit_code: task.vulnerable_exit_code,
          fixed_exit_code: task.fixed_exit_code,
        },
      },
      {
        step: "duplicates",
        kind: null,
        payload: {
          candidates: task.duplicate_candidates.map((id) => ({ id })),
          excluded_osv_ids: null,
          excluded_note: "Excluded OSV ids are not in the recorded summary.",
        },
      },
      {
        step: "verdict",
        kind: null,
        payload: {
          verdict: task.verdict,
          model_cost_usd: task.model_cost_usd,
          sandbox_cost_usd: task.sandbox_cost_usd,
          total_cost_usd: task.cost_usd,
          wall_seconds: task.wall_seconds,
        },
      },
    ],
  };
}
