import type { DoorEvent, DoorStepEvent } from "@/lib/events";
import { liveResultFrom, liveSummary, type DoorSummary, type LiveResult } from "@/lib/summary";

/**
 * One recorded response of the deployed door, as scripts/record_door_triage.py wrote it.
 * `events` are the NDJSON lines of the response body, in order; tests/test_door_receipt.py
 * holds them equal to the raw body and its SHA-256.
 */
export type DoorReceipt = {
  recorded_at_utc: string;
  url: string;
  request_body: { arvo_id: number };
  http_status: number;
  client_elapsed_seconds: number;
  events: DoorEvent[];
};

export type Replay = {
  steps: DoorStepEvent[];
  result: LiveResult | null;
  rawResult: Record<string, unknown> | null;
};

/** Feed the recorded events through the same reading the live stream gets. */
export function replayEvents(events: DoorEvent[]): Replay {
  const steps: DoorStepEvent[] = [];
  let rawResult: Record<string, unknown> | null = null;
  for (const event of events) {
    if (event.type === "step" && event.step) steps.push(event.step);
    if (event.type === "result" && event.result) rawResult = event.result;
  }
  return { steps, result: rawResult ? liveResultFrom(rawResult) : null, rawResult };
}

export function receiptArvoId(receipt: DoorReceipt): number {
  return receipt.request_body.arvo_id;
}

/** The answer-first summary of a recorded response. Every value comes from the recorded events. */
export function receiptSummary(receipt: DoorReceipt): DoorSummary {
  const { steps, result } = replayEvents(receipt.events);
  return { ...liveSummary(steps, result, { ended: true }), source: "RECORDED", recordedAt: receipt.recorded_at_utc };
}

/** "2026-10-20T23:45:01+00:00" as "2026-10-20 23:45 UTC". Only a UTC stamp is shortened. */
export function utcMinute(stamp: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2})?(?:\+00:00|Z)$/.exec(stamp);
  return match ? `${match[1]} ${match[2]} UTC` : stamp;
}
