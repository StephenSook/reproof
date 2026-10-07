import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import evaluation from "../src/content/arvo10.json";
import type { DoorStepEvent } from "../src/lib/events";
import {
  PUBLIC_NO_PAGE_LINE,
  PUBLIC_NOT_RECORDED_LINE,
  PUBLIC_NOT_RUN_LINE,
  PUBLIC_PENDING_LINE,
  PUBLIC_UNAVAILABLE_LINE,
  RUNNING_SENTENCE,
  liveResultFrom,
  liveSummary,
  recordedSummary,
  type LiveResult,
} from "../src/lib/summary";

// Written by tests/test_door.py from reproof/door.py and the ASGI serializer, with stubbed services.
const streamText = readFileSync(new URL("./fixtures/door-stream.ndjson", import.meta.url), "utf8");

type StreamEvent = { type: string; step?: DoorStepEvent; result?: Record<string, unknown> };

const events = streamText
  .split("\n")
  .map((line) => line.trim())
  .filter(Boolean)
  .map((line) => JSON.parse(line) as StreamEvent);

function replay(count: number): { steps: DoorStepEvent[]; result: LiveResult | null } {
  const steps: DoorStepEvent[] = [];
  let result: LiveResult | null = null;
  for (const event of events.slice(0, count)) {
    if (event.type === "step" && event.step) steps.push(event.step);
    if (event.type === "result" && event.result) result = liveResultFrom(event.result);
  }
  return { steps, result };
}

const fixedSentence = "Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5.";

describe("recorded summary", () => {
  it("reads every value from the saved evaluation row", () => {
    const first = recordedSummary(evaluation.tasks[0]);
    expect(first).toMatchObject({
      source: "RECORDED",
      verdict: "REPRODUCED",
      sentence: "The vulnerable build crashed and the fixed build was clean.",
      vulnerable: {
        state: "CRASHED",
        crashType: "Heap-buffer-overflow WRITE 1",
        topFrame: "decToString",
        sanitizer: "AddressSanitizer",
        exitCode: 1,
      },
      fixed: { state: "CLEAN", exitCode: 0 },
      publicStatus: { kind: "NOT_RECORDED", line: PUBLIC_NOT_RECORDED_LINE },
      totals: { seconds: 4.72856, usd: 0.00089983, tavilyCredits: null, modelCalls: 1 },
    });

    for (const task of evaluation.tasks) {
      const summary = recordedSummary(task);
      expect(summary.verdict).toBe(task.verdict);
      expect(summary.vulnerable.exitCode).toBe(task.vulnerable_exit_code);
      expect(summary.vulnerable.crashType).toBe(task.crash_state.length ? task.crash_type : null);
      expect(summary.vulnerable.topFrame).toBe(task.crash_state[0] ?? null);
      expect(summary.fixed).toEqual({ state: task.fix_clean ? "CLEAN" : "NOT_CLEAN", exitCode: task.fixed_exit_code });
      expect(summary.totals.seconds).toBe(task.wall_seconds);
      expect(summary.totals.usd).toBe(task.cost_usd);
      expect(summary.totals.modelCalls).toBe(task.model_request_ids.length);
      expect(summary.duplicateIds).toEqual(task.duplicate_candidates);
    }
  });

  it("names the duplicate from the saved row", () => {
    const duplicate = evaluation.tasks.find((task) => task.arvo_id === 42508524);
    expect(duplicate).toBeDefined();
    const summary = recordedSummary(duplicate!);
    expect(summary.verdict).toBe("DUPLICATE");
    expect(summary.sentence).toBe("The crash matches another OSV report: OSV-2022-147.");
  });
});

describe("live summary from the producer's stream", () => {
  it("has the real event order", () => {
    expect(events.map((event) => (event.step ? `${event.step.step}:${event.step.kind ?? ""}` : event.type))).toEqual([
      "claim:",
      "sandbox:vul",
      "sandbox:fix",
      "crash:",
      "duplicates:",
      "public_status:",
      "verdict:",
      "result",
    ]);
  });

  it("puts the verdict, both builds, the public line and the totals first", () => {
    const { steps, result } = replay(events.length);
    const summary = liveSummary(steps, result);
    expect(summary).toMatchObject({
      source: "LIVE",
      verdict: "REPRODUCED",
      sentence: "The vulnerable build crashed and the fixed build was clean.",
      details: [],
      duplicateIds: [],
      vulnerable: {
        state: "CRASHED",
        crashType: "Heap-buffer-overflow WRITE 1",
        topFrame: "decToString",
        sanitizer: "AddressSanitizer",
        exitCode: 1,
      },
      fixed: { state: "CLEAN", exitCode: 0 },
      publicStatus: {
        kind: "STATUS",
        state: "PUBLICLY_KNOWN_FIXED",
        line: fixedSentence,
        ancestrySentence: fixedSentence,
        link: {
          href: "https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc",
          label: "GHSA-686w-5m7m-54vc",
        },
        ribbon: {
          ancestry: "CONTAINS_FIX",
          tag: "jq-1.7.1",
          commit: "71c2ab509a8628dbbad4bc7b3f98a64aa90d3297",
          shortCommit: "71c2ab5",
        },
        reusedFrom: null,
      },
    });
    const card = result?.card as { total_cost_usd: number; model_calls: unknown[] };
    expect(summary.totals).toEqual({
      seconds: result?.wall_seconds,
      usd: card.total_cost_usd,
      tavilyCredits: 5,
      tavilyUnanswered: 0,
      modelCalls: card.model_calls.length,
    });
    expect(summary.totals.modelCalls).toBe(2);
  });

  it("fills in step by step while the triage streams", () => {
    const empty = liveSummary([], null);
    expect(empty.verdict).toBeNull();
    expect(empty.sentence).toBe(RUNNING_SENTENCE);
    expect(empty.vulnerable.state).toBeNull();
    expect(empty.fixed.state).toBeNull();
    expect(empty.publicStatus).toEqual({ kind: "PENDING", line: PUBLIC_PENDING_LINE });
    expect(empty.totals).toEqual({ seconds: null, usd: null, tavilyCredits: null, tavilyUnanswered: 0, modelCalls: null });

    const afterClaim = liveSummary(replay(1).steps, null);
    expect(afterClaim.totals.modelCalls).toBe(1);
    expect(afterClaim.vulnerable.exitCode).toBeNull();

    const afterBuilds = liveSummary(replay(3).steps, null);
    expect(afterBuilds.vulnerable).toMatchObject({ state: null, exitCode: 1 });
    expect(afterBuilds.fixed).toEqual({ state: null, exitCode: 0 });

    const afterCrash = liveSummary(replay(4).steps, null);
    expect(afterCrash.vulnerable).toMatchObject({ state: "CRASHED", topFrame: "decToString" });
    expect(afterCrash.fixed.state).toBe("CLEAN");
    expect(afterCrash.verdict).toBeNull();

    const afterPublic = liveSummary(replay(6).steps, null);
    expect(afterPublic.publicStatus).toMatchObject({ kind: "STATUS", line: fixedSentence });
    expect(afterPublic.totals).toMatchObject({ tavilyCredits: 5, modelCalls: 2, seconds: null, usd: null });

    const afterVerdict = liveSummary(replay(7).steps, null);
    const verdictPayload = events[6]?.step?.payload as { total_cost_usd: number; wall_seconds: number };
    expect(afterVerdict.verdict).toBe("REPRODUCED");
    expect(afterVerdict.totals).toMatchObject({ usd: verdictPayload.total_cost_usd, seconds: verdictPayload.wall_seconds });
  });
});

describe("live summary edge cases", () => {
  const publicStep = (payload: Record<string, unknown>): DoorStepEvent => ({ step: "public_status", kind: null, payload });

  it("says an unavailable lookup claims nothing", () => {
    const summary = liveSummary([publicStep({ state: "LOOKUP_UNAVAILABLE", credits: 0, evidence: [], draft: [] })], null);
    expect(summary.publicStatus).toMatchObject({ kind: "STATUS", line: PUBLIC_UNAVAILABLE_LINE, link: null, ribbon: null });
  });

  it("says when no page passed and counts pages that did", () => {
    expect(liveSummary([publicStep({ state: "NO_PUBLIC_FINDINGS", evidence: [] })], null).publicStatus).toMatchObject({
      line: PUBLIC_NO_PAGE_LINE,
    });
    const open = liveSummary(
      [
        publicStep({
          state: "PUBLICLY_KNOWN_OPEN",
          evidence: [
            { url: "javascript:alert(1)", title: "blocked", ancestry: "NOT_CHECKABLE" },
            { url: "https://example.org/a", title: "Advisory A", ancestry: "NOT_CHECKABLE" },
          ],
        }),
      ],
      null,
    );
    expect(open.publicStatus).toMatchObject({
      line: "2 public pages passed the checks for this crash.",
      ancestrySentence: null,
      link: { href: "https://example.org/a", label: "Advisory A" },
      ribbon: null,
    });
  });

  it("draws a does-not-contain ribbon only from the row that says so", () => {
    const summary = liveSummary(
      [
        publicStep({
          state: "RELATED_VARIANTS_ONLY",
          evidence: [
            {
              url: "https://example.org/b",
              title: "Variant",
              ancestry: "DOES_NOT_CONTAIN_FIX",
              checked_tag: "v2.0",
              checked_commit: "0123456789abcdef",
            },
          ],
        }),
      ],
      null,
    );
    expect(summary.publicStatus).toMatchObject({
      ancestrySentence: null,
      ribbon: { ancestry: "DOES_NOT_CONTAIN_FIX", tag: "v2.0", shortCommit: "0123456" },
    });
  });

  it("keeps a NEEDS_INFO reason and does not invent a public step", () => {
    const reason = "ARVO 1 has no committed ConTree checkpoint.";
    const summary = liveSummary(
      [{ step: "verdict", kind: null, payload: { verdict: "NEEDS_INFO", reason } }],
      liveResultFrom({ verdict: "NEEDS_INFO", reason, missing_details: [reason], wall_seconds: 0.01, card: null }),
    );
    expect(summary.verdict).toBe("NEEDS_INFO");
    expect(summary.details).toEqual([reason]);
    expect(summary.publicStatus).toEqual({ kind: "NOT_RUN", line: PUBLIC_NOT_RUN_LINE });
    expect(summary.totals.modelCalls).toBeNull();
    expect(summary.vulnerable.state).toBeNull();
  });

  it("reads the card when the stream sent only a result", () => {
    const summary = liveSummary(
      [],
      liveResultFrom({
        verdict: "DUPLICATE",
        reason: "",
        missing_details: [],
        wall_seconds: 2,
        card: {
          evidence: {
            crash: { crash_type: "Stack-buffer-overflow READ 4", crash_state: ["decNaNs"], sanitizer_kind: "AddressSanitizer" },
            fix_clean: true,
            fixed_exit_code: 0,
            duplicate_candidates: [{ id: "OSV-1" }],
          },
          sandbox_operations: [{ kind: "vul", exit_code: 1 }],
          model_calls: [{ request_id: "a" }],
          total_cost_usd: 0.5,
          public_status: { state: "NO_PUBLIC_FINDINGS", tavily_credits: 3, evidence: [] },
        },
      }),
    );
    expect(summary).toMatchObject({
      sentence: "The crash matches another OSV report: OSV-1.",
      vulnerable: { state: "CRASHED", crashType: "Stack-buffer-overflow READ 4", topFrame: "decNaNs", exitCode: 1 },
      fixed: { state: "CLEAN", exitCode: 0 },
      publicStatus: { line: PUBLIC_NO_PAGE_LINE },
      totals: { seconds: 2, usd: 0.5, tavilyCredits: 3, modelCalls: 1 },
    });
  });
});
