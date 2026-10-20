import { describe, expect, it } from "vitest";
import receiptJson from "../src/content/door-42530604.json";
import { receiptArvoId, receiptSummary, replayEvents, utcMinute, type DoorReceipt } from "../src/lib/receipt";

const receipt = receiptJson as DoorReceipt;

type Card = {
  verdict: string;
  total_cost_usd: number;
  model_calls: unknown[];
  public_status: { state: string; tavily_credits: number; evidence: { checked_tag: string }[] };
};

const resultEvent = receipt.events.at(-1)?.result as { wall_seconds: number; card: Card };
const card = resultEvent.card;

describe("recorded live response", () => {
  it("replays the recorded events in order", () => {
    const { steps, result } = replayEvents(receipt.events);
    expect(steps.map((step) => `${step.step}:${step.kind ?? ""}`)).toEqual([
      "claim:",
      "sandbox:vul",
      "sandbox:fix",
      "crash:",
      "duplicates:",
      "public_status:",
      "verdict:",
    ]);
    expect(result?.verdict).toBe(card.verdict);
    expect(receiptArvoId(receipt)).toBe(42530604);
  });

  it("fills the public status and every total from the recording, not from the saved eval row", () => {
    const summary = receiptSummary(receipt);
    expect(summary.source).toBe("RECORDED");
    expect(summary.recordedAt).toBe(receipt.recorded_at_utc);
    expect(summary.verdict).toBe(card.verdict);
    expect(summary.publicStatus).toMatchObject({ kind: "STATUS", state: card.public_status.state });
    expect(summary.publicStatus.kind).not.toBe("NOT_RECORDED");
    expect(summary.totals).toEqual({
      seconds: resultEvent.wall_seconds,
      usd: card.total_cost_usd,
      tavilyCredits: card.public_status.tavily_credits,
      tavilyUnanswered: 0,
      modelCalls: card.model_calls.length,
    });
    if (summary.publicStatus.kind === "STATUS") {
      expect(summary.publicStatus.ribbon?.tag).toBe(card.public_status.evidence[0]?.checked_tag);
    }
  });

  it("shortens only a UTC stamp", () => {
    expect(utcMinute("2026-10-20T23:45:01+00:00")).toBe("2026-10-20 23:45 UTC");
    expect(utcMinute("2026-10-20T23:45:01Z")).toBe("2026-10-20 23:45 UTC");
    expect(utcMinute("2026-10-20T19:45:01-04:00")).toBe("2026-10-20T19:45:01-04:00");
  });
});
