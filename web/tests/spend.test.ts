import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import evaluation from "../src/content/arvo10.json";
import receiptJson from "../src/content/door-42530604.json";
import type { DoorStepEvent } from "../src/lib/events";
import { money } from "../src/lib/measured";
import { receiptSummary, replayEvents, type DoorReceipt } from "../src/lib/receipt";
import { modelName, platformName, spendLines } from "../src/lib/spend";
import { liveSummary, recordedSummary } from "../src/lib/summary";

const receipt = receiptJson as DoorReceipt;
const card = receipt.events.at(-1)?.result?.card as {
  model_cost_usd: number;
  sandbox_cost_usd: number;
  model_calls: { model: string; price_source: string }[];
  sandbox_operations: unknown[];
};

describe("spend lines", () => {
  it("names the model and the platform from the recorded calls and splits the cost", () => {
    const summary = receiptSummary(receipt);
    expect(summary.spend.models).toEqual([...new Set(card.model_calls.map((call) => call.model))]);
    const lines = spendLines(summary.spend, summary.totals.modelCalls);
    expect(lines).toEqual({
      model: `${card.model_calls.length} calls to Nemotron 3 Super on Nebius Token Factory`,
      modelUsd: `${money(card.model_cost_usd)} USD`,
      sandbox: `${card.sandbox_operations.length} sandbox runs`,
      sandboxUsd: `${money(card.sandbox_cost_usd)} USD`,
      modelShare: card.model_cost_usd / (card.model_cost_usd + card.sandbox_cost_usd),
    });
    expect(lines.model).toBe("3 calls to Nemotron 3 Super on Nebius Token Factory");
  });

  it("says the saved row does not name the model instead of guessing it", () => {
    const row = evaluation.tasks[0];
    const summary = recordedSummary(row);
    const lines = spendLines(summary.spend, summary.totals.modelCalls, true);
    expect(lines.model).toBe("1 model call; the saved row does not name the model");
    expect(lines.modelUsd).toBe(`${money(row.model_cost_usd)} USD`);
    expect(lines.sandbox).toBe("2 sandbox runs");
    expect(lines.sandboxUsd).toBe(`${money(row.sandbox_cost_usd)} USD`);
  });

  it("names only what has arrived while a triage streams", () => {
    const stream = readFileSync(new URL("./fixtures/door-stream.ndjson", import.meta.url), "utf8");
    const events = stream.split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
    const claimOnly: DoorStepEvent[] = replayEvents(events.slice(0, 1)).steps;
    const early = liveSummary(claimOnly, null);
    expect(spendLines(early.spend, early.totals.modelCalls).model).toBe("1 call to Nemotron 3 Super");
    expect(spendLines(early.spend, early.totals.modelCalls).modelShare).toBeNull();
    const done = replayEvents(events);
    const finished = liveSummary(done.steps, done.result);
    expect(spendLines(finished.spend, finished.totals.modelCalls).model).toBe(
      "2 calls to Nemotron 3 Super on Nebius Token Factory",
    );
  });

  it("shows an unknown model id or price source as it is", () => {
    expect(modelName("acme/other-model")).toBe("acme/other-model");
    expect(platformName(["https://example.org/pricing"])).toBeNull();
    expect(platformName([])).toBeNull();
  });
});
