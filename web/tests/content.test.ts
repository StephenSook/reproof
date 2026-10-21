import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import evaluation from "../src/content/arvo10.json";
import catalog from "../src/content/catalog.json";
import copiedLimits from "../src/content/limits.json";
import { costComparison, limitsSentence, measuredSummary, money, PHASE1_NOTE, verdictCounts } from "../src/lib/measured";

const webRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const repoRoot = resolve(webRoot, "..");

function read(path: string): Buffer {
  return readFileSync(path);
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    if (/\.(ts|tsx|css|json|mjs)$/.test(name)) return [path];
    return [];
  });
}

describe("copied judge content", () => {
  it("matches the committed catalog, limits, and evaluation", () => {
    expect(read(join(webRoot, "src/content/catalog.json"))).toEqual(
      read(join(repoRoot, "reproof/assets/catalog.json")),
    );
    expect(read(join(webRoot, "src/content/limits.json"))).toEqual(
      read(join(repoRoot, "reproof/assets/limits.json")),
    );
    expect(read(join(webRoot, "src/content/arvo10.json"))).toEqual(
      read(join(repoRoot, "eval/results/arvo10.json")),
    );
    expect(read(join(webRoot, "src/content/eval100-run1.json"))).toEqual(
      read(join(repoRoot, "eval/results/eval100.json")),
    );
    expect(read(join(webRoot, "src/content/eval100-run2.json"))).toEqual(
      read(join(repoRoot, "eval/results/eval100-run2.json")),
    );
    expect(read(join(webRoot, "src/content/door-42530604.json"))).toEqual(
      read(join(repoRoot, "eval/results/door-42530604.json")),
    );
    expect(read(join(webRoot, "src/content/patch-eval.json"))).toEqual(
      read(join(repoRoot, "eval/results/patch-eval.json")),
    );
    expect(read(join(webRoot, "src/content/patch-eval-notes.json"))).toEqual(
      read(join(repoRoot, "eval/results/patch-eval-notes.json")),
    );
    expect(read(join(webRoot, "src/content/patch-eval-run2.json"))).toEqual(
      read(join(repoRoot, "eval/results/patch-eval-run2.json")),
    );
    expect(read(join(webRoot, "src/content/patch-eval-run2-notes.json"))).toEqual(
      read(join(repoRoot, "eval/results/patch-eval-run2-notes.json")),
    );
  });

  it("counts verdicts from the evaluation and keeps the dated note", () => {
    expect(catalog.tasks).toHaveLength(10);
    expect(catalog.tasks.map((task) => task.arvo_id)).toEqual(evaluation.tasks.map((task) => task.arvo_id));
    const counts = verdictCounts(evaluation.tasks);
    expect(counts.REPRODUCED).toBe(6);
    expect(counts.DUPLICATE).toBe(4);
    const summary = measuredSummary(evaluation);
    expect(summary).toContain("6 REPRODUCED");
    expect(summary).toContain("4 DUPLICATE");
    expect(summary).toContain("10 of 10 tasks completed");
    expect(summary).toContain(PHASE1_NOTE);
    const cost = costComparison(evaluation.totals);
    expect(cost.bars.map((bar) => [bar.key, bar.text])).toEqual([
      ["model", `${money(evaluation.totals.total_model_cost_usd)} USD`],
      ["sandbox", `${money(evaluation.totals.total_sandbox_cost_usd)} USD`],
    ]);
    expect(cost.bars.map((bar) => bar.text)).toEqual(["0.00141720 USD", "0.00775084 USD"]);
    expect(cost.bars[1]?.width).toBe(1);
    expect(cost.bars[0]?.width).toBeCloseTo(0.0014172 / 0.00775084, 10);
    expect(cost.lead).toBe(
      `The sandboxes cost ${(evaluation.totals.total_sandbox_cost_usd / evaluation.totals.total_model_cost_usd).toFixed(1)} times the model calls.`,
    );
    expect(cost.lead).toBe("The sandboxes cost 5.5 times the model calls.");
    expect(cost.combined).toBe("0.00916804 USD for all 10 tasks together");
    expect(cost.tokens).toBe("1349 input and 1125 output tokens");
    const flipped = costComparison({ ...evaluation.totals, total_model_cost_usd: 0.3, total_sandbox_cost_usd: 0.1 });
    expect(flipped.lead).toBe("The model calls cost 3.0 times the sandboxes.");
    expect(limitsSentence(copiedLimits)).toContain("1 triage");
    expect(limitsSentence(copiedLimits)).toContain("8 triages per hour");
    expect(limitsSentence(copiedLimits)).toContain("60 triages per day");
    expect(limitsSentence(copiedLimits)).toContain("credit hold no longer fits in 100 Tavily credits for the UTC day");
    expect(limitsSentence(copiedLimits)).toContain("reused for 60 minutes");
    expect(limitsSentence(copiedLimits)).toContain("Instances do not share a disk.");
  });

  it("does not put credentials or a hardcoded verdict tally in the page source", () => {
    const door = readFileSync(join(webRoot, "src/ui/Door.tsx"), "utf8");
    expect(door).not.toContain("6 REPRODUCED");
    expect(door).not.toContain("4 DUPLICATE");
    for (const path of sourceFiles(join(webRoot, "src"))) {
      const text = readFileSync(path, "utf8");
      expect(text, path).not.toContain("NEBIUS_API_KEY");
      expect(text, path).not.toContain("NEBIUS_PROJECT_ID");
      expect(text, path).not.toContain("\u2014");
      expect(text, path).not.toContain("\u2013");
    }
  });
});
