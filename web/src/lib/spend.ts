import { money } from "@/lib/measured";
import type { SummarySpend } from "@/lib/summary";

/** Display names for model ids the results carry. An id not listed here is shown as it is. */
const MODEL_NAMES: Record<string, string> = {
  "nvidia/nemotron-3-super-120b-a12b": "Nemotron 3 Super",
};

/** A model call's price_source URL names the platform that billed it. */
const PLATFORMS: { prefix: string; name: string }[] = [
  { prefix: "https://nebius.com/services/token-factory/", name: "Nebius Token Factory" },
];

export function modelName(id: string): string {
  return MODEL_NAMES[id] ?? id;
}

export function platformName(priceSources: string[]): string | null {
  const names = new Set<string>();
  for (const url of priceSources) {
    const match = PLATFORMS.find((platform) => url.startsWith(platform.prefix));
    if (!match) return null;
    names.add(match.name);
  }
  return names.size === 1 ? [...names][0] : null;
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

export type SpendLines = {
  /** "3 calls to Nemotron 3 Super on Nebius Token Factory", or null before a call is known. */
  model: string | null;
  modelUsd: string | null;
  /** "2 sandbox runs", or null before a run is known. */
  sandbox: string | null;
  sandboxUsd: string | null;
  /** Model share of model plus sandbox cost, 0 to 1, when both costs are known. */
  modelShare: number | null;
};

export function spendLines(spend: SummarySpend, modelCalls: number | null, savedRow = false): SpendLines {
  let model: string | null = null;
  if (modelCalls !== null && modelCalls > 0) {
    const calls = plural(modelCalls, "call", "calls");
    const platform = platformName(spend.priceSources);
    if (spend.models.length) {
      model = `${calls} to ${spend.models.map(modelName).join(" and ")}${platform ? ` on ${platform}` : ""}`;
    } else {
      model = plural(modelCalls, "model call", "model calls");
      if (savedRow) model += "; the saved row does not name the model";
    }
  }
  const known = spend.modelUsd !== null && spend.sandboxUsd !== null && spend.modelUsd + spend.sandboxUsd > 0;
  return {
    model,
    modelUsd: spend.modelUsd !== null ? `${money(spend.modelUsd)} USD` : null,
    sandbox: spend.sandboxRuns ? plural(spend.sandboxRuns, "sandbox run", "sandbox runs") : null,
    sandboxUsd: spend.sandboxUsd !== null ? `${money(spend.sandboxUsd)} USD` : null,
    modelShare: known ? (spend.modelUsd ?? 0) / ((spend.modelUsd ?? 0) + (spend.sandboxUsd ?? 0)) : null,
  };
}
