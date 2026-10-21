import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const receipt = JSON.parse(readFileSync(resolve(here, "../../src/content/door-42530604.json"), "utf8")) as {
  recorded_at_utc: string;
  client_elapsed_seconds: number;
  request_body: { arvo_id: number };
  events: {
    type: string;
    result?: {
      verdict: string;
      wall_seconds: number;
      card: {
        total_cost_usd: number;
        model_cost_usd: number;
        sandbox_cost_usd: number;
        model_calls: unknown[];
        public_status: { state: string; tavily_credits: number };
      };
    };
  }[];
};
const recorded = receipt.events.at(-1)?.result;
if (!recorded) throw new Error("the receipt has no result event");
const stream = readFileSync(resolve(here, "../fixtures/door-stream.ndjson"), "utf8");
// The button's estimate is the recorded run's client time, rounded to the nearest 5 s.
const estimate = `about ${Math.round(receipt.client_elapsed_seconds / 5) * 5} s`;

function watchTriage(page: Page): string[] {
  const bodies: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/triage") bodies.push(request.postData() ?? "");
  });
  return bodies;
}

test("the first screen at 1440 holds a finished answer from the recorded response", async ({ page }) => {
  const calls = watchTriage(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  const card = page.locator("[data-hero-answer]");
  await expect(card).toBeVisible();
  const box = await card.boundingBox();
  expect(box && box.y + box.height).toBeLessThanOrEqual(900);
  await expect(card.locator("[data-hero-next-step]")).toHaveText(
    "Already fixed in jq 1.7.1 (tag jq-1.7.1 contains 71c2ab5). Close it and point the reporter to the release.",
  );
  await expect(card).toContainText(recorded.verdict);
  await expect(card).toContainText(recorded.card.public_status.state);
  await expect(card.locator('[data-hero-fact="time"]')).toContainText(`${recorded.wall_seconds.toFixed(2)} s`);
  await expect(card.locator('[data-hero-fact="cost"]')).toContainText(`${recorded.card.total_cost_usd.toFixed(8)} USD`);
  await expect(card.locator('[data-hero-fact="credits"]')).toContainText(String(recorded.card.public_status.tavily_credits));
  await expect(card.locator("[data-hero-model]")).toContainText(
    `${recorded.card.model_calls.length} calls to Nemotron 3 Super on Nebius Token Factory: ${recorded.card.model_cost_usd.toFixed(8)} USD`,
  );
  await expect(card.locator("[data-hero-recorded-at]")).toHaveAttribute("data-hero-recorded-at", receipt.recorded_at_utc);
  const run = card.getByRole("button", { name: `Run it live (${estimate})` });
  await expect(run).toBeInViewport({ ratio: 1 });
  expect(calls).toEqual([]);
});

test("at 390 the answer and the run button are within the first two screens", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const card = page.locator("[data-hero-answer]");
  const stepBox = await card.locator("[data-hero-next-step]").boundingBox();
  const runBox = await card.getByRole("button", { name: `Run it live (${estimate})` }).boundingBox();
  expect(stepBox && stepBox.y + stepBox.height).toBeLessThanOrEqual(844);
  expect(runBox && runBox.y + runBox.height).toBeLessThanOrEqual(2 * 844);
  const size = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(size.scrollWidth).toBeLessThanOrEqual(size.clientWidth);
});

test("Run it live starts a real triage of the recorded report", async ({ page }) => {
  const calls = watchTriage(page);
  await page.route("**/api/triage", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body: stream }),
  );
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await page.locator('[data-task="42507851"] input[type="radio"]').check();
  await page.locator("[data-hero-answer]").getByRole("button", { name: `Run it live (${estimate})` }).click();
  await expect(page.locator('[data-result][data-source="LIVE"]')).toBeVisible();
  expect(calls.map((body) => JSON.parse(body))).toEqual([{ arvo_id: receipt.request_body.arvo_id }]);
  await expect(page.locator(`[data-task="${receipt.request_body.arvo_id}"] input`)).toBeChecked();
  await expect(page.locator("[data-summary]")).toBeInViewport();
});

test("Open the evidence replays the recorded response without a triage call", async ({ page }) => {
  const calls = watchTriage(page);
  await page.goto("/");
  await page.locator("[data-hero-answer]").getByRole("button", { name: "Open the evidence" }).click();
  await expect(page.locator('[data-result][data-source="RECORDED"]')).toBeVisible();
  await expect(page.locator("[data-summary] [data-recorded-at]")).toHaveAttribute("data-recorded-at", receipt.recorded_at_utc);
  await expect(page.locator("[data-summary]")).toBeInViewport();
  expect(calls).toEqual([]);
});

test("the verdict key is a closed disclosure in the hero card", async ({ page }) => {
  await page.goto("/");
  const key = page.locator("[data-hero-answer] details[data-verdict-key]");
  await expect(key).not.toHaveAttribute("open", "");
  await key.locator("summary").click();
  for (const verdict of ["REPRODUCED", "DUPLICATE", "NOT_REPRODUCED", "NEEDS_INFO"]) await expect(key).toContainText(verdict);
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, `${width}px`).toEqual([]);
  }
});
