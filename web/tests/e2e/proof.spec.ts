import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const run2 = JSON.parse(
  readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../src/content/eval100-run2.json"), "utf8"),
) as { selected_arvo_ids: number[]; run_failed: unknown[] };

test("the proof page lists every selected task, failed runs and misses first", async ({ page }) => {
  await page.goto("/proof");
  const rows = page.locator("[data-proof-row]");
  await expect(rows).toHaveCount(run2.selected_arvo_ids.length);
  await expect(page.locator("#proof-title")).toHaveText(`${run2.selected_arvo_ids.length} public bugs`);

  const kinds = await rows.evaluateAll((items) => items.map((item) => item.getAttribute("data-proof-kind")));
  const order = { failed: 0, miss: 1, agree: 2 } as const;
  const ranks = kinds.map((kind) => order[kind as keyof typeof order]);
  expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  expect(kinds.filter((kind) => kind === "failed")).toHaveLength(run2.run_failed.length);

  for (const href of await page.locator("[data-proof-row] a").evaluateAll((links) => links.map((link) => link.getAttribute("href")))) {
    expect(href).toMatch(/^https:\/\/github\.com\/StephenSook\/reproof\/blob\/main\/eval\/results\/.+\.json$/);
  }
  await expect(page.locator('[data-proof-run="Run 1"]')).toContainText("of 100 completed");
  await expect(page.locator('[data-proof-run="Run 2"]')).toContainText("before run 2 started");
});

test("the proof page has no horizontal overflow", async ({ page }) => {
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/proof");
    const size = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(size.scrollWidth, `${width}px`).toBeLessThanOrEqual(size.clientWidth);
  }
});

test("the door links to the proof page", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "100 bugs", exact: true }).click();
  await expect(page).toHaveURL(/\/proof$/);
});
