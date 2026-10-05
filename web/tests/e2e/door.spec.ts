import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { PHASE1_NOTE } from "../../src/lib/measured";

const catalog = JSON.parse(
  readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../src/content/catalog.json"), "utf8"),
) as {
  tasks: { arvo_id: number; osv_record_id: string; project: string; report_text: string }[];
};

const widths = [390, 768, 1024, 1440];

test("the picker shows each public report and its OSV id", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("radio")).toHaveCount(catalog.tasks.length);
  for (const task of catalog.tasks) {
    const row = page.locator(`[data-task="${task.arvo_id}"]`);
    await row.locator('input[type="radio"]').check();
    await expect(row).toContainText(task.osv_record_id);
    await expect(row).toContainText(task.project);
    await expect(page.locator("[data-report]")).toContainText(task.report_text.split("\n")[0] ?? "");
  }
});

test("the recorded result is labelled RECORDED and does not call triage", async ({ page }) => {
  const triageCalls: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/triage") triageCalls.push(request.url());
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Show recorded result" }).click();

  const work = page.locator("section[aria-labelledby='work-heading']");
  const result = page.locator('[data-result][data-source="RECORDED"]');
  await expect(result).toBeVisible();
  await expect(result).toHaveAttribute("data-verdict", "REPRODUCED");
  await expect(result).toContainText("RECORDED");
  await expect(result).toContainText("This is the saved evaluation row. It is not a new triage card.");
  await expect(result).toContainText("No triage card was returned with this result.");
  await expect(work.locator('[data-step="claim"]')).toContainText("not in the recorded summary");
  await expect(work.locator('[data-step="sandbox"][data-kind="vul"]')).toHaveAttribute(
    "data-operation-id",
    "01a10d76-4c5f-7726-8825-c7b18b1ff5d8",
  );
  await expect(work.locator('[data-step="sandbox"][data-kind="fix"]')).toHaveAttribute(
    "data-operation-id",
    "01a10d76-4d3b-76a4-b69f-3f853d63a4ca",
  );
  await expect(work.locator('[data-step="crash"]')).toContainText("Heap-buffer-overflow WRITE 1");
  await expect(work.locator('[data-step="duplicates"]')).toContainText(
    "Excluded OSV ids are not in the recorded summary.",
  );
  await expect(work.locator('[data-step="verdict"]')).toContainText("REPRODUCED");
  expect(triageCalls).toEqual([]);
});

test("the Measured section renders the saved evaluation", async ({ page }) => {
  await page.goto("/");
  const measured = page.locator("#measured");
  await expect(measured).toContainText("These numbers are the saved ARVO 10 evaluation. They are not a new run.");
  await expect(measured).toContainText("6 REPRODUCED");
  await expect(measured).toContainText("4 DUPLICATE");
  await expect(measured).toContainText("0.00141720 model USD");
  await expect(measured).toContainText("0.00775084 sandbox USD");
  await expect(measured).toContainText("0.00916804 combined USD");
  await expect(measured).toContainText("40.709021 seconds");
  await expect(measured).toContainText(PHASE1_NOTE);
  await expect(page.locator("[data-measured-task]")).toHaveCount(10);
  await expect(page.locator('[data-measured-task="42530604"]')).toContainText("REPRODUCED");
  await expect(page.locator('[data-measured-task="42508524"]')).toContainText("OSV-2022-147");
});

test("the page has no horizontal overflow", async ({ page }) => {
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.getByRole("button", { name: "Show recorded result" }).click();
    await expect(page.locator('[data-source="RECORDED"]')).toBeVisible();
    const size = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(size.scrollWidth, `${width}px`).toBeLessThanOrEqual(size.clientWidth);
  }
});

test("axe reports zero violations", async ({ page }) => {
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.getByRole("button", { name: "Show recorded result" }).click();
    await expect(page.locator('[data-source="RECORDED"]')).toBeVisible();
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, `${width}px`).toEqual([]);
  }
});
