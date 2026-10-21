import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
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

test("the task list names any-size crashes in words and says which rows have a card", async ({ page }) => {
  await page.goto("/proof");
  const crashes = await page.locator(".proof-row-crash").allTextContents();
  expect(crashes.length).toBeGreaterThan(0);
  expect(crashes.filter((text) => text.includes("{*}"))).toEqual([]);
  expect(crashes.some((text) => text.includes("(any size)"))).toBe(true);
  await expect(page.locator("#every-task")).toContainText("Every task that ran links to the card the run wrote.");
});

type PatchFile = {
  prereg: { commit: string; path: string };
  tasks: { arvo_id: number; outcome: string; proven_diff: string; card_path: string }[];
  totals: { proven: number; tasks: number };
};

function patchFile(name: string): PatchFile {
  return JSON.parse(
    readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), `../../src/content/${name}`), "utf8"),
  ) as PatchFile;
}

const patchRuns = [
  { key: "1", title: "Run 1", report: patchFile("patch-eval.json"), cards: "patch-cards" },
  { key: "2", title: "Run 2", report: patchFile("patch-eval-run2.json"), cards: "patch-eval-run2-cards" },
];

test("the patch section shows both registered offline runs side by side from their committed results", async ({ page }) => {
  await page.goto("/proof");
  const section = page.locator("[data-patch-section]");
  await expect(section).toBeVisible();
  await expect(section.locator("[data-patch-offline]")).toContainText(
    "Every patch here was proposed and proven offline, in a local Docker container",
  );
  await expect(section.locator("[data-patch-offline]")).toContainText("None was applied upstream");
  await expect(section.locator("[data-patch-row]")).toHaveCount(patchRuns[0].report.tasks.length);
  for (const run of patchRuns) {
    const card = section.locator(`[data-patch-run="${run.key}"]`);
    await expect(card.locator("[data-patch-headline]")).toContainText(
      `${run.report.totals.proven} of ${run.report.totals.tasks}`,
    );
    await expect(card.getByRole("link", { name: /Rule committed in/ })).toHaveAttribute(
      "href",
      `https://github.com/StephenSook/reproof/commit/${run.report.prereg.commit}`,
    );
    await expect(card.getByRole("link", { name: "Read the rule" })).toHaveAttribute(
      "href",
      `https://github.com/StephenSook/reproof/blob/main/${run.report.prereg.path}`,
    );
    for (const task of run.report.tasks) {
      const cell = section.locator(`[data-patch-row="${task.arvo_id}"] [data-patch-run-cell="${run.key}"]`);
      await expect(cell).toHaveAttribute("data-patch-outcome", task.outcome);
      await expect(cell.getByRole("link", { name: `${run.title} card` })).toHaveAttribute(
        "href",
        `https://github.com/StephenSook/reproof/blob/main/eval/results/${run.cards}/${task.arvo_id}.json`,
      );
      const diff = cell.locator("[data-patch-diff]");
      if (task.outcome === "PROVEN") {
        await diff.locator("summary").click();
        const firstChange = task.proven_diff.split("\n").find((line) => line.startsWith("+") && !line.startsWith("+++")) ?? "";
        await expect(diff.locator("pre")).toContainText(firstChange.slice(1).trim());
        await expect(diff).toContainText("not that it is the upstream fix or safe to merge");
        await expect(cell.locator("[data-patch-plain]")).toContainText("What the edit does: ");
      } else {
        await expect(diff).toHaveCount(0);
        await expect(cell.locator("[data-patch-plain]")).toHaveCount(0);
      }
    }
  }
});

test("the patch section has no axe violations with every diff open", async ({ page }) => {
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/proof");
    for (const summary of await page.locator("[data-patch-diff] summary").all()) await summary.click();
    const results = await new AxeBuilder({ page }).include("[data-patch-section]").analyze();
    expect(results.violations, `${width}px`).toEqual([]);
    const size = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(size.scrollWidth, `${width}px`).toBeLessThanOrEqual(size.clientWidth);
  }
});
