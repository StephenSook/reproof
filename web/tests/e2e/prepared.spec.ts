import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const read = (path: string) => JSON.parse(readFileSync(resolve(here, path), "utf8"));
const catalog = read("../../src/content/catalog.json") as { tasks: { arvo_id: number }[] };
const prepared = read("../../src/content/prepared-catalog.json") as {
  tasks: {
    arvo_id: number;
    project: string;
    osv_record_id: string;
    report_text: string;
    recorded: { verdict: string };
  }[];
};

const projects = [...new Set(prepared.tasks.map((task) => task.project))].sort((a, b) => a.localeCompare(b));
// The project with the most reports, so the search has more than one row to keep.
const busiest = projects
  .map((project) => ({ project, rows: prepared.tasks.filter((task) => task.project === project) }))
  .sort((a, b) => b.rows.length - a.rows.length || a.project.localeCompare(b.project))[0]!;
const chosen = busiest.rows[0]!;
// The report's own first line, trimmed the way reportTitle trims it.
const firstLine = (text: string) => text.split("\n").find((line) => line.trim())?.trim() ?? "";
const label = (task: { project: string; report_text: string }) => {
  const first = firstLine(task.report_text);
  return `${task.project}: ${first.charAt(0).toLowerCase()}${first.slice(1)}`;
};

async function openMore(page: Page) {
  const more = page.locator("details[data-more-reports]");
  await more.locator("summary").click();
  await expect(page.locator("[data-more-count]")).toHaveText(
    `All ${prepared.tasks.length} reports, ${projects.length} projects.`,
  );
  return more;
}

test("the first paint carries the featured ten and a count, not the 100-bug rows", async ({ page, request }) => {
  const html = await (await request.get("/")).text();
  const featured = new Set(catalog.tasks.map((task) => task.arvo_id));
  for (const task of prepared.tasks) {
    expect(featured.has(task.arvo_id)).toBe(false);
    expect(html, task.osv_record_id).not.toContain(task.osv_record_id);
  }
  await page.goto("/");
  await expect(page.getByRole("radio")).toHaveCount(catalog.tasks.length);
  const more = page.locator("details[data-more-reports]");
  await expect(more).not.toHaveAttribute("open", "");
  await expect(more.locator("summary")).toContainText(`${prepared.tasks.length} more from the 100-bug run`);
  await expect(more.locator("summary")).toContainText(`${projects.length} projects. Search by project, bug, crash type or id.`);
  await expect(page.locator("#door-title")).toHaveText(`${catalog.tasks.length + prepared.tasks.length} public reports`);
});

test("the 100-bug reports open grouped by project, search narrows them, and one plays its recorded row", async ({
  page,
}) => {
  const triageCalls: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/triage") triageCalls.push(request.url());
  });
  await page.goto("/");
  const more = await openMore(page);
  await expect(page.getByRole("radio")).toHaveCount(catalog.tasks.length + prepared.tasks.length);
  await expect(more.locator("[data-project]")).toHaveCount(projects.length);
  expect(await more.locator("[data-project]").evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-project")))).toEqual(
    projects,
  );

  const search = more.getByRole("searchbox");
  await search.fill(busiest.project);
  const matching = prepared.tasks.filter((task) => `${task.project} ${firstLine(task.report_text)}`.toLowerCase().includes(busiest.project.toLowerCase()));
  await expect(page.locator("[data-more-count]")).toHaveText(`${matching.length} of ${prepared.tasks.length} reports match.`);
  await expect(more.getByRole("radio")).toHaveCount(matching.length);

  const row = more.locator(`[data-task="${chosen.arvo_id}"]`);
  await row.locator('input[type="radio"]').check();
  await expect(row.locator(".pick-ids")).toHaveText(`ARVO ${chosen.arvo_id}, ${chosen.osv_record_id}`);
  await expect(page.locator("#work-heading")).toHaveText(label(chosen));
  await expect(page.locator("[data-report]")).toContainText(firstLine(chosen.report_text));
  await expect(more.locator("[data-more-chosen]")).toHaveText(`Chosen: ${label(chosen)}. Go to the report`);
  await expect(more.locator("[data-more-chosen] a")).toHaveAttribute("href", "#work-heading");
  // A featured radio is no longer checked: one group, one choice.
  await expect(page.locator('#reports input[type="radio"]:checked')).toHaveCount(1);

  await page.getByRole("button", { name: "Show recorded result" }).click();
  const result = page.locator('[data-result][data-source="RECORDED"]');
  await expect(result).toBeVisible();
  await expect(result).toHaveAttribute("data-verdict", chosen.recorded.verdict);
  await expect(result).toContainText("This is the saved evaluation row. It is not a new triage card.");
  await expect(result).toContainText(label(chosen));

  await search.fill("no-such-report-zz");
  await expect(page.locator("[data-more-count]")).toHaveText('No report matches "no-such-report-zz".');
  await expect(more.getByRole("radio")).toHaveCount(0);
  expect(triageCalls).toEqual([]);
});

test("Triage sends the chosen 100-bug report's id", async ({ page }) => {
  const bodies: unknown[] = [];
  await page.route("**/api/triage", async (route) => {
    bodies.push(route.request().postDataJSON());
    const result = { verdict: "NEEDS_INFO", reason: "canned", missing_details: ["canned"], wall_seconds: 0.1, card: null };
    await route.fulfill({
      status: 200,
      contentType: "application/x-ndjson",
      body: `${JSON.stringify({ type: "result", result })}\n`,
    });
  });
  await page.goto("/");
  const more = await openMore(page);
  await more.locator(`[data-task="${chosen.arvo_id}"] input[type="radio"]`).check();
  await page.getByRole("button", { name: "Triage", exact: true }).click();
  await expect(page.locator('[data-result][data-source="LIVE"]')).toBeVisible();
  expect(bodies).toEqual([{ arvo_id: chosen.arvo_id }]);
});

test("the open list has no axe violations and no horizontal scroll, light and dark", async ({ page }) => {
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const width of [390, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/");
      await openMore(page);
      await page.locator("details[data-more-reports]").getByRole("searchbox").fill("heap");
      const size = await page.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      }));
      expect(size.scrollWidth, `${width}px ${scheme}`).toBeLessThanOrEqual(size.clientWidth);
      const results = await new AxeBuilder({ page }).analyze();
      expect(results.violations, `${width}px ${scheme}`).toEqual([]);
    }
  }
});
