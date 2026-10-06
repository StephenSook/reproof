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

test("a canned triage shows public status without page text", async ({ page }) => {
  const advisory = "https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22";
  const payload = {
    state: "PUBLICLY_KNOWN_OPEN",
    credits: 2,
    unanswered_credits: 2,
    latency_seconds: 1.2,
    request_ids: ["tavily-req-1"],
    queries: ["jq Stack-buffer-overflow decNaNs"],
    domains: ["github.com"],
    failed_sources: [],
    note: "One open advisory matched the measured frames.",
    model_request_ids: ["public-model"],
    model_cost_usd: 0.0000123,
    caps: { searches: 2, extract_urls: 5, tavily_credits: 200, nemotron_calls: 120 },
    evidence: [
      {
        url: advisory,
        title: "Again, stack-buffer-overflow when comparing nan with payload",
        frames_matched: ["decNaNs", "decNumberCopy"],
        cve_ids: [],
        ghsa_ids: ["GHSA-x6c3-qv5r-7q22"],
        relation: "SAME_BUG",
        upstream_status: "OPEN",
        upstream_version: "",
        ancestry: "NOT_CHECKABLE",
        stale_fields: [],
        checked_tag: "",
      },
      {
        url: "javascript:alert(1)",
        title: "blocked link",
        frames_matched: ["notAFrame"],
        relation: "UNRELATED",
      },
    ],
    draft: [
      {
        text: "One public advisory is still open.",
        source_url: advisory,
        source_date: "2026-10-05",
        confidence: "medium",
      },
    ],
  };
  const cardStatus = {
    ...payload,
    tavily_credits: payload.credits,
    tavily_request_ids: payload.request_ids,
    evidence: payload.evidence.map((item) => ({ ...item, matched_lines: ["NAN1000000000"] })),
  };
  const body = [
    JSON.stringify({ type: "step", step: { step: "public_status", kind: null, payload } }),
    JSON.stringify({
      type: "result",
      result: {
        verdict: "DUPLICATE",
        reason: "",
        missing_details: [],
        wall_seconds: 1.2,
        card: {
          public_status: cardStatus,
          model_cost_usd: 0.0000198,
          sandbox_cost_usd: 0,
          total_cost_usd: 0.0000198,
        },
      },
    }),
    "",
  ].join("\n");
  await page.route("**/api/triage", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body }),
  );

  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.getByRole("button", { name: "Triage", exact: true }).click();
    const block = page.locator('[data-step="public_status"] [data-public-status]');
    await expect(block).toBeVisible();
    await expect(block).toHaveAttribute("data-public-status", "PUBLICLY_KNOWN_OPEN");
    await expect(block.getByRole("link", { name: "Again, stack-buffer-overflow when comparing nan with payload" })).toHaveAttribute(
      "href",
      advisory,
    );
    await expect(block.locator('[data-matched-frame="decNaNs"]')).toBeVisible();
    await expect(block.locator('[data-matched-frame="decNumberCopy"]')).toBeVisible();
    await expect(block.locator('[data-tavily-request-id="tavily-req-1"]')).toBeVisible();
    await expect(block.locator("[data-public-caps]")).toContainText("2 searches");
    await expect(block.locator("[data-public-caps]")).toContainText("5 extract URLs");
    await expect(block.locator("[data-public-caps]")).toContainText("200 Tavily credits");
    await expect(block.locator("[data-public-caps]")).toContainText("120 Nemotron calls");
    await expect(block).toContainText("Tavily credits: 2");
    await expect(block.locator('[data-unanswered-credits="2"]')).toContainText("Tavily did not report them");
    await expect(block).toContainText("blocked link");
    await expect(page.locator('a[href^="javascript"]')).toHaveCount(0);
    await expect(page.getByText("NAN1000000000")).toHaveCount(0);
    const size = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(size.scrollWidth, `${width}px`).toBeLessThanOrEqual(size.clientWidth);
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, `${width}px`).toEqual([]);
  }
});

test("an unavailable lookup is not shown as no findings", async ({ page }) => {
  const payload = {
    state: "LOOKUP_UNAVAILABLE",
    credits: 0,
    latency_seconds: 0,
    request_ids: [],
    queries: [],
    domains: [],
    failed_sources: ["TAVILY_API_KEY is not set"],
    note: "No Tavily search was sent. Failed sources: TAVILY_API_KEY is not set.",
    model_request_ids: [],
    model_cost_usd: 0,
    evidence: [],
    draft: [],
  };
  const body = [JSON.stringify({ type: "step", step: { step: "public_status", kind: null, payload } }), ""].join(
    "\n",
  );
  await page.route("**/api/triage", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body }),
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Triage", exact: true }).click();
  const block = page.locator('[data-step="public_status"] [data-public-status]');
  await expect(block).toHaveAttribute("data-public-status", "LOOKUP_UNAVAILABLE");
  await expect(block.locator("[data-lookup-unavailable]")).toBeVisible();
  await expect(block.getByText("No public page passed the checks for this crash.")).toHaveCount(0);
});

test("a reused lookup names its time and the daily credit cap", async ({ page }) => {
  const payload = {
    state: "NO_PUBLIC_FINDINGS",
    reused_from: "2026-10-06T01:00:00+00:00",
    credits: 0,
    latency_seconds: 0,
    request_ids: ["tavily-req-earlier"],
    queries: ["jq heap buffer overflow decToString"],
    domains: ["github.com"],
    failed_sources: [],
    note: "Reused the lookup made at 2026-10-06T01:00:00+00:00.",
    model_request_ids: [],
    model_cost_usd: 0,
    caps: { searches: 2, extract_urls: 5, tavily_credits: 5, nemotron_calls: 120, tavily_credits_per_day: 100 },
    evidence: [],
    draft: [],
  };
  const body = [JSON.stringify({ type: "step", step: { step: "public_status", kind: null, payload } }), ""].join(
    "\n",
  );
  await page.route("**/api/triage", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body }),
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Triage", exact: true }).click();
  const block = page.locator('[data-step="public_status"] [data-public-status]');
  await expect(block.locator('[data-reused-from="2026-10-06T01:00:00+00:00"]')).toBeVisible();
  await expect(block.locator("[data-public-caps]")).toContainText("5 Tavily credits");
  await expect(block.locator("[data-public-caps]")).toContainText("5-credit hold no longer fits in 100 credits for the UTC day");
  await expect(block.locator('[data-tavily-request-id="tavily-req-earlier"]')).toBeVisible();
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
