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

test("the picker names each report by project and bug first, then its ids", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("radio")).toHaveCount(catalog.tasks.length);
  for (const task of catalog.tasks) {
    const row = page.locator(`[data-task="${task.arvo_id}"]`);
    const first = task.report_text.split("\n")[0] ?? "";
    const label = `${task.project}: ${first.charAt(0).toLowerCase()}${first.slice(1)}`;
    await row.locator('input[type="radio"]').check();
    await expect(row.locator(".pick-title")).toHaveText(label);
    await expect(row.locator(".pick-ids")).toHaveText(`ARVO ${task.arvo_id}, ${task.osv_record_id}`);
    const titleTop = await row.locator(".pick-title").evaluate((node) => node.getBoundingClientRect().top);
    const idsTop = await row.locator(".pick-ids").evaluate((node) => node.getBoundingClientRect().top);
    expect(titleTop).toBeLessThan(idsTop);
    await expect(row.getByRole("radio")).toHaveAccessibleName(`${label} ARVO ${task.arvo_id}, ${task.osv_record_id}`);
    await expect(page.locator("#work-heading")).toHaveText(label);
    await expect(page.locator("[data-report]")).toContainText(first);
  }
});

type ReceiptStep = { step: string; kind: string | null; payload: Record<string, unknown> };
const receipt = JSON.parse(
  readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../src/content/door-42530604.json"), "utf8"),
) as {
  recorded_at_utc: string;
  events: { type: string; step?: ReceiptStep; result?: { verdict: string } }[];
};
const receiptStep = (step: string, kind: string | null = null) =>
  receipt.events.find((event) => event.step?.step === step && (event.step?.kind ?? null) === kind)?.step;

test("the recorded jq result replays the full recorded response and does not call triage", async ({ page }) => {
  const triageCalls: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/triage") triageCalls.push(request.url());
  });
  await page.goto("/");
  await page.locator('[data-task="42530604"] input[type="radio"]').check();
  await page.getByRole("button", { name: "Show recorded result" }).click();

  const work = page.locator("section[aria-labelledby='work-heading']");
  const result = page.locator('[data-result][data-source="RECORDED"]');
  await expect(result).toBeVisible();
  await expect(result).toHaveAttribute("data-verdict", receipt.events.at(-1)?.result?.verdict ?? "");
  await expect(result).toContainText("RECORDED");
  await expect(result.locator("[data-recorded-at]")).toHaveAttribute("data-recorded-at", receipt.recorded_at_utc);
  await expect(result).not.toContainText("not in the recorded summary");
  await expect(work.locator('[data-step="claim"]')).toContainText(String(receiptStep("claim")?.payload.request_id));
  await expect(work.locator('[data-step="sandbox"][data-kind="vul"]')).toHaveAttribute(
    "data-operation-id",
    String(receiptStep("sandbox", "vul")?.payload.operation_uuid),
  );
  await expect(work.locator('[data-step="sandbox"][data-kind="fix"]')).toHaveAttribute(
    "data-operation-id",
    String(receiptStep("sandbox", "fix")?.payload.operation_uuid),
  );
  await expect(work.locator('[data-step="public_status"]')).toBeVisible();
  await expect(work.locator("[data-card]")).toContainText("Triage card");
  expect(triageCalls).toEqual([]);
});

test("a report without a recorded response shows its saved evaluation row", async ({ page }) => {
  const triageCalls: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/triage") triageCalls.push(request.url());
  });
  await page.goto("/");
  await page.locator('[data-task="42507851"] input[type="radio"]').check();
  await page.getByRole("button", { name: "Show recorded result" }).click();

  const work = page.locator("section[aria-labelledby='work-heading']");
  const result = page.locator('[data-result][data-source="RECORDED"]');
  await expect(result).toBeVisible();
  await expect(result).toHaveAttribute("data-verdict", "REPRODUCED");
  await expect(result).toContainText("This is the saved evaluation row. It is not a new triage card.");
  await expect(result).toContainText("No triage card was returned with this result.");
  await expect(work.locator('[data-step="claim"]')).toContainText("not in the recorded summary");
  await expect(work.locator('[data-step="duplicates"]')).toContainText(
    "Excluded OSV ids are not in the recorded summary.",
  );
  await expect(work.locator('[data-step="public_status"]')).toHaveCount(0);
  expect(triageCalls).toEqual([]);
});

test("the shared limits sit in a closed Limits disclosure beside the buttons", async ({ page }) => {
  await page.goto("/");
  const limits = page.locator("details[data-limits]");
  await expect(limits).toHaveCount(1);
  await expect(limits).not.toHaveAttribute("open", "");
  await expect(limits.locator("summary")).toHaveText("Limits");
  await expect(limits.locator("p")).toBeHidden();
  await expect(page.locator(".report-card details[data-limits]")).toHaveCount(1);
  await limits.locator("summary").click();
  await expect(limits.locator("p")).toBeVisible();
  await expect(limits.locator("p")).toContainText("This address can start 8 triages per hour.");
  await expect(limits.locator("p")).toContainText("Instances do not share a disk.");
});

test("the Measured section renders the saved evaluation", async ({ page }) => {
  await page.goto("/");
  const measured = page.locator("#measured");
  await expect(measured).toContainText("These numbers are the saved ARVO 10 evaluation. They are not a new run.");
  await expect(measured).toContainText("6 REPRODUCED");
  await expect(measured).toContainText("4 DUPLICATE");
  const cost = measured.locator("[data-cost-compare]");
  await expect(cost).toContainText("The sandboxes cost 5.5 times the model calls.");
  await expect(cost.locator('[data-cost="model"]')).toContainText("0.00141720 USD");
  await expect(cost.locator('[data-cost="sandbox"]')).toContainText("0.00775084 USD");
  await expect(cost).toContainText("0.00916804 USD for all 10 tasks together");
  // The bars are drawn from the two totals: the sandbox bar is full and the model bar is to scale.
  const widths = await cost.locator(".cost-fill").evaluateAll((bars) => bars.map((bar) => bar.getBoundingClientRect().width));
  expect(widths[0]! / widths[1]!).toBeCloseTo(0.0014172 / 0.00775084, 2);
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
    await expect(page.locator('[data-result][data-source="LIVE"]')).toBeVisible();
    // The evidence closes when the verdict arrives; the judge opens it with one click.
    await page.locator('[data-step="public_status"] summary').click();
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

test("a fixed advisory shows the version source and the ancestry sentence", async ({ page }) => {
  const advisory = "https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc";
  const sentence = "Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5.";
  const payload = {
    state: "PUBLICLY_KNOWN_FIXED",
    project: "jq",
    credits: 2,
    unanswered_credits: 0,
    latency_seconds: 1.2,
    request_ids: ["tavily-req-fixed"],
    queries: ["jq Stack-buffer-overflow decNaNs"],
    domains: ["github.com"],
    failed_sources: [],
    note: "One advisory version contains the recorded fix.",
    model_request_ids: ["public-model"],
    model_cost_usd: 0.0000123,
    caps: { searches: 2, extract_urls: 5, tavily_credits: 200, nemotron_calls: 120 },
    evidence: [
      {
        url: advisory,
        title: "GHSA-686w-5m7m-54vc",
        frames_matched: ["decNaNs"],
        cve_ids: ["CVE-2023-50246"],
        ghsa_ids: ["GHSA-686w-5m7m-54vc"],
        relation: "SAME_BUG",
        upstream_status: "FIXED",
        upstream_version: "1.7.1",
        ancestry: "CONTAINS_FIX",
        stale_fields: [],
        checked_tag: "jq-1.7.1",
        checked_commit: "71c2ab509a8628dbbad4bc7b3f98a64aa90d3297",
        version_sources: ["github_advisory_api:1.7.1"],
      },
    ],
    draft: [
      {
        text: `${sentence} Source: ${advisory}.`,
        source_url: advisory,
        source_date: "2026-10-06",
        confidence: "high",
      },
    ],
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
          project: "jq",
          public_status: payload,
          model_cost_usd: 0.0000123,
          sandbox_cost_usd: 0,
          total_cost_usd: 0.0000123,
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
    await expect(page.locator('[data-result][data-source="LIVE"]')).toBeVisible();
    // The ancestry sentence is the summary's public line, and it appears on the page exactly once.
    await expect(page.locator('[data-summary-public="PUBLICLY_KNOWN_FIXED"]')).toContainText(sentence);
    // Page text only: the framework's serialized props in body <script> tags are not page text.
    const occurrences = await page.evaluate(
      (text) => (document.querySelector("main")?.textContent ?? "").split(text).length - 1,
      sentence,
    );
    expect(occurrences, `${width}px`).toBe(1);
    await page.locator('[data-step="public_status"] summary').click();
    const block = page.locator('[data-step="public_status"] [data-public-status]');
    await expect(block).toHaveAttribute("data-public-status", "PUBLICLY_KNOWN_FIXED");
    await expect(block.locator('[data-version-source="github_advisory_api:1.7.1"]')).toHaveText(
      "Version source: github_advisory_api:1.7.1",
    );
    await expect(block.getByRole("link", { name: "GHSA-686w-5m7m-54vc", exact: true })).toHaveAttribute(
      "href",
      advisory,
    );
    await expect(block).toContainText("Checked tag: jq-1.7.1");
    await expect(block).toContainText("Checked commit: 71c2ab509a8628dbbad4bc7b3f98a64aa90d3297");
    await expect(block.locator("[data-draft-line]")).toContainText(`Source: ${advisory}.`);
    await expect(block.locator('[data-matched-frame="decNaNs"]')).toBeVisible();
    await expect(block.locator('[data-tavily-request-id="tavily-req-fixed"]')).toBeVisible();
    // The card does not repeat the public-status block the step already shows.
    await expect(page.locator("[data-public-status]")).toHaveCount(1);
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
