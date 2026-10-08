import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
// Written by tests/test_door.py from reproof/door.py and the door's NDJSON serializer.
const stream = readFileSync(resolve(here, "../fixtures/door-stream.ndjson"), "utf8");
const lines = stream
  .split("\n")
  .map((line) => line.trim())
  .filter(Boolean);
const fixedSentence = "Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5.";
const advisory = "https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc";

async function noOverflow(page: Page, label: string) {
  const size = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(size.scrollWidth, label).toBeLessThanOrEqual(size.clientWidth);
}

async function axeClean(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations, label).toEqual([]);
}

async function openEveryDisclosure(page: Page) {
  const closed = page.locator(".evidence details:not([open]) > summary");
  while ((await closed.count()) > 0) await closed.first().click();
}

async function sentenceCount(page: Page, sentence: string): Promise<number> {
  return page.evaluate((text) => (document.body.textContent ?? "").split(text).length - 1, sentence);
}

test("the recorded result answers first and keeps the evidence one click away", async ({ page }) => {
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.goto("/");
    await page.getByRole("button", { name: "Show recorded result" }).click();

    const summary = page.locator("[data-summary]");
    await expect(summary).toBeVisible();
    await expect(summary).toBeInViewport();
    await expect(summary).toHaveAttribute("data-summary-source", "RECORDED");
    await expect(summary).toContainText("RECORDED");
    await expect(summary.locator('[data-summary-verdict="REPRODUCED"]')).toContainText(
      "The vulnerable build crashed and the fixed build was clean.",
    );
    const vulnerable = summary.locator('[data-summary-vulnerable="CRASHED"]');
    await expect(vulnerable).toContainText("CRASHED");
    await expect(vulnerable).toContainText("Heap-buffer-overflow WRITE 1");
    await expect(vulnerable).toContainText("decToString");
    await expect(vulnerable).toContainText("Exit code1");
    const fixed = summary.locator('[data-summary-fixed="CLEAN"]');
    await expect(fixed).toContainText("CLEAN");
    await expect(fixed).toContainText("Exit code0");
    await expect(summary.locator('[data-summary-public="NOT_RECORDED"]')).toContainText(
      "The public-status lookup is not in the recorded summary.",
    );
    await expect(page.locator("[data-ribbon]")).toHaveCount(0);
    const totals = summary.locator("[data-summary-totals]");
    await expect(totals).toContainText("4.73 s");
    await expect(totals).toContainText("0.00089983 USD");
    await expect(totals).toContainText("Tavily creditsnot recorded");
    await expect(totals).toContainText("Model calls1");

    const evidenceTop = await page.locator("#evidence-heading").evaluate((node) => node.getBoundingClientRect().top);
    const summaryTop = await summary.evaluate((node) => node.getBoundingClientRect().top);
    expect(summaryTop).toBeLessThan(evidenceTop);

    await expect(page.locator(".evidence details[open]")).toHaveCount(0);
    const vulStep = page.locator('[data-step="sandbox"][data-kind="vul"]');
    const vulBody = vulStep.locator(".disclosure-body");
    await expect(vulBody).toBeHidden();
    await vulStep.locator("summary").click();
    await expect(vulBody).toBeVisible();
    await expect(vulBody).toContainText("Operation id: 01a10d76-4c5f-7726-8825-c7b18b1ff5d8");

    await noOverflow(page, `${width}px`);
    await axeClean(page, `${width}px`);
    await openEveryDisclosure(page);
    await noOverflow(page, `${width}px open`);
    await axeClean(page, `${width}px open`);
  }
});

test("a live result from the producer's stream puts the answer and the git proof first", async ({ page }) => {
  await page.route("**/api/triage", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body: stream }),
  );
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.goto("/");
    await page.getByRole("button", { name: "Triage", exact: true }).click();

    const result = page.locator('[data-result][data-source="LIVE"]');
    await expect(result).toBeVisible();
    await expect(result).toHaveAttribute("data-verdict", "REPRODUCED");
    const summary = page.locator("[data-summary]");
    await expect(summary).toBeInViewport();
    await expect(summary).toContainText("LIVE");
    await expect(summary.locator('[data-summary-verdict="REPRODUCED"]')).toBeVisible();
    await expect(summary.locator('[data-summary-vulnerable="CRASHED"]')).toContainText("decToString");
    await expect(summary.locator('[data-summary-fixed="CLEAN"]')).toContainText("Exit code0");
    const publicLine = summary.locator('[data-summary-public="PUBLICLY_KNOWN_FIXED"]');
    await expect(publicLine).toContainText(fixedSentence);
    await expect(publicLine.getByRole("link", { name: "GHSA-686w-5m7m-54vc", exact: true })).toHaveAttribute(
      "href",
      advisory,
    );
    const ribbon = publicLine.locator('[data-ribbon="CONTAINS_FIX"]');
    await expect(ribbon).toBeVisible();
    await expect(ribbon).toContainText("release tagjq-1.7.1");
    await expect(ribbon).toContainText("contains");
    await expect(ribbon).not.toContainText("does not contain");
    await expect(ribbon).toContainText("OSV fix commit71c2ab5");
    await expect(ribbon.locator(".ribbon-commit")).toHaveAttribute(
      "title",
      "71c2ab509a8628dbbad4bc7b3f98a64aa90d3297",
    );
    const totals = summary.locator("[data-summary-totals]");
    await expect(totals).toContainText("Tavily credits5");
    await expect(totals).toContainText("Model calls2");
    await expect(totals).toContainText("0.00017280 USD");

    expect(await sentenceCount(page, fixedSentence)).toBe(1);
    await expect(page.locator(".evidence details[open]")).toHaveCount(0);
    await expect(page.locator("[data-step]")).toHaveCount(7);
    await expect(page.locator('[data-step="sandbox"][data-kind="vul"]')).toHaveAttribute(
      "data-operation-id",
      "test-vul-operation",
    );

    const publicStep = page.locator('[data-step="public_status"]');
    await publicStep.locator("summary").click();
    await expect(publicStep.locator('[data-version-source="github_advisory_api:1.7.1"]')).toBeVisible();
    await expect(publicStep).toContainText("Checked commit: 71c2ab509a8628dbbad4bc7b3f98a64aa90d3297");
    await expect(publicStep.locator("[data-draft-repeats-summary]")).toBeVisible();
    await expect(publicStep.locator('[data-tavily-request-id="tavily-req-c"]')).toBeVisible();
    expect(await sentenceCount(page, fixedSentence)).toBe(1);

    await noOverflow(page, `${width}px`);
    await axeClean(page, `${width}px`);
    await openEveryDisclosure(page);
    await expect(page.locator("[data-model-call]")).toHaveCount(2);
    await noOverflow(page, `${width}px open`);
    await axeClean(page, `${width}px open`);
  }
});

test("the ancestry ribbon is drawn only when the evidence decided the ancestry", async ({ page }) => {
  const row = {
    url: "https://example.org/advisory",
    title: "Example advisory",
    frames_matched: ["decNaNs"],
    relation: "SAME_BUG",
    upstream_status: "FIXED",
    upstream_version: "2.0",
    checked_tag: "v2.0",
    checked_commit: "0123456789abcdef0123456789abcdef01234567",
  };
  const bodyFor = (ancestry: string) =>
    [
      JSON.stringify({
        type: "step",
        step: {
          step: "public_status",
          kind: null,
          payload: { state: "RELATED_VARIANTS_ONLY", project: "demo", evidence: [{ ...row, ancestry }], draft: [] },
        },
      }),
      JSON.stringify({ type: "result", result: { verdict: "DUPLICATE", reason: "", missing_details: [], wall_seconds: 1, card: null } }),
      "",
    ].join("\n");
  let body = bodyFor("DOES_NOT_CONTAIN_FIX");
  await page.route("**/api/triage", (route) => route.fulfill({ status: 200, contentType: "application/x-ndjson", body }));

  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    body = bodyFor("DOES_NOT_CONTAIN_FIX");
    await page.goto("/");
    await page.getByRole("button", { name: "Triage", exact: true }).click();
    const missing = page.locator('[data-summary-public] [data-ribbon="DOES_NOT_CONTAIN_FIX"]');
    await expect(missing).toBeVisible();
    await expect(missing).toContainText("v2.0");
    await expect(missing).toContainText("does not contain");
    await expect(missing).toContainText("0123456");
    await expect(page.locator('[data-summary-public="RELATED_VARIANTS_ONLY"]')).toContainText(
      "1 public page passed the checks for this crash.",
    );
    await noOverflow(page, `${width}px`);
    await axeClean(page, `${width}px`);

    body = bodyFor("NOT_CHECKABLE");
    await page.goto("/");
    await page.getByRole("button", { name: "Triage", exact: true }).click();
    await expect(page.locator("[data-result]")).toBeVisible();
    await expect(page.locator("[data-ribbon]")).toHaveCount(0);
  }
});

test("motion runs only when the visitor allows it", async ({ page }) => {
  // Record every inline transform GSAP writes on a motion wrapper while the recorded result appears.
  const watchMotion = () =>
    page.evaluate(() => {
      const host = window as unknown as { __moved: number };
      host.__moved = 0;
      new MutationObserver((records) => {
        for (const record of records) {
          const target = record.target as HTMLElement;
          if (target.classList?.contains("motion-wrap") && target.style.transform) host.__moved += 1;
        }
      }).observe(document.body, { attributes: true, attributeFilter: ["style"], subtree: true });
    });
  const moved = () => page.evaluate(() => (window as unknown as { __moved: number }).__moved);

  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto("/");
  await expect(page.locator("html")).toHaveClass(/lenis/);
  await watchMotion();
  await page.getByRole("button", { name: "Show recorded result" }).click();
  await expect(page.locator("[data-summary]")).toBeVisible();
  await expect.poll(moved).toBeGreaterThan(0);

  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.locator("[data-summary]")).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.classList.contains("lenis"))).toBe(false);
  await watchMotion();
  await page.getByRole("button", { name: "Show recorded result" }).click();
  await expect(page.locator("[data-summary]")).toBeVisible();
  await page.waitForTimeout(1200);
  expect(await moved()).toBe(0);
});

test("the summary fills in while the stream arrives and the evidence closes at the verdict", async ({ page }) => {
  await page.addInitScript(() => {
    const host = window as unknown as {
      __push: (line: string) => void;
      __end: () => void;
      __ready: boolean;
      fetch: typeof fetch;
    };
    const original = host.fetch.bind(window);
    let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
    host.__ready = false;
    host.__push = (line) => controller?.enqueue(new TextEncoder().encode(`${line}\n`));
    host.__end = () => controller?.close();
    host.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (!url.endsWith("/api/triage")) return original(input, init);
      const body = new ReadableStream<Uint8Array>({
        start(next) {
          controller = next;
          host.__ready = true;
        },
      });
      return Promise.resolve(new Response(body, { status: 200, headers: { "content-type": "application/x-ndjson" } }));
    };
  });
  const push = (count: [number, number]) =>
    page.evaluate((batch) => {
      const host = window as unknown as { __push: (line: string) => void };
      for (const line of batch) host.__push(line);
    }, lines.slice(...count));

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await page.getByRole("button", { name: "Triage", exact: true }).click();
  await page.waitForFunction(() => (window as unknown as { __ready: boolean }).__ready);

  const summary = page.locator("[data-summary]");
  await expect(summary).toBeVisible();
  await expect(summary.locator('[data-summary-verdict=""]')).toContainText("Running");
  await expect(page.locator("[data-result]")).toHaveCount(0);

  await push([0, 3]);
  await expect(page.locator("[data-step]")).toHaveCount(3);
  await expect(summary.locator("[data-summary-vulnerable]")).toContainText("Exit code1");
  await expect(summary.locator('[data-summary-vulnerable=""]')).toContainText("Waiting");
  await expect(summary.locator("[data-summary-totals]")).toContainText("Model calls1");
  await expect(page.locator(".evidence details[open]")).toHaveCount(3);
  await expect(summary.locator(".progress .progress-done")).toHaveCount(3);

  await push([3, 6]);
  await expect(summary.locator('[data-summary-vulnerable="CRASHED"]')).toContainText("Heap-buffer-overflow WRITE 1");
  await expect(summary.locator('[data-summary-public="PUBLICLY_KNOWN_FIXED"]')).toContainText(fixedSentence);
  await expect(page.locator(".evidence details[open]")).toHaveCount(6);

  await push([6, lines.length]);
  await page.evaluate(() => (window as unknown as { __end: () => void }).__end());
  await expect(page.locator('[data-result][data-source="LIVE"]')).toHaveAttribute("data-verdict", "REPRODUCED");
  await expect(summary.locator('[data-summary-verdict="REPRODUCED"]')).toBeVisible();
  await expect(page.locator(".evidence details[open]")).toHaveCount(0);
  await expect(page.locator(".evidence details")).toHaveCount(8);
  await expect(summary.locator(".progress")).toHaveCount(0);
});
