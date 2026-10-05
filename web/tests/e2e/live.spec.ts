import { expect, test } from "@playwright/test";

const verdicts = ["REPRODUCED", "NOT_REPRODUCED", "DUPLICATE", "NEEDS_INFO"];
const secretNames = ["NEBIUS_API_KEY", "NEBIUS_PROJECT_ID"];

test("one live triage of ARVO 42530604 returns a verdict and every step", async ({ page }) => {
  test.skip(process.env.REPROOF_LIVE !== "1", "Set REPROOF_LIVE=1 to run one real triage.");
  page.setDefaultTimeout(180_000);
  await page.goto("/");
  await page.locator('[data-task="42530604"] input[type="radio"]').check();
  await page.getByRole("button", { name: "Triage", exact: true }).click();

  const work = page.locator("section[aria-labelledby='work-heading']");
  const alert = work.getByRole("alert");
  const result = page.locator('[data-result][data-source="LIVE"]');
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    if (await result.isVisible()) break;
    if (await alert.isVisible()) {
      const text = ((await alert.textContent()) ?? "").trim();
      if (text) throw new Error(`Triage failed: ${text}`);
    }
    await page.waitForTimeout(250);
  }
  await expect(result).toBeVisible();

  const report = await page.evaluate((allowed) => {
    const card = document.querySelector('[data-result][data-source="LIVE"]');
    const steps = [...document.querySelectorAll("[data-step]")].map((node) => ({
      step: node.getAttribute("data-step"),
      kind: node.getAttribute("data-kind"),
      operationId: node.getAttribute("data-operation-id") ?? "",
    }));
    const find = (step: string, kind?: string) =>
      steps.find((row) => row.step === step && (kind == null || row.kind === kind));
    const field = (label: string) => {
      const row = [...(card?.querySelectorAll("p") ?? [])].find((item) =>
        (item.textContent ?? "").startsWith(`${label}:`),
      );
      return row?.textContent?.slice(label.length + 1).trim() ?? "";
    };
    return {
      verdict: card?.getAttribute("data-verdict") ?? "",
      claim: Boolean(find("claim")),
      vul: find("sandbox", "vul")?.operationId ?? "",
      fix: find("sandbox", "fix")?.operationId ?? "",
      crash: Boolean(find("crash")),
      duplicates: Boolean(find("duplicates")),
      verdictStep: Boolean(find("verdict")),
      totalCostUsd: field("Total cost USD"),
      wallSeconds: field("Wall seconds"),
      allowed: allowed.includes(card?.getAttribute("data-verdict") ?? ""),
    };
  }, verdicts);

  console.log(JSON.stringify({ arvoId: 42530604, ...report }));
  expect(report.allowed).toBe(true);
  expect(report.claim).toBe(true);
  expect(report.vul).toMatch(/^[0-9a-f-]{36}$/);
  expect(report.fix).toMatch(/^[0-9a-f-]{36}$/);
  expect(report.crash).toBe(true);
  expect(report.duplicates).toBe(true);
  expect(report.verdictStep).toBe(true);
  expect(report.totalCostUsd).toMatch(/^\d+\.\d+$/);
  expect(report.wallSeconds).toMatch(/^\d+\.\d+$/);

  const html = await page.content();
  for (const name of secretNames) {
    expect(html).not.toContain(name);
    const value = process.env[name] ?? "";
    if (value.length >= 8) expect(html.includes(value)).toBe(false);
  }
});
