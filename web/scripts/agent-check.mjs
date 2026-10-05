const baseUrl = (process.argv[2] ?? "").trim();
if (!baseUrl) {
  console.error("Usage: node scripts/agent-check.mjs <base-url>");
  process.exit(2);
}

const arvoId = "42530604";
const verdicts = ["REPRODUCED", "NOT_REPRODUCED", "DUPLICATE", "NEEDS_INFO"];
const secretNames = ["NEBIUS_API_KEY", "NEBIUS_PROJECT_ID"];

const { chromium } = await import("@playwright/test");

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(180_000);
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page.locator(`[data-task="${arvoId}"] input[type="radio"]`).check();
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
  if (!(await result.isVisible())) {
    throw new Error("Timed out waiting for the live verdict.");
  }

  const report = await page.evaluate((allowed) => {
    const result = document.querySelector('[data-result][data-source="LIVE"]');
    const verdict = result?.getAttribute("data-verdict") ?? "";
    const steps = [...document.querySelectorAll("[data-step]")].map((node) => ({
      step: node.getAttribute("data-step"),
      kind: node.getAttribute("data-kind"),
      operationId: node.getAttribute("data-operation-id") ?? "",
    }));
    const find = (step, kind) => steps.find((row) => row.step === step && (kind == null || row.kind === kind));
    const field = (label) => {
      if (!result) return null;
      const row = [...result.querySelectorAll("p")].find((item) => (item.textContent ?? "").startsWith(`${label}:`));
      if (!row?.textContent) return null;
      return row.textContent.slice(label.length + 1).trim();
    };
    return {
      verdict,
      claim: Boolean(find("claim")),
      vul: find("sandbox", "vul")?.operationId ?? "",
      fix: find("sandbox", "fix")?.operationId ?? "",
      crash: Boolean(find("crash")),
      duplicates: Boolean(find("duplicates")),
      verdictStep: Boolean(find("verdict")),
      totalCostUsd: field("Total cost USD"),
      wallSeconds: field("Wall seconds"),
      allowed: allowed.includes(verdict),
    };
  }, verdicts);

  const html = await page.content();
  const namedSecret = secretNames.find((name) => html.includes(name));
  const valueSecret = secretNames.some((name) => {
    const value = process.env[name] ?? "";
    return value.length >= 8 && html.includes(value);
  });
  if (namedSecret || valueSecret) {
    console.error(valueSecret ? "The page contains a credential value." : "The page contains a credential name.");
    process.exitCode = 1;
  } else {
    const missing = [];
    if (!report.allowed) missing.push("verdict");
    if (!report.claim) missing.push("claim");
    if (!report.vul) missing.push("sandbox vul operation id");
    if (!report.fix) missing.push("sandbox fix operation id");
    if (!report.crash) missing.push("crash");
    if (!report.duplicates) missing.push("duplicates");
    if (!report.verdictStep) missing.push("verdict step");
    console.log(JSON.stringify({
      arvoId,
      verdict: report.verdict,
      operationIds: { vul: report.vul, fix: report.fix },
      totalCostUsd: report.totalCostUsd,
      wallSeconds: report.wallSeconds,
      missing,
    }, null, 2));
    if (missing.length > 0) process.exitCode = 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  await browser.close();
}
