import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const baseUrl = (process.argv[2] ?? "").trim();
if (!baseUrl) {
  console.error("Usage: node scripts/agent-check.mjs <base-url>");
  process.exit(2);
}

const arvoId = "42530604";
const verdicts = ["REPRODUCED", "NOT_REPRODUCED", "DUPLICATE", "NEEDS_INFO"];
const secretNames = ["NEBIUS_API_KEY", "NEBIUS_PROJECT_ID"];
const timeoutMs = 180_000;
const retryDelayMs = 60_000;
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const resultsDirectory = path.resolve(scriptDirectory, "..", "test-results");
const configuredReportPath = process.env.PROBE_REPORT?.trim();
const reportPath = configuredReportPath
  ? path.resolve(configuredReportPath)
  : path.join(resultsDirectory, "probe-report.json");
const primaryTracePath = path.join(resultsDirectory, "probe-trace.zip");
const secretValues = secretNames
  .map((name) => process.env[name] ?? "")
  .filter((value) => value.length >= 8);

const { chromium } = await import("@playwright/test");

function redact(value) {
  let text = String(value);
  for (const secret of secretValues) {
    text = text.replaceAll(secret, "[REDACTED]");
    text = text.replaceAll(encodeURIComponent(secret), "[REDACTED]");
  }
  return text;
}

function errorMessage(error) {
  return redact(error instanceof Error ? error.message : String(error));
}

function isTriageUrl(url) {
  try {
    return new URL(url).pathname === "/api/triage";
  } catch {
    return false;
  }
}

async function checkPage(page) {
  page.setDefaultTimeout(timeoutMs);
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page.locator(`[data-task="${arvoId}"] input[type="radio"]`).check();
  await page.getByRole("button", { name: "Triage", exact: true }).click();

  const work = page.locator("section[aria-labelledby='work-heading']");
  const alert = work.getByRole("alert");
  const result = page.locator('[data-result][data-source="LIVE"]');
  const deadline = Date.now() + timeoutMs;
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

  const check = await page.evaluate((allowed) => {
    const result = document.querySelector('[data-result][data-source="LIVE"]');
    const verdict = result?.getAttribute("data-verdict") ?? "";
    const steps = [...document.querySelectorAll("[data-step]")].map((node) => ({
      step: node.getAttribute("data-step"),
      kind: node.getAttribute("data-kind"),
      operationId: node.getAttribute("data-operation-id") ?? "",
    }));
    const find = (step, kind) =>
      steps.find((row) => row.step === step && (kind == null || row.kind === kind));
    const field = (label) => {
      if (!result) return null;
      const row = [...result.querySelectorAll("p")].find((item) =>
        (item.textContent ?? "").startsWith(`${label}:`),
      );
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
  const valueSecret = secretValues.some((value) => html.includes(value));
  if (namedSecret || valueSecret) {
    throw new Error(valueSecret ? "The page contains a credential value." : "The page contains a credential name.");
  }

  const missing = [];
  if (!check.allowed) missing.push("verdict");
  if (!check.claim) missing.push("claim");
  if (!check.vul) missing.push("sandbox vul operation id");
  if (!check.fix) missing.push("sandbox fix operation id");
  if (!check.crash) missing.push("crash");
  if (!check.duplicates) missing.push("duplicates");
  if (!check.verdictStep) missing.push("verdict step");

  const summary = {
    arvoId,
    verdict: check.verdict,
    operationIds: { vul: check.vul, fix: check.fix },
    totalCostUsd: check.totalCostUsd,
    wallSeconds: check.wallSeconds,
    missing,
  };
  if (missing.length > 0) {
    const error = new Error(`Missing required live result fields: ${missing.join(", ")}.`);
    error.check = summary;
    throw error;
  }
  return summary;
}

function attachDiagnostics(page, diagnostics, responseTasks) {
  page.on("request", (request) => {
    if (!isTriageUrl(request.url())) return;
    diagnostics.triageRequests.push({
      observedAt: new Date().toISOString(),
      method: request.method(),
      url: redact(request.url()),
    });
  });

  page.on("response", (response) => {
    if (!isTriageUrl(response.url())) return;
    const entry = {
      observedAt: new Date().toISOString(),
      method: response.request().method(),
      url: redact(response.url()),
      status: response.status(),
      headers: null,
      bodyPreview: null,
      bodyReadError: null,
    };
    diagnostics.triageResponses.push(entry);
    const task = (async () => {
      try {
        const headers = await response.allHeaders();
        entry.headers = {
          "x-vercel-id": headers["x-vercel-id"] ?? null,
          "x-vercel-cache": headers["x-vercel-cache"] ?? null,
          server: headers.server ?? null,
          "x-vercel-mitigated": headers["x-vercel-mitigated"] ?? null,
          "content-type": headers["content-type"] ?? null,
        };
        if (response.status() !== 200) {
          entry.bodyPreview = redact((await response.text()).slice(0, 500));
        }
      } catch (error) {
        entry.bodyReadError = errorMessage(error);
      }
    })();
    responseTasks.add(task);
    void task.finally(() => responseTasks.delete(task));
  });

  page.on("console", (message) => {
    if (message.type() !== "error") return;
    const location = message.location();
    diagnostics.consoleErrors.push({
      observedAt: new Date().toISOString(),
      text: redact(message.text()),
      location: {
        url: redact(location.url),
        lineNumber: location.lineNumber,
        columnNumber: location.columnNumber,
      },
    });
  });

  page.on("pageerror", (error) => {
    diagnostics.pageErrors.push({
      observedAt: new Date().toISOString(),
      message: errorMessage(error),
      stack: redact(error.stack ?? ""),
    });
  });

  page.on("requestfailed", (request) => {
    diagnostics.failedRequests.push({
      observedAt: new Date().toISOString(),
      method: request.method(),
      url: redact(request.url()),
      failureText: redact(request.failure()?.errorText ?? "Unknown request failure"),
    });
  });
}

async function runAttempt(browser, attemptNumber) {
  const diagnostics = {
    triageRequests: [],
    triageResponses: [],
    consoleErrors: [],
    pageErrors: [],
    failedRequests: [],
  };
  const attempt = {
    attempt: attemptNumber,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    passed: false,
    error: null,
    check: null,
    tracePath: null,
    traceError: null,
    diagnostics,
  };
  const responseTasks = new Set();
  const context = await browser.newContext();
  let tracingStarted = false;

  try {
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    tracingStarted = true;
    const page = await context.newPage();
    attachDiagnostics(page, diagnostics, responseTasks);
    attempt.check = await checkPage(page);
    attempt.passed = true;
  } catch (error) {
    attempt.error = errorMessage(error);
    if (error && typeof error === "object" && "check" in error) {
      attempt.check = error.check;
    }
  } finally {
    await Promise.allSettled([...responseTasks]);
    if (tracingStarted) {
      try {
        if (attempt.passed) {
          await context.tracing.stop();
        } else {
          const tracePath =
            attemptNumber === 1
              ? primaryTracePath
              : path.join(resultsDirectory, `probe-trace-attempt-${attemptNumber}.zip`);
          await mkdir(path.dirname(tracePath), { recursive: true });
          await context.tracing.stop({ path: tracePath });
          attempt.tracePath = tracePath;
        }
      } catch (error) {
        attempt.traceError = errorMessage(error);
      }
    }
    await context.close();
    attempt.finishedAt = new Date().toISOString();
  }
  return attempt;
}

function buildReport(attempts, status) {
  const passed = attempts.find((attempt) => attempt.passed) ?? null;
  const first = attempts[0] ?? null;
  return {
    generatedAt: new Date().toISOString(),
    status,
    baseUrl: redact(baseUrl),
    arvoId,
    passed: Boolean(passed),
    passedAttempt: passed?.attempt ?? null,
    firstFailure: first && !first.passed ? first.error : null,
    reportPath,
    attempts,
  };
}

async function writeReport(report) {
  await mkdir(path.dirname(reportPath), { recursive: true });
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

const attempts = [];
const browser = await chromium.launch();
try {
  const first = await runAttempt(browser, 1);
  attempts.push(first);
  if (!first.passed) {
    await writeReport(buildReport(attempts, "retry_pending"));
    await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    attempts.push(await runAttempt(browser, 2));
  }
} finally {
  await browser.close();
}

const passed = attempts.find((attempt) => attempt.passed) ?? null;
const report = buildReport(attempts, passed ? "passed" : "failed");
await writeReport(report);

if (attempts.some((attempt) => !attempt.passed)) {
  console.error(`=== PROBE DIAGNOSTICS ===\n${JSON.stringify(report, null, 2)}\n=== END PROBE DIAGNOSTICS ===`);
}

if (passed) {
  console.log(JSON.stringify({ attempt: passed.attempt, ...passed.check }, null, 2));
} else {
  process.exitCode = 1;
}
