"use client";

import { useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { stepKey, takeLines, type DoorStepEvent } from "@/lib/events";
import { receiptArvoId, receiptSummary, replayEvents, type DoorReceipt } from "@/lib/receipt";
import { recordedView, type RecordedTask } from "@/lib/recorded";
import { reportIds, reportLabel } from "@/lib/reports";
import { liveResultFrom, liveSummary, recordedSummary, type DoorSummary } from "@/lib/summary";
import { CardBody, Disclosure, STEP_LABEL, StepItem, stepLabel, type ShownCard, type ShownResult } from "@/ui/Evidence";
import { scrollToElement } from "@/ui/motion/motion";
import { SquashButton } from "@/ui/SquashButton";
import { Summary, type Progress, type TypicalRun } from "@/ui/Summary";

export type ReportTask = {
  arvo_id: number;
  project: string;
  osv_record_id: string;
  report_source: string;
  report_text: string;
};

const PROGRESS_KEYS = ["claim", "sandbox:vul", "sandbox:fix", "crash", "duplicates", "public_status", "verdict"];

function asNumber(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

/** The result event as the page shows it, live or recorded. */
function shownResult(raw: Record<string, unknown>): ShownResult {
  const live = liveResultFrom(raw);
  const card = live.card as ShownCard | null;
  return {
    ...live,
    card,
    model_cost_usd: asNumber(card?.model_cost_usd),
    sandbox_cost_usd: asNumber(card?.sandbox_cost_usd),
    total_cost_usd: asNumber(card?.total_cost_usd),
  };
}

async function readFailure(response: Response): Promise<string> {
  const raw = await response.text();
  try {
    const payload = JSON.parse(raw) as { error?: string };
    return payload.error ?? raw;
  } catch {
    return raw || `The triage request failed (${response.status}).`;
  }
}

export function Door({
  tasks,
  recordedTasks,
  receipts,
  limitsNote,
}: {
  tasks: ReportTask[];
  recordedTasks: RecordedTask[];
  receipts: DoorReceipt[];
  /** The door's shared limits in one paragraph, shown on request beside the buttons. */
  limitsNote: string;
}) {
  const [selected, setSelected] = useState(tasks[0]?.arvo_id ?? 0);
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"LIVE" | "RECORDED" | null>(null);
  const [steps, setSteps] = useState<DoorStepEvent[]>([]);
  const [result, setResult] = useState<ShownResult | null>(null);
  const [recordedTask, setRecordedTask] = useState<RecordedTask | null>(null);
  const [recordedReceipt, setRecordedReceipt] = useState<DoorReceipt | null>(null);
  const [runArvo, setRunArvo] = useState<number | null>(null);
  const [run, setRun] = useState(0);
  const [opened, setOpened] = useState<Record<string, boolean>>({});
  const [notice, setNotice] = useState<string | null>(null);
  // Clock readings for the elapsed counter of a running triage, from performance.now().
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  const resultRef = useRef<HTMLElement>(null);
  const current = tasks.find((task) => task.arvo_id === selected) ?? tasks[0];

  useEffect(() => {
    if (!busy) return;
    const timer = window.setInterval(() => setNow(performance.now()), 250);
    return () => window.clearInterval(timer);
  }, [busy]);
  const elapsedSeconds = busy && startedAt !== null ? Math.max(0, Math.floor((now - startedAt) / 1000)) : null;
  // The reference time is the recorded run's own client time, request to last byte.
  const reference = receipts[0];
  const referenceProject = reference ? tasks.find((task) => task.arvo_id === receiptArvoId(reference))?.project : undefined;
  const typicalRun: TypicalRun | null = reference
    ? { seconds: reference.client_elapsed_seconds, project: referenceProject ?? `ARVO ${receiptArvoId(reference)}` }
    : null;

  function bringResultIntoView() {
    const element = resultRef.current;
    if (!element) return;
    scrollToElement(element);
    element.querySelector<HTMLElement>("#result-heading")?.focus({ preventScroll: true });
  }

  function showRecorded() {
    const task = recordedTasks.find((row) => row.arvo_id === selected);
    const receipt = receipts.find((row) => receiptArvoId(row) === selected);
    let shown = false;
    flushSync(() => {
      setNotice(null);
      setResult(null);
      setRecordedTask(null);
      setRecordedReceipt(null);
      setRunArvo(selected);
      setRun((value) => value + 1);
      setOpened({});
      if (receipt) {
        // A full recorded response of the live door: the same steps and card a live run sends.
        const replay = replayEvents(receipt.events);
        setSource("RECORDED");
        setSteps(replay.steps);
        setRecordedReceipt(receipt);
        setResult(replay.rawResult ? shownResult(replay.rawResult) : null);
        shown = true;
        return;
      }
      if (!task) {
        setSource(null);
        setSteps([]);
        setNotice("This report has no saved evaluation row.");
        return;
      }
      try {
        const view = recordedView(task);
        setSource("RECORDED");
        setSteps(view.steps);
        setRecordedTask(task);
        setResult({
          verdict: view.verdict,
          reason: view.reason,
          missing_details: view.missing_details,
          wall_seconds: view.wall_seconds,
          card: null,
          model_cost_usd: view.model_cost_usd,
          sandbox_cost_usd: view.sandbox_cost_usd,
          total_cost_usd: view.total_cost_usd,
        });
        shown = true;
      } catch (error) {
        setSource(null);
        setSteps([]);
        setNotice(error instanceof Error ? error.message : "The recorded row is incomplete.");
      }
    });
    if (shown) bringResultIntoView();
  }

  async function runTriage() {
    const clock = performance.now();
    flushSync(() => {
      setBusy(true);
      setStartedAt(clock);
      setNow(clock);
      setNotice(null);
      setResult(null);
      setRecordedTask(null);
      setRecordedReceipt(null);
      setSteps([]);
      setSource("LIVE");
      setRunArvo(selected);
      setRun((value) => value + 1);
      setOpened({});
    });
    bringResultIntoView();
    try {
      const response = await fetch("/api/triage", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ arvo_id: selected }),
      });
      if (!response.ok || !response.body) {
        setNotice(await readFailure(response));
        setSource(null);
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let rest = "";
      const apply = (line: string) => {
        const event = JSON.parse(line) as { type?: string; step?: DoorStepEvent; result?: Record<string, unknown> };
        if (event.type === "step" && event.step) {
          const step = event.step;
          setSteps((previous) => [...previous, step]);
        }
        if (event.type === "result" && event.result) setResult(shownResult(event.result));
      };
      while (true) {
        const chunk = await reader.read();
        rest += decoder.decode(chunk.value, { stream: !chunk.done });
        const taken = takeLines(rest);
        rest = taken.rest;
        for (const line of taken.lines) apply(line);
        if (chunk.done) break;
      }
      if (rest.trim()) apply(rest);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The triage request failed.");
      setSource(null);
    } finally {
      setBusy(false);
    }
  }

  let summary: DoorSummary | null = null;
  if (source === "RECORDED" && recordedReceipt) summary = receiptSummary(recordedReceipt);
  else if (source === "RECORDED" && recordedTask) summary = recordedSummary(recordedTask);
  if (source === "LIVE") {
    const live = result ? { ...result, card: result.card as Record<string, unknown> | null } : null;
    summary = liveSummary(steps, live, { ended: !busy });
  }
  const verdictArrived = summary?.verdict != null;
  const phase = `${run}:${verdictArrived ? "settled" : "streaming"}`;
  const isOpen = (key: string) => opened[`${phase}:${key}`] ?? !verdictArrived;
  const toggle = (key: string) => (open: boolean) =>
    setOpened((previous) =>
      previous[`${phase}:${key}`] === open ? previous : { ...previous, [`${phase}:${key}`]: open },
    );
  const summarySentence = summary?.publicStatus.kind === "STATUS" ? summary.publicStatus.ancestrySentence : null;
  const seen = new Set(steps.map(stepKey));
  const progress: Progress = PROGRESS_KEYS.map((key) => ({ key, label: STEP_LABEL[key] ?? key, done: seen.has(key) }));
  const runTask = tasks.find((task) => task.arvo_id === runArvo);
  const runTitle = runTask ? reportLabel(runTask) : runArvo !== null ? `ARVO ${runArvo}` : null;
  const lastStep = steps.at(-1);
  const announcement = summary?.verdict
    ? `Verdict ${summary.verdict}.`
    : lastStep
      ? `${stepLabel(lastStep)} arrived.`
      : busy
        ? "Triage started."
        : "";

  return (
    <div className="door-grid">
      <form
        className="min-w-0"
        id="reports"
        onSubmit={(event) => {
          event.preventDefault();
          void runTriage();
        }}
      >
        <fieldset className="min-w-0 border-0 p-0">
          <legend className="picker-legend">Reports</legend>
          <div aria-label="ARVO reports" className="picker" role="radiogroup">
            {tasks.map((task) => (
              <label className="pick" data-task={task.arvo_id} key={task.arvo_id}>
                <input
                  checked={task.arvo_id === current?.arvo_id}
                  name="arvo-report"
                  onChange={() => setSelected(task.arvo_id)}
                  type="radio"
                  value={task.arvo_id}
                />
                <span className="grid min-w-0">
                  <span className="pick-title">{reportLabel(task)}</span>
                  <span className="pick-ids">{reportIds(task)}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      </form>
      <section aria-labelledby="work-heading" className="work">
        <div className="report-card">
          <div className="report-head">
            <h2 id="work-heading">{current ? reportLabel(current) : "No report"}</h2>
            {current ? <p className="report-ids">{reportIds(current)}</p> : null}
          </div>
          {current ? (
            <>
              <p className="report-source">{current.report_source}</p>
              <pre className="report-text" data-report>
                {current.report_text.trimEnd()}
              </pre>
            </>
          ) : null}
          <div className="actions">
            <SquashButton disabled={busy || !current} form="reports" icon={"▶"} type="submit">
              {busy ? "Triage running" : "Triage"}
            </SquashButton>
            <SquashButton disabled={busy || !current} icon={"↺"} onClick={showRecorded} variant="secondary">
              Show recorded result
            </SquashButton>
          </div>
          <p className="action-note">
            Triage makes real model, sandbox, and search calls now. Show recorded result makes none.
          </p>
          <details className="limits" data-limits>
            <summary>Limits</summary>
            <p>{limitsNote}</p>
          </details>
        </div>
        {notice ? (
          <p className="notice" role="alert">
            {notice}
          </p>
        ) : null}
        <p aria-live="polite" className="sr-only" role="status">
          {announcement}
        </p>
        {source && summary ? (
          <article
            aria-busy={busy}
            aria-labelledby="result-heading"
            className="result"
            data-result={result ? "" : undefined}
            data-source={result ? source : undefined}
            data-verdict={result ? result.verdict : undefined}
            ref={resultRef}
          >
            <Summary
              elapsedSeconds={elapsedSeconds}
              progress={progress}
              running={busy}
              summary={summary}
              title={runTitle}
              typicalRun={typicalRun}
            />
            <section aria-labelledby="evidence-heading" className="evidence">
              <div className="evidence-head">
                <h3 id="evidence-heading">Evidence</h3>
                <p className="hand">{verdictArrived ? "every id and cost, one click away" : "open while it runs"}</p>
              </div>
              <ol className="evidence-list">
                {steps.map((step, index) => {
                  const key = `${index}:${stepKey(step)}`;
                  return (
                    <StepItem
                      key={key}
                      onToggle={toggle(key)}
                      open={isOpen(key)}
                      step={step}
                      summarySentence={summarySentence}
                    />
                  );
                })}
                {result ? (
                  <li className="evidence-item" data-card>
                    <Disclosure
                      gist={result.card ? "model calls, sandbox operations, costs" : "saved summary row"}
                      onToggle={toggle("card")}
                      open={isOpen("card")}
                      title={result.card ? "Triage card" : "Saved row"}
                    >
                      <CardBody hasPublicStep={seen.has("public_status")} result={result} summarySentence={summarySentence} />
                    </Disclosure>
                  </li>
                ) : null}
              </ol>
            </section>
          </article>
        ) : null}
      </section>
    </div>
  );
}
