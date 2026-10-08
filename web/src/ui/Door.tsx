"use client";

import { useRef, useState } from "react";
import { flushSync } from "react-dom";
import { stepKey, takeLines, type DoorStepEvent } from "@/lib/events";
import { recordedView, type RecordedTask } from "@/lib/recorded";
import { liveResultFrom, liveSummary, recordedSummary, type DoorSummary } from "@/lib/summary";
import { CardBody, Disclosure, STEP_LABEL, StepItem, stepLabel, type ShownCard, type ShownResult } from "@/ui/Evidence";
import { SquashButton } from "@/ui/SquashButton";
import { Summary, type Progress } from "@/ui/Summary";

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

async function readFailure(response: Response): Promise<string> {
  const raw = await response.text();
  try {
    const payload = JSON.parse(raw) as { error?: string };
    return payload.error ?? raw;
  } catch {
    return raw || `The triage request failed (${response.status}).`;
  }
}

function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function Door({
  tasks,
  recordedTasks,
}: {
  tasks: ReportTask[];
  recordedTasks: RecordedTask[];
}) {
  const [selected, setSelected] = useState(tasks[0]?.arvo_id ?? 0);
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"LIVE" | "RECORDED" | null>(null);
  const [steps, setSteps] = useState<DoorStepEvent[]>([]);
  const [result, setResult] = useState<ShownResult | null>(null);
  const [recordedTask, setRecordedTask] = useState<RecordedTask | null>(null);
  const [runArvo, setRunArvo] = useState<number | null>(null);
  const [run, setRun] = useState(0);
  const [opened, setOpened] = useState<Record<string, boolean>>({});
  const [notice, setNotice] = useState<string | null>(null);
  const resultRef = useRef<HTMLElement>(null);
  const current = tasks.find((task) => task.arvo_id === selected) ?? tasks[0];

  function bringResultIntoView() {
    const element = resultRef.current;
    if (!element) return;
    element.scrollIntoView({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
    element.querySelector<HTMLElement>("#result-heading")?.focus({ preventScroll: true });
  }

  function showRecorded() {
    const task = recordedTasks.find((row) => row.arvo_id === selected);
    let shown = false;
    flushSync(() => {
      setNotice(null);
      setResult(null);
      setRecordedTask(null);
      setRunArvo(selected);
      setRun((value) => value + 1);
      setOpened({});
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
    flushSync(() => {
      setBusy(true);
      setNotice(null);
      setResult(null);
      setRecordedTask(null);
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
        if (event.type === "result" && event.result) {
          const live = liveResultFrom(event.result);
          const card = live.card as ShownCard | null;
          setResult({
            ...live,
            card,
            model_cost_usd: asNumber(card?.model_cost_usd),
            sandbox_cost_usd: asNumber(card?.sandbox_cost_usd),
            total_cost_usd: asNumber(card?.total_cost_usd),
          });
        }
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
  if (source === "RECORDED" && recordedTask) summary = recordedSummary(recordedTask);
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
                  <span className="pick-id">ARVO {task.arvo_id}</span>
                  <span className="pick-osv">{task.osv_record_id}</span>
                </span>
                <span className="chip pick-project">{task.project}</span>
              </label>
            ))}
          </div>
        </fieldset>
      </form>
      <section aria-labelledby="work-heading" className="work">
        <div className="report-card">
          <div className="report-head">
            <h2 id="work-heading">{current ? `ARVO ${current.arvo_id}` : "No report"}</h2>
            {current ? <span className="chip">{current.project}</span> : null}
            {current ? <span className="chip">{current.osv_record_id}</span> : null}
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
            <Summary arvoId={runArvo} progress={progress} running={busy} summary={summary} />
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
                      title={source === "RECORDED" ? "Saved row" : "Triage card"}
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
