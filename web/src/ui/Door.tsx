"use client";

import { useState } from "react";
import { takeLines, type DoorStepEvent } from "@/lib/events";
import { money, seconds } from "@/lib/measured";
import { recordedView, type RecordedTask } from "@/lib/recorded";

export type ReportTask = {
  arvo_id: number;
  project: string;
  osv_record_id: string;
  report_source: string;
  report_text: string;
};

type CardCall = {
  model?: string;
  request_id?: string;
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number;
};

type CardOperation = {
  kind?: string;
  operation_uuid?: string | null;
  checkpoint_operation_uuid?: string | null;
  wall_seconds?: number;
  exit_code?: number;
  cost_usd?: number | null;
};

type ShownCard = {
  model_calls?: CardCall[];
  sandbox_operations?: CardOperation[];
  model_cost_usd?: number;
  sandbox_cost_usd?: number;
  total_cost_usd?: number;
  missing_details?: string[];
  evidence?: {
    excluded_osv_ids?: string[];
    duplicate_candidates?: { id?: string }[];
  };
  public_status?: Record<string, unknown> | null;
  project?: string;
};

type ShownResult = {
  verdict: string;
  reason: string;
  missing_details: string[];
  wall_seconds: number | null;
  card: ShownCard | null;
  model_cost_usd: number | null;
  sandbox_cost_usd: number | null;
  total_cost_usd: number | null;
};

const STEP_LABEL: Record<string, string> = {
  claim: "Claim extraction",
  "sandbox:vul": "Vulnerable build",
  "sandbox:fix": "Fixed build",
  crash: "Parsed crash",
  duplicates: "Duplicate search",
  public_status: "Public status",
  verdict: "Verdict",
};

function gloss(verdict: string): string {
  if (verdict === "REPRODUCED") return "The vulnerable build crashed and the fixed build was clean.";
  if (verdict === "NOT_REPRODUCED") return "The crash did not reproduce. The steps above are the ones that ran.";
  if (verdict === "DUPLICATE") return "The crash matches another OSV report.";
  if (verdict === "NEEDS_INFO") return "A detail is missing, so this is not a conclusive verdict.";
  return "The service returned a verdict.";
}

function stepLabel(step: DoorStepEvent): string {
  const key = step.step === "sandbox" ? `sandbox:${step.kind ?? ""}` : step.step;
  return STEP_LABEL[key] ?? step.step;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

function asText(value: unknown): string | null {
  if (typeof value === "string" && value) return value;
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (Array.isArray(value)) return value.map(String).join(", ");
  return null;
}

function Field({ label, value }: { label: string; value: unknown }) {
  const text = asText(value);
  if (text == null) return null;
  const shown = label.endsWith("USD") && typeof value === "number" ? money(value) : text;
  return (
    <p className="min-w-0">
      <span className="text-[var(--muted)]">{label}: </span>
      <span className="break-words">{shown}</span>
    </p>
  );
}

function textList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function safeHttpUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.href;
  } catch {
    return null;
  }
}

function LinkedText({ url, label }: { url: string; label: string }) {
  const href = safeHttpUrl(url);
  if (!href) return <span className="break-words">{label}</span>;
  return (
    <a className="break-all underline" href={href} rel="noreferrer">
      {label}
    </a>
  );
}

function numberField(record: Record<string, unknown>, key: string): number | null {
  return asNumber(record[key]);
}

function ancestrySentence(row: Record<string, unknown>, projectName: string): string | null {
  const ancestry = typeof row.ancestry === "string" ? row.ancestry : "";
  const version = typeof row.upstream_version === "string" ? row.upstream_version : "";
  const tag = typeof row.checked_tag === "string" ? row.checked_tag : "";
  const commit = typeof row.checked_commit === "string" ? row.checked_commit : "";
  if (ancestry !== "CONTAINS_FIX" || !version || !tag || commit.length < 7) return null;
  const name = projectName.trim() || "this project";
  return `Fixed in ${name} ${version}. Git ancestry: tag ${tag} contains OSV fix ${commit.slice(0, 7)}.`;
}

function PublicStatusBlock({
  status,
  project,
}: {
  status: Record<string, unknown>;
  project?: string;
}) {
  const credits = numberField(status, "credits") ?? numberField(status, "tavily_credits");
  const projectName =
    (typeof status.project === "string" && status.project) || project || "";
  const unanswered =
    numberField(status, "unanswered_credits") ?? numberField(status, "tavily_unanswered_credits") ?? 0;
  const requestIds = textList(status.request_ids).length
    ? textList(status.request_ids)
    : textList(status.tavily_request_ids);
  const queries = textList(status.queries).length ? textList(status.queries) : textList(status.queries_sent);
  const evidence = Array.isArray(status.evidence) ? status.evidence : [];
  const draft = Array.isArray(status.draft) ? status.draft : [];
  const failed = textList(status.failed_sources);
  const caps = status.caps;
  const capRecord = caps !== null && typeof caps === "object" ? (caps as Record<string, unknown>) : null;
  const state = typeof status.state === "string" ? status.state : "";
  const reusedFrom = typeof status.reused_from === "string" ? status.reused_from : "";
  return (
    <div data-public-status={state || undefined}>
      <Field label="State" value={status.state} />
      {reusedFrom ? (
        <p data-reused-from={reusedFrom}>Reused lookup from {reusedFrom} UTC. This triage sent no Tavily call.</p>
      ) : null}
      <Field label="Note" value={status.note} />
      {failed.length ? <Field label="Failed sources" value={failed} /> : null}
      {requestIds.map((requestId) => (
        <p data-tavily-request-id={requestId} key={requestId}>
          Tavily request id: {requestId}
        </p>
      ))}
      <Field label="Tavily credits" value={credits} />
      {unanswered > 0 ? (
        <p data-unanswered-credits={unanswered}>
          Plus an estimated {unanswered} credits for calls that were sent and got no answer. Tavily did not report them.
        </p>
      ) : null}
      {capRecord ? (
        <p data-public-caps>
          Caps: {asText(capRecord.searches)} searches, {asText(capRecord.extract_urls)} extract URLs,{" "}
          {asText(capRecord.tavily_credits)} Tavily credits, {asText(capRecord.nemotron_calls)} Nemotron calls.
          {typeof capRecord.tavily_credits_per_day === "number"
            ? ` This server instance sends no new Tavily lookup when a ${asText(capRecord.tavily_credits)}-credit hold no longer fits in ${capRecord.tavily_credits_per_day} credits for the UTC day.`
            : null}
        </p>
      ) : null}
      {queries.length ? <Field label="Queries" value={queries} /> : null}
      <Field label="Model cost USD" value={status.model_cost_usd} />
      {state === "LOOKUP_UNAVAILABLE" ? (
        <p data-lookup-unavailable>No page was read, so this says nothing either way about whether the crash is public.</p>
      ) : evidence.length === 0 ? (
        <p>No public page passed the checks for this crash.</p>
      ) : null}
      <ul className="grid list-none gap-3 p-0">
        {evidence.map((item, index) => {
          const row = item !== null && typeof item === "object" ? (item as Record<string, unknown>) : {};
          const url = typeof row.url === "string" ? row.url : "";
          const title = typeof row.title === "string" && row.title ? row.title : url || "Untitled page";
          const frames = textList(row.frames_matched);
          const sentence = ancestrySentence(row, projectName);
          return (
            <li className="min-w-0" key={`${url}-${index}`}>
              <p>
                <LinkedText label={title} url={url} />
              </p>
              {frames.length ? (
                <p>
                  Matched frames:{" "}
                  {frames.map((frame, frameIndex) => (
                    <span key={frame}>
                      {frameIndex > 0 ? ", " : null}
                      <mark data-matched-frame={frame}>{frame}</mark>
                    </span>
                  ))}
                </p>
              ) : null}
              {textList(row.cve_ids).length ? <Field label="CVE" value={textList(row.cve_ids)} /> : null}
              {textList(row.ghsa_ids).length ? <Field label="GHSA" value={textList(row.ghsa_ids)} /> : null}
              <Field label="Relation" value={row.relation} />
              <Field label="Upstream status" value={row.upstream_status} />
              <Field label="Upstream version" value={row.upstream_version} />
              <Field label="Ancestry" value={row.ancestry} />
              <Field label="Checked tag" value={row.checked_tag} />
              {textList(row.version_sources).map((source, sourceIndex) => (
                <p className="min-w-0 break-words" data-version-source={source} key={`${source}-${sourceIndex}`}>
                  Version source: {source}
                </p>
              ))}
              {sentence ? <p className="min-w-0 break-words">{sentence}</p> : null}
              {textList(row.stale_fields).length ? (
                <Field label="Stale fields" value={textList(row.stale_fields)} />
              ) : null}
            </li>
          );
        })}
      </ul>
      {draft.map((item, index) => {
        const line = item !== null && typeof item === "object" ? (item as Record<string, unknown>) : {};
        const text = typeof line.text === "string" ? line.text : "";
        const source = typeof line.source_url === "string" ? line.source_url : "";
        if (!text) return null;
        return (
          <p className="min-w-0 break-words" key={`${source}-${index}`}>
            {text}{" "}
            {source ? <LinkedText label={source} url={source} /> : null}{" "}
            {typeof line.source_date === "string" ? <span>{line.source_date}</span> : null}{" "}
            {typeof line.confidence === "string" ? <span>({line.confidence})</span> : null}
          </p>
        );
      })}
    </div>
  );
}

function StepView({ step }: { step: DoorStepEvent }) {
  const payload = step.payload;
  const operationId = typeof payload.operation_uuid === "string" ? payload.operation_uuid : undefined;
  return (
    <li
      className="min-w-0 border-l-4 border-[var(--line)] py-2 pl-3"
      data-kind={step.kind ?? undefined}
      data-operation-id={operationId}
      data-step={step.step}
    >
      <h3 className="text-xl">{stepLabel(step)}</h3>
      {step.step === "claim" ? (
        <>
          <Field label="Model" value={payload.model} />
          <Field label="Request id" value={payload.request_id} />
          <Field label="Input tokens" value={payload.input_tokens} />
          <Field label="Output tokens" value={payload.output_tokens} />
          <Field label="Cost USD" value={payload.cost_usd} />
          <Field label="Latency seconds" value={asNumber(payload.latency_seconds) == null ? null : seconds(asNumber(payload.latency_seconds) ?? 0)} />
          <Field label="Bug class" value={payload.bug_class} />
          <Field label="Functions" value={payload.functions} />
        </>
      ) : null}
      {step.step === "sandbox" ? (
        <>
          <Field label="Operation id" value={payload.operation_uuid} />
          <Field label="Checkpoint operation id" value={payload.checkpoint_operation_uuid} />
          <Field label="Checkpoint id" value={payload.checkpoint_uuid} />
          <Field label="Exit code" value={payload.exit_code} />
          <Field
            label="Duration seconds"
            value={asNumber(payload.wall_seconds) == null ? null : seconds(asNumber(payload.wall_seconds) ?? 0)}
          />
          <Field label="Run cost USD" value={payload.cost_usd} />
          <Field label="Checkpoint cost USD" value={payload.checkpoint_cost_usd} />
          {typeof payload.duration_note === "string" ? <p>{payload.duration_note}</p> : null}
        </>
      ) : null}
      {step.step === "crash" ? (
        <>
          <Field label="Crash type" value={payload.crash_type} />
          <Field label="Sanitizer" value={payload.sanitizer_kind} />
          <Field label="Crash state" value={payload.crash_state} />
          <Field label="Vulnerable crashed" value={payload.vulnerable_crashed} />
          <Field label="Vulnerable exit code" value={payload.vulnerable_exit_code} />
          <Field label="Fixed build clean" value={payload.fix_clean} />
          <Field label="Fixed exit code" value={payload.fixed_exit_code} />
        </>
      ) : null}
      {step.step === "duplicates" ? <Duplicates payload={payload} /> : null}
      {step.step === "public_status" ? <PublicStatusBlock status={payload} /> : null}
      {step.step === "verdict" ? (
        <>
          <p data-verdict={asText(payload.verdict) ?? undefined}>{asText(payload.verdict)}</p>
          <Field label="Reason" value={payload.reason} />
          <Field label="Missing" value={payload.missing_details} />
          <Field label="Model cost USD" value={payload.model_cost_usd} />
          <Field label="Sandbox cost USD" value={payload.sandbox_cost_usd} />
          <Field label="Total cost USD" value={payload.total_cost_usd} />
          <Field
            label="Wall seconds"
            value={asNumber(payload.wall_seconds) == null ? null : seconds(asNumber(payload.wall_seconds) ?? 0)}
          />
        </>
      ) : null}
    </li>
  );
}

function Duplicates({ payload }: { payload: Record<string, unknown> }) {
  const excluded = payload.excluded_osv_ids;
  const candidates = Array.isArray(payload.candidates) ? payload.candidates : [];
  return (
    <>
      {Array.isArray(excluded) ? (
        <p data-excluded-ids={excluded.join(" ")}>
          Excluded OSV ids: {excluded.length ? excluded.map(String).join(", ") : "none"}
        </p>
      ) : null}
      {typeof payload.excluded_note === "string" ? <p>{payload.excluded_note}</p> : null}
      {candidates.length === 0 ? <p>No duplicate candidates.</p> : null}
      <ul className="grid gap-2 p-0">
        {candidates.map((candidate) => {
          const row = candidate as { id?: string; summary?: string; match_kind?: string };
          return (
            <li data-candidate-id={row.id} key={row.id ?? row.summary}>
              <span>{row.id}</span>
              {row.match_kind ? <span> ({row.match_kind})</span> : null}
              {row.summary ? <span className="block text-[var(--muted)]">{row.summary}</span> : null}
            </li>
          );
        })}
      </ul>
    </>
  );
}

function FinalCard({ result, source }: { result: ShownResult; source: "LIVE" | "RECORDED" }) {
  const card = result.card;
  return (
    <article
      aria-label="Verdict"
      className="mt-4 min-w-0 border-4 border-[var(--line)] bg-[var(--card)] p-4"
      data-result
      data-source={source}
      data-verdict={result.verdict}
    >
      <p className="stamp text-[var(--violet)]">{source}</p>
      <h2 className="mt-2 text-4xl">{result.verdict}</h2>
      <p>{gloss(result.verdict)}</p>
      {source === "RECORDED" ? (
        <p>This is the saved evaluation row. It is not a new triage card.</p>
      ) : null}
      {result.reason ? <p>{result.reason}</p> : null}
      {result.missing_details.length ? <p>Missing: {result.missing_details.join(" ")}</p> : null}
      {card == null ? <p>No triage card was returned with this result.</p> : null}
      {card?.model_calls?.map((call) => (
        <p data-model-call={call.request_id} key={call.request_id}>
          Model call {call.model}: request {call.request_id}, {call.input_tokens} input tokens,{" "}
          {call.output_tokens} output tokens, {typeof call.cost_usd === "number" ? money(call.cost_usd) : ""} USD.
        </p>
      ))}
      {card?.sandbox_operations?.map((operation) => (
        <p data-operation-id={operation.operation_uuid ?? undefined} key={`${operation.kind}-${operation.operation_uuid}`}>
          {operation.kind} sandbox operation {operation.operation_uuid}, checkpoint operation{" "}
          {operation.checkpoint_operation_uuid}, exit {operation.exit_code},{" "}
          {typeof operation.wall_seconds === "number" ? seconds(operation.wall_seconds) : ""} seconds.
        </p>
      ))}
      <Field label="Model cost USD" value={card?.model_cost_usd ?? result.model_cost_usd} />
      <Field label="Sandbox cost USD" value={card?.sandbox_cost_usd ?? result.sandbox_cost_usd} />
      <Field label="Total cost USD" value={card?.total_cost_usd ?? result.total_cost_usd} />
      <Field label="Wall seconds" value={result.wall_seconds == null ? null : seconds(result.wall_seconds)} />
      {card?.evidence?.excluded_osv_ids ? (
        <p>Excluded OSV ids: {card.evidence.excluded_osv_ids.join(", ") || "none"}</p>
      ) : null}
      {card?.evidence?.duplicate_candidates?.length ? (
        <p>
          Duplicate candidates:{" "}
          {card.evidence.duplicate_candidates.map((candidate) => candidate.id).filter(Boolean).join(", ")}
        </p>
      ) : null}
      {card?.public_status ? (
        <PublicStatusBlock project={card.project} status={card.public_status} />
      ) : null}
    </article>
  );
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
}: {
  tasks: ReportTask[];
  recordedTasks: RecordedTask[];
}) {
  const [selected, setSelected] = useState(tasks[0]?.arvo_id ?? 0);
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"LIVE" | "RECORDED" | null>(null);
  const [steps, setSteps] = useState<DoorStepEvent[]>([]);
  const [result, setResult] = useState<ShownResult | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const current = tasks.find((task) => task.arvo_id === selected) ?? tasks[0];

  function showRecorded() {
    const task = recordedTasks.find((row) => row.arvo_id === selected);
    setNotice(null);
    setResult(null);
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
    } catch (error) {
      setSource(null);
      setSteps([]);
      setNotice(error instanceof Error ? error.message : "The recorded row is incomplete.");
    }
  }

  async function runTriage() {
    setBusy(true);
    setNotice(null);
    setResult(null);
    setSteps([]);
    setSource("LIVE");
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
          const card = event.result.card;
          const shownCard = card && typeof card === "object" ? (card as ShownCard) : null;
          setResult({
            verdict: String(event.result.verdict ?? ""),
            reason: String(event.result.reason ?? ""),
            missing_details: Array.isArray(event.result.missing_details)
              ? event.result.missing_details.map(String)
              : [],
            wall_seconds: asNumber(event.result.wall_seconds),
            card: shownCard,
            model_cost_usd: asNumber(shownCard?.model_cost_usd),
            sandbox_cost_usd: asNumber(shownCard?.sandbox_cost_usd),
            total_cost_usd: asNumber(shownCard?.total_cost_usd),
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

  return (
    <div className="mt-8 grid min-w-0 gap-6 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
      <form
        id="reports"
        onSubmit={(event) => {
          event.preventDefault();
          void runTriage();
        }}
      >
        <fieldset className="min-w-0 border-0 p-0">
          <legend className="mb-3 font-[family-name:var(--font-display)] text-3xl">Reports</legend>
          <div aria-label="ARVO reports" className="grid gap-2" role="radiogroup">
            {tasks.map((task) => (
              <label
                className="grid min-h-11 cursor-pointer gap-1 border border-[var(--line)] bg-[var(--card)] px-3 py-3 has-[:checked]:border-[var(--violet)]"
                data-task={task.arvo_id}
                key={task.arvo_id}
              >
                <span className="flex flex-wrap gap-x-3">
                  <input
                    checked={task.arvo_id === current?.arvo_id}
                    className="mt-1"
                    name="arvo-report"
                    onChange={() => setSelected(task.arvo_id)}
                    type="radio"
                    value={task.arvo_id}
                  />
                  <span>ARVO {task.arvo_id}</span>
                  <span>{task.project}</span>
                  <span>{task.osv_record_id}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      </form>
      <section aria-labelledby="work-heading" className="min-w-0">
        <h2 className="text-3xl" id="work-heading">
          {current ? `ARVO ${current.arvo_id}` : "No report"}
        </h2>
        {current ? (
          <>
            <p className="mt-2 text-[var(--muted)]">{current.report_source}</p>
            <pre className="mt-3 border border-[var(--line)] bg-[var(--card)] p-3" data-report>
              {current.report_text}
            </pre>
          </>
        ) : null}
        <div className="mt-4 flex flex-wrap gap-3">
          <button
            className="min-h-11 border border-[var(--ink)] bg-[var(--ink)] px-4 text-[var(--paper)] disabled:opacity-60"
            disabled={busy || !current}
            form="reports"
            type="submit"
          >
            {busy ? "Triage running" : "Triage"}
          </button>
          <button
            className="min-h-11 border border-[var(--ink)] bg-[var(--card)] px-4 text-[var(--ink)] disabled:opacity-60"
            disabled={busy || !current}
            onClick={showRecorded}
            type="button"
          >
            Show recorded result
          </button>
        </div>
        {notice ? (
          <p className="mt-4 border border-[var(--amber)] bg-[var(--card)] p-3" role="alert">
            {notice}
          </p>
        ) : null}
        <div aria-busy={busy} aria-live="polite" className="mt-4">
          {source ? <p className="stamp">{source}</p> : null}
          <ol className="mt-2 grid list-none gap-2 p-0">
            {steps.map((step, index) => (
              <StepView key={`${step.step}-${step.kind ?? ""}-${index}`} step={step} />
            ))}
          </ol>
          {result && source ? <FinalCard result={result} source={source} /> : null}
        </div>
      </section>
    </div>
  );
}
