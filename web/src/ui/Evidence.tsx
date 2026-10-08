import type { ReactNode } from "react";
import { stepKey, type DoorStepEvent } from "@/lib/events";
import { money, seconds } from "@/lib/measured";
import { safeHttpUrl } from "@/lib/summary";

export const STEP_LABEL: Record<string, string> = {
  claim: "Claim extraction",
  "sandbox:vul": "Vulnerable build",
  "sandbox:fix": "Fixed build",
  crash: "Parsed crash",
  duplicates: "Duplicate search",
  public_status: "Public status",
  verdict: "Verdict",
};

export type CardCall = {
  model?: string;
  request_id?: string;
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number;
};

export type CardOperation = {
  kind?: string;
  operation_uuid?: string | null;
  checkpoint_operation_uuid?: string | null;
  wall_seconds?: number;
  exit_code?: number;
  cost_usd?: number | null;
};

export type ShownCard = {
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

export type ShownResult = {
  verdict: string;
  reason: string;
  missing_details: string[];
  wall_seconds: number | null;
  card: ShownCard | null;
  model_cost_usd: number | null;
  sandbox_cost_usd: number | null;
  total_cost_usd: number | null;
};

export function stepLabel(step: DoorStepEvent): string {
  return STEP_LABEL[stepKey(step)] ?? step.step;
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
    <p className="field">
      <span className="field-label">{label}: </span>
      <span className="field-value">{shown}</span>
    </p>
  );
}

function textList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function LinkedText({ url, label }: { url: string; label: string }) {
  const href = safeHttpUrl(url);
  if (!href) return <span className="break-words">{label}</span>;
  return (
    <a className="break-all" href={href} rel="noreferrer">
      {label}
    </a>
  );
}

function numberField(record: Record<string, unknown>, key: string): number | null {
  return asNumber(record[key]);
}

export function PublicStatusBlock({
  status,
  summarySentence,
}: {
  status: Record<string, unknown>;
  summarySentence: string | null;
}) {
  const credits = numberField(status, "credits") ?? numberField(status, "tavily_credits");
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
    <div className="public-block" data-public-status={state || undefined}>
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
      {evidence.length ? (
        <ul className="evidence-pages">
          {evidence.map((item, index) => {
            const row = item !== null && typeof item === "object" ? (item as Record<string, unknown>) : {};
            const url = typeof row.url === "string" ? row.url : "";
            const title = typeof row.title === "string" && row.title ? row.title : url || "Untitled page";
            const frames = textList(row.frames_matched);
            return (
              <li className="evidence-page" key={`${url}-${index}`}>
                <p className="evidence-page-title">
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
                <Field label="Checked commit" value={row.checked_commit} />
                {textList(row.version_sources).map((source, sourceIndex) => (
                  <p className="field" data-version-source={source} key={`${source}-${sourceIndex}`}>
                    Version source: {source}
                  </p>
                ))}
                {textList(row.stale_fields).length ? (
                  <Field label="Stale fields" value={textList(row.stale_fields)} />
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}
      {draft.length ? (
        <ul className="draft-lines">
          {draft.map((item, index) => {
            const line = item !== null && typeof item === "object" ? (item as Record<string, unknown>) : {};
            const text = typeof line.text === "string" ? line.text : "";
            const source = typeof line.source_url === "string" ? line.source_url : "";
            if (!text) return null;
            const repeats = summarySentence !== null && text.startsWith(summarySentence);
            return (
              <li className="draft-line" data-draft-line key={`${source}-${index}`}>
                <p className="field-label">Draft line for the maintainer</p>
                <p>
                  {repeats ? (
                    <>
                      <span className="draft-repeat" data-draft-repeats-summary>
                        Opens with the summary sentence above.
                      </span>{" "}
                      {text.slice(summarySentence.length).trim()}
                    </>
                  ) : (
                    text
                  )}
                </p>
                <p className="draft-meta">
                  {source ? <LinkedText label={source} url={source} /> : null}{" "}
                  {typeof line.source_date === "string" ? <span>{line.source_date}</span> : null}{" "}
                  {typeof line.confidence === "string" ? <span>({line.confidence})</span> : null}
                </p>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
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
      {candidates.length ? (
        <ul className="evidence-pages">
          {candidates.map((candidate) => {
            const row = candidate as { id?: string; summary?: string; match_kind?: string };
            return (
              <li data-candidate-id={row.id} key={row.id ?? row.summary}>
                <span className="display">{row.id}</span>
                {row.match_kind ? <span> ({row.match_kind})</span> : null}
                {row.summary ? <span className="field-label block">{row.summary}</span> : null}
              </li>
            );
          })}
        </ul>
      ) : null}
    </>
  );
}

function StepBody({ step, summarySentence }: { step: DoorStepEvent; summarySentence: string | null }) {
  const payload = step.payload;
  if (step.step === "claim") {
    return (
      <>
        <Field label="Model" value={payload.model} />
        <Field label="Request id" value={payload.request_id} />
        <Field label="Input tokens" value={payload.input_tokens} />
        <Field label="Output tokens" value={payload.output_tokens} />
        <Field label="Cost USD" value={payload.cost_usd} />
        <Field
          label="Latency seconds"
          value={asNumber(payload.latency_seconds) == null ? null : seconds(asNumber(payload.latency_seconds) ?? 0)}
        />
        <Field label="Bug class" value={payload.bug_class} />
        <Field label="Functions" value={payload.functions} />
      </>
    );
  }
  if (step.step === "sandbox") {
    return (
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
    );
  }
  if (step.step === "crash") {
    return (
      <>
        <Field label="Crash type" value={payload.crash_type} />
        <Field label="Sanitizer" value={payload.sanitizer_kind} />
        <Field label="Crash state" value={payload.crash_state} />
        <Field label="Vulnerable crashed" value={payload.vulnerable_crashed} />
        <Field label="Vulnerable clean" value={payload.vulnerable_clean} />
        <Field label="Vulnerable exit code" value={payload.vulnerable_exit_code} />
        <Field label="Fixed build clean" value={payload.fix_clean} />
        <Field label="Fixed exit code" value={payload.fixed_exit_code} />
      </>
    );
  }
  if (step.step === "duplicates") return <Duplicates payload={payload} />;
  if (step.step === "public_status") return <PublicStatusBlock status={payload} summarySentence={summarySentence} />;
  if (step.step === "verdict") {
    return (
      <>
        <p data-verdict={asText(payload.verdict) ?? undefined}>{asText(payload.verdict)}</p>
        <Field label="Reason" value={payload.reason} />
        <Field label="Missing" value={payload.missing_details} />
        <Field label="Request ids" value={payload.request_ids} />
        <Field label="Model cost USD" value={payload.model_cost_usd} />
        <Field label="Sandbox cost USD" value={payload.sandbox_cost_usd} />
        <Field label="Run cost USD" value={payload.run_cost_usd} />
        <Field label="Checkpoint cost USD" value={payload.checkpoint_cost_usd} />
        <Field label="Total cost USD" value={payload.total_cost_usd} />
        <Field
          label="Wall seconds"
          value={asNumber(payload.wall_seconds) == null ? null : seconds(asNumber(payload.wall_seconds) ?? 0)}
        />
      </>
    );
  }
  return <pre className="field">{JSON.stringify(payload, null, 2)}</pre>;
}

function stepGist(step: DoorStepEvent): string {
  const payload = step.payload;
  if (step.step === "claim") {
    const id = asText(payload.request_id);
    return id ? `request ${id}` : "model call";
  }
  if (step.step === "sandbox") {
    const exit = asNumber(payload.exit_code);
    return exit !== null ? `exit code ${exit}` : (asText(payload.operation_uuid) ?? "");
  }
  if (step.step === "crash") return asText(payload.crash_type) ?? "no conclusive crash";
  if (step.step === "duplicates") {
    const count = Array.isArray(payload.candidates) ? payload.candidates.length : 0;
    return count === 1 ? "1 candidate" : `${count} candidates`;
  }
  if (step.step === "public_status") return asText(payload.state) ?? "";
  if (step.step === "verdict") return asText(payload.verdict) ?? "";
  return "";
}

export function Disclosure({
  title,
  gist,
  open,
  onToggle,
  children,
}: {
  title: string;
  gist: string;
  open: boolean;
  onToggle: (open: boolean) => void;
  children: ReactNode;
}) {
  return (
    <details className="disclosure" onToggle={(event) => onToggle(event.currentTarget.open)} open={open}>
      <summary>
        <span className="disclosure-title">{title}</span>
        {gist ? <span className="disclosure-gist">{gist}</span> : null}
        <span aria-hidden="true" className="disclosure-caret" />
      </summary>
      <div className="disclosure-body">{children}</div>
    </details>
  );
}

export function StepItem({
  step,
  open,
  onToggle,
  summarySentence,
}: {
  step: DoorStepEvent;
  open: boolean;
  onToggle: (open: boolean) => void;
  summarySentence: string | null;
}) {
  const operationId = typeof step.payload.operation_uuid === "string" ? step.payload.operation_uuid : undefined;
  return (
    <li className="evidence-item" data-kind={step.kind ?? undefined} data-operation-id={operationId} data-step={step.step}>
      <Disclosure gist={stepGist(step)} onToggle={onToggle} open={open} title={stepLabel(step)}>
        <StepBody step={step} summarySentence={summarySentence} />
      </Disclosure>
    </li>
  );
}

export function CardBody({
  result,
  hasPublicStep,
  summarySentence,
}: {
  result: ShownResult;
  hasPublicStep: boolean;
  summarySentence: string | null;
}) {
  const card = result.card;
  return (
    <>
      {result.reason ? <Field label="Reason" value={result.reason} /> : null}
      {result.missing_details.length ? <p>Missing: {result.missing_details.join(" ")}</p> : null}
      {card == null ? <p>No triage card was returned with this result.</p> : null}
      {card?.model_calls?.map((call) => (
        <p data-model-call={call.request_id} key={call.request_id}>
          Model call {call.model}: request {call.request_id}, {call.input_tokens} input tokens, {call.output_tokens}{" "}
          output tokens, {typeof call.cost_usd === "number" ? money(call.cost_usd) : ""} USD.
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
      {card?.public_status && !hasPublicStep ? (
        <PublicStatusBlock status={card.public_status} summarySentence={summarySentence} />
      ) : null}
    </>
  );
}
