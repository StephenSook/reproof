"use client";

import { money } from "@/lib/measured";
import { nextStep } from "@/lib/nextStep";
import { aboutSeconds, receiptArvoId, receiptSummary, utcMinute, type DoorReceipt } from "@/lib/receipt";
import { reportIds, reportLabel, type ReportNames } from "@/lib/reports";
import { spendLines } from "@/lib/spend";
import { Button } from "@/ui/Button";
import { publicTone, Stamp, VerdictStamp, verdictTone } from "@/ui/Stamp";
import { useTriageChannel } from "@/ui/TriageContext";

const VERDICTS = [
  {
    verdict: "REPRODUCED",
    text: "The vulnerable build produced a measured sanitizer crash and the fixed build was clean.",
  },
  { verdict: "DUPLICATE", text: "The measured crash state matched one or more public OSV records." },
  { verdict: "NOT_REPRODUCED", text: "The vulnerable build completed cleanly without a sanitizer crash." },
  { verdict: "NEEDS_INFO", text: "The run cannot support another verdict. The card says what is missing." },
];

/**
 * A finished answer in the first screen: the recorded live response for one report, read from its
 * receipt, with a button that runs the same report live. Every value comes from the receipt.
 */
export function HeroAnswer({ receipt, task }: { receipt: DoorReceipt; task: ReportNames }) {
  const channel = useTriageChannel();
  const arvoId = receiptArvoId(receipt);
  const summary = receiptSummary(receipt);
  const step = nextStep(summary);
  const spend = spendLines(summary.spend, summary.totals.modelCalls);
  const publicState = summary.publicStatus.kind === "STATUS" ? summary.publicStatus.state : null;
  const estimate = aboutSeconds(receipt.client_elapsed_seconds);
  // The card's left edge takes the public state's tone, or the verdict's when there is no public state.
  const tone = publicState ? publicTone(publicState) : summary.verdict ? verdictTone(summary.verdict) : "slate";
  return (
    <aside aria-labelledby="hero-answer-title" className={`hero-answer tone-${tone}`} data-hero-answer>
      <p className="hero-answer-when" data-hero-recorded-at={receipt.recorded_at_utc}>
        Recorded from the live door, {utcMinute(receipt.recorded_at_utc)}
      </p>
      <h2 className="hero-answer-title" id="hero-answer-title">
        {reportLabel(task)}
      </h2>
      <p className="hero-answer-ids">{reportIds(task)}</p>
      {step ? (
        <p className="hero-answer-step" data-hero-next-step>
          <span className="next-finding">{step.finding}</span> <span className="next-action">{step.action}</span>
        </p>
      ) : null}
      <div className="summary-stamps">
        {summary.verdict ? <VerdictStamp className="stamp-public" verdict={summary.verdict} /> : null}
        {publicState ? (
          <Stamp className="stamp-public" tone={publicTone(publicState)}>
            {publicState}
          </Stamp>
        ) : null}
      </div>
      <dl className="hero-answer-facts">
        {summary.totals.seconds !== null ? (
          <div data-hero-fact="time">
            <dt>Time</dt>
            <dd>{summary.totals.seconds.toFixed(2)} s</dd>
          </div>
        ) : null}
        {summary.totals.usd !== null ? (
          <div data-hero-fact="cost">
            <dt>Cost</dt>
            <dd>{money(summary.totals.usd)} USD</dd>
          </div>
        ) : null}
        {summary.totals.tavilyCredits !== null ? (
          <div data-hero-fact="credits">
            <dt>Tavily credits</dt>
            <dd>{summary.totals.tavilyCredits}</dd>
          </div>
        ) : null}
      </dl>
      {spend.model ? (
        <ul className="hero-answer-model" data-hero-model>
          <li>
            {spend.model}
            {spend.modelUsd ? `: ${spend.modelUsd}` : ""}
          </li>
          {spend.sandbox ? (
            <li>
              {spend.sandbox}
              {spend.sandboxUsd ? `: ${spend.sandboxUsd}` : ""}
            </li>
          ) : null}
        </ul>
      ) : null}
      <div className="hero-answer-actions">
        <Button icon={"▶"} onClick={() => channel?.run(arvoId)}>
          Run it live ({estimate})
        </Button>
        <Button onClick={() => channel?.showRecorded(arvoId)} variant="secondary">
          Open the evidence
        </Button>
      </div>
      <details className="verdict-key" data-verdict-key>
        <summary>What each verdict means</summary>
        <ul>
          {VERDICTS.map((row) => (
            <li key={row.verdict}>
              <VerdictStamp className="stamp-small" verdict={row.verdict} />
              <p>{row.text}</p>
            </li>
          ))}
        </ul>
        <p>Public status is a separate line. It does not change the verdict.</p>
      </details>
    </aside>
  );
}
