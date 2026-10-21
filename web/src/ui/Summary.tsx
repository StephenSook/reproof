"use client";

import { useRef, type ReactNode } from "react";
import { displayCrashType } from "@/lib/crashType";
import { money } from "@/lib/measured";
import { nextStep } from "@/lib/nextStep";
import { spendLines } from "@/lib/spend";
import { utcMinute } from "@/lib/receipt";
import type { DoorSummary, FixedTile, PublicSummary, VulnerableTile } from "@/lib/summary";
import { AncestryRibbon } from "@/ui/AncestryRibbon";
import { plop, settle, useArrival } from "@/ui/motion/motion";
import { publicTone, Stamp, VerdictStamp, verdictTone, type Tone } from "@/ui/Stamp";

export type Progress = { key: string; label: string; done: boolean }[];

function waitingWord(running: boolean): string {
  return running ? "Waiting" : "Not sent";
}

function TileRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="tile-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function VulnerableBuild({ tile, running }: { tile: VulnerableTile; running: boolean }) {
  const tone: Tone = tile.state === "CRASHED" ? "crash" : tile.state === "CLEAN" ? "slate" : "info";
  const stampRef = useRef<HTMLSpanElement>(null);
  useArrival(stampRef, tile.state, settle);
  return (
    <section aria-label="Vulnerable build" className="build-tile" data-summary-vulnerable={tile.state ?? ""}>
      <h4>Vulnerable build</h4>
      {tile.state ? (
        <span className="motion-wrap" ref={stampRef}>
          <Stamp icon={tile.state === "CRASHED" ? "✕" : tile.state === "CLEAN" ? "✓" : "?"} tone={tone}>
            {tile.state}
          </Stamp>
        </span>
      ) : (
        <Stamp className="stamp-waiting" tone="slate">
          {waitingWord(running)}
        </Stamp>
      )}
      <dl className="tile-rows">
        {tile.crashType ? <TileRow label="Crash">{displayCrashType(tile.crashType)}</TileRow> : null}
        {tile.topFrame ? (
          <TileRow label="Top frame">
            <code>{tile.topFrame}</code>
          </TileRow>
        ) : null}
        <TileRow label="Exit code">{tile.exitCode ?? waitingWord(running).toLowerCase()}</TileRow>
      </dl>
    </section>
  );
}

function FixedBuild({ tile, running }: { tile: FixedTile; running: boolean }) {
  const stampRef = useRef<HTMLSpanElement>(null);
  useArrival(stampRef, tile.state, settle);
  return (
    <section aria-label="Fixed build" className="build-tile" data-summary-fixed={tile.state ?? ""}>
      <h4>Fixed build</h4>
      {tile.state ? (
        <span className="motion-wrap" ref={stampRef}>
          <Stamp icon={tile.state === "CLEAN" ? "✓" : "!"} tone={tile.state === "CLEAN" ? "proof" : "crash"}>
            {tile.state === "CLEAN" ? "CLEAN" : "NOT CLEAN"}
          </Stamp>
        </span>
      ) : (
        <Stamp className="stamp-waiting" tone="slate">
          {waitingWord(running)}
        </Stamp>
      )}
      <dl className="tile-rows">
        <TileRow label="Exit code">{tile.exitCode ?? waitingWord(running).toLowerCase()}</TileRow>
      </dl>
    </section>
  );
}

function PublicLine({ status }: { status: PublicSummary }) {
  const state = status.kind === "STATUS" ? status.state : status.kind;
  return (
    <section aria-label="Public status" className="public-line" data-summary-public={state}>
      <div className="public-head">
        <h4>Public status</h4>
      </div>
      <p className="public-sentence" data-summary-public-line>
        {status.line}
      </p>
      {status.kind === "STATUS" && status.ribbon ? <AncestryRibbon ribbon={status.ribbon} /> : null}
      {status.kind === "STATUS" && status.link ? (
        <p className="public-link">
          <span className="field-label">Source page: </span>
          <a href={status.link.href} rel="noreferrer">
            {status.link.label}
          </a>
          <span aria-hidden="true"> {"↗"}</span>
        </p>
      ) : null}
      {status.kind === "STATUS" && status.reusedFrom ? (
        <p className="public-reused">Reused lookup from {status.reusedFrom} UTC. This triage sent no Tavily call.</p>
      ) : null}
    </section>
  );
}

/** A recorded run's own time, shown as the reference while a live run counts up. */
export type TypicalRun = { seconds: number; project: string };

function Totals({
  summary,
  running,
  elapsedSeconds,
  typicalRun,
}: {
  summary: DoorSummary;
  running: boolean;
  elapsedSeconds: number | null;
  typicalRun: TypicalRun | null;
}) {
  const { totals } = summary;
  const wait = waitingWord(running).toLowerCase();
  const credits =
    totals.tavilyCredits !== null
      ? String(totals.tavilyCredits)
      : summary.publicStatus.kind === "NOT_RECORDED"
        ? "not recorded"
        : summary.publicStatus.kind === "NOT_RUN"
          ? "not in result"
          : wait;
  return (
    <dl aria-label="Totals" className="totals" data-summary-totals>
      <div>
        <dt>Wall time</dt>
        <dd>
          {totals.seconds !== null ? (
            <>
              {totals.seconds.toFixed(2)}
              <span className="unit"> s</span>
            </>
          ) : running && elapsedSeconds !== null ? (
            <>
              <span data-elapsed={elapsedSeconds}>
                {elapsedSeconds}
                <span className="unit"> s elapsed</span>
              </span>
              {typicalRun ? (
                <small data-typical-run>
                  The recorded {typicalRun.project} run took {typicalRun.seconds.toFixed(1)} s.
                </small>
              ) : null}
            </>
          ) : (
            wait
          )}
        </dd>
      </div>
      <div>
        <dt>Cost</dt>
        <dd>
          {totals.usd !== null ? (
            <>
              {money(totals.usd)}
              <span className="unit"> USD</span>
            </>
          ) : (
            wait
          )}
        </dd>
      </div>
      <div>
        <dt>Tavily credits</dt>
        <dd>
          {credits}
          {totals.tavilyUnanswered > 0 ? <small> plus {totals.tavilyUnanswered} estimated</small> : null}
        </dd>
      </div>
      <div>
        <dt>Model calls</dt>
        <dd>{totals.modelCalls !== null ? totals.modelCalls : wait}</dd>
      </div>
    </dl>
  );
}

/** Where the cost went, model calls against sandbox runs, named from the result's own fields. */
function Spend({ summary }: { summary: DoorSummary }) {
  const savedRow = summary.source === "RECORDED" && summary.recordedAt === null;
  const lines = spendLines(summary.spend, summary.totals.modelCalls, savedRow);
  if (!lines.model && !lines.sandbox) return null;
  return (
    <div className="spend" data-summary-spend>
      {lines.modelShare !== null ? (
        <div aria-hidden="true" className="spend-bar">
          <span className="spend-bar-model" style={{ width: `${(lines.modelShare * 100).toFixed(1)}%` }} />
          <span className="spend-bar-sandbox" />
        </div>
      ) : null}
      <ul className="spend-lines">
        {lines.model ? (
          <li data-spend-model>
            <span className="spend-key spend-key-model" aria-hidden="true" />
            <span>{lines.model}</span>
            {lines.modelUsd ? <span className="spend-usd">{lines.modelUsd}</span> : null}
          </li>
        ) : null}
        {lines.sandbox ? (
          <li data-spend-sandbox>
            <span className="spend-key spend-key-sandbox" aria-hidden="true" />
            <span>{lines.sandbox}</span>
            {lines.sandboxUsd ? <span className="spend-usd">{lines.sandboxUsd}</span> : null}
          </li>
        ) : null}
      </ul>
    </div>
  );
}

export function Summary({
  summary,
  running,
  title,
  progress,
  elapsedSeconds = null,
  typicalRun = null,
}: {
  summary: DoorSummary;
  running: boolean;
  /** The report as a maintainer names it, for example "jq: heap-buffer-overflow in decToString". */
  title: string | null;
  progress: Progress;
  /** Whole seconds since a live triage started, while it runs. */
  elapsedSeconds?: number | null;
  typicalRun?: TypicalRun | null;
}) {
  const tone = summary.verdict ? verdictTone(summary.verdict) : "slate";
  const verdictRef = useRef<HTMLSpanElement>(null);
  useArrival(verdictRef, summary.verdict, plop);
  const step = nextStep(summary);
  const publicState = summary.publicStatus.kind === "STATUS" ? summary.publicStatus.state : null;
  return (
    <div className={`summary tone-${tone}`} data-summary data-summary-source={summary.source}>
      <div className="summary-top">
        <span className={`source-chip source-${summary.source.toLowerCase()}`}>{summary.source}</span>
        <h3 className="summary-kicker" id="result-heading" tabIndex={-1}>
          {title !== null ? `Answer for ${title}` : "Answer"}
        </h3>
      </div>
      {summary.source === "RECORDED" && summary.recordedAt ? (
        <p className="summary-note" data-recorded-at={summary.recordedAt}>
          Recorded from the live door at {utcMinute(summary.recordedAt)}. Triage runs it again now.
        </p>
      ) : summary.source === "RECORDED" ? (
        <p className="summary-note">This is the saved evaluation row. It is not a new triage card.</p>
      ) : null}
      <div className="summary-verdict" data-summary-verdict={summary.verdict ?? ""}>
        {step ? (
          <p className="next-step" data-next-step>
            <span className="next-finding">{step.finding}</span> <span className="next-action">{step.action}</span>
          </p>
        ) : null}
        <div className="summary-stamps">
          {summary.verdict ? (
            <span className="motion-wrap" ref={verdictRef}>
              <VerdictStamp className="stamp-verdict" verdict={summary.verdict} />
            </span>
          ) : (
            <Stamp className="stamp-verdict stamp-waiting" tone="slate">
              {running ? "Running" : "No verdict"}
            </Stamp>
          )}
          {publicState ? (
            <Stamp className="stamp-public" data-public-stamp={publicState} tone={publicTone(publicState)}>
              {publicState}
            </Stamp>
          ) : null}
        </div>
        <p className="summary-sentence">{summary.sentence}</p>
        {summary.details.map((detail) => (
          <p className="summary-detail" key={detail}>
            {detail}
          </p>
        ))}
      </div>
      {running ? (
        <ol aria-label="Steps received" className="progress">
          {progress.map((item) => (
            <li className={item.done ? "progress-done" : ""} key={item.key}>
              <span aria-hidden="true">{item.done ? "✓" : "•"}</span>
              {item.label}
              <span className="sr-only">{item.done ? " received" : " waiting"}</span>
            </li>
          ))}
        </ol>
      ) : null}
      <div className="build-tiles">
        <VulnerableBuild running={running} tile={summary.vulnerable} />
        <FixedBuild running={running} tile={summary.fixed} />
      </div>
      <PublicLine status={summary.publicStatus} />
      <Totals elapsedSeconds={elapsedSeconds} running={running} summary={summary} typicalRun={typicalRun} />
      <Spend summary={summary} />
    </div>
  );
}
