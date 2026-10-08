"use client";

import { useRef, type ReactNode } from "react";
import { money } from "@/lib/measured";
import type { DoorSummary, FixedTile, PublicSummary, VulnerableTile } from "@/lib/summary";
import { AncestryRibbon } from "@/ui/AncestryRibbon";
import { plop, settle, useArrival } from "@/ui/motion/motion";
import { Stamp, VerdictStamp, verdictTone, type Tone } from "@/ui/Stamp";

const PUBLIC_TONE: Record<string, Tone> = {
  PUBLICLY_KNOWN_FIXED: "proof",
  PUBLICLY_KNOWN_OPEN: "info",
  RELATED_VARIANTS_ONLY: "dup",
  SOURCE_DISPUTE: "info",
  NO_PUBLIC_FINDINGS: "slate",
  LOOKUP_UNAVAILABLE: "slate",
};

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
        {tile.crashType ? <TileRow label="Crash">{tile.crashType}</TileRow> : null}
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
        {status.kind === "STATUS" && status.state ? (
          <Stamp className="stamp-small" tone={PUBLIC_TONE[status.state] ?? "slate"}>
            {status.state}
          </Stamp>
        ) : null}
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

function Totals({ summary, running }: { summary: DoorSummary; running: boolean }) {
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

export function Summary({
  summary,
  running,
  arvoId,
  progress,
}: {
  summary: DoorSummary;
  running: boolean;
  arvoId: number | null;
  progress: Progress;
}) {
  const tone = summary.verdict ? verdictTone(summary.verdict) : "slate";
  const verdictRef = useRef<HTMLSpanElement>(null);
  useArrival(verdictRef, summary.verdict, plop);
  return (
    <div className={`summary tone-${tone}`} data-summary data-summary-source={summary.source}>
      <div className="summary-top">
        <span className={`source-chip source-${summary.source.toLowerCase()}`}>{summary.source}</span>
        <h3 className="summary-kicker" id="result-heading" tabIndex={-1}>
          {arvoId !== null ? `Answer for ARVO ${arvoId}` : "Answer"}
        </h3>
      </div>
      {summary.source === "RECORDED" ? (
        <p className="summary-note">This is the saved evaluation row. It is not a new triage card.</p>
      ) : null}
      <div className="summary-verdict" data-summary-verdict={summary.verdict ?? ""}>
        {summary.verdict ? (
          <span className="motion-wrap" ref={verdictRef}>
            <VerdictStamp className="stamp-verdict" verdict={summary.verdict} />
          </span>
        ) : (
          <Stamp className="stamp-verdict stamp-waiting" tone="slate">
            {running ? "Running" : "No verdict"}
          </Stamp>
        )}
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
      <Totals running={running} summary={summary} />
    </div>
  );
}
