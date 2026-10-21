import { dollars } from "@/lib/eval100";
import { displayCrashType } from "@/lib/crashType";
import {
  attemptText,
  blockedSentence,
  harnessSentence,
  outcomeText,
  pairTasks,
  patchHeadline,
  plainPatch,
  provenList,
  runWindow,
  upstreamCommitUrl,
  type PatchCell,
  type PatchRun,
  type PatchTaskPair,
} from "@/lib/patchEval";
import { Stamp, type Tone } from "@/ui/Stamp";

const OUTCOME_TONE: Record<string, Tone> = {
  PROVEN: "proof",
  NOT_PROVEN: "crash",
  HARNESS_FAILED: "slate",
  BUDGET_STOPPED: "slate",
};

const OUTCOME_ICON: Record<string, string> = {
  PROVEN: "✓",
  NOT_PROVEN: "×",
  HARNESS_FAILED: "!",
  BUDGET_STOPPED: "!",
};

/** How each run's harness ran the attempts, in one line under the run's title. */
const HARNESS: Record<string, string> = {
  "1": "Every attempt rebuilt in the container that had already run the control build.",
  "2": "Every attempt rebuilt in a fresh container from a snapshot taken before the control build.",
};

function RunCard({ run, blob, repoUrl }: { run: PatchRun; blob: string; repoUrl: string }) {
  const { report, notes } = run;
  const headline = patchHeadline(report);
  const proven = provenList(report);
  const totals = notes.totals;
  return (
    <article className="proof-run patch-run" data-patch-run={run.key}>
      <h3>{run.title}</h3>
      <p className="proof-run-when">
        {runWindow(report)}. {HARNESS[run.key] ?? ""}
      </p>
      <p className="proof-run-count" data-patch-headline>
        <span className="display">
          {headline.proven} of {headline.total}
        </span>{" "}
        {headline.sentence}
      </p>
      <p>
        {headline.calls} model calls. {headline.attempts} {dollars(headline.costUsd, 4)} on Token Factory for all{" "}
        {headline.total}, against a ${report.budget_usd} cap.
      </p>
      <p data-patch-breakdown>
        {headline.breakdown.map((row) => row.text).join(", ")}.{proven ? ` Proven: ${proven}.` : ""}
      </p>
      {run.key === "1" ? (
        <p className="patch-harness-note" data-patch-harness-note>
          Found during the run: {totals.blocked_attempts} of the {totals.attempts} attempts never tested their edit. In{" "}
          {totals.tasks_with_blocked_attempts} images the build script makes a directory with plain <code>mkdir</code>,
          so its second run in one container stops, and the harness had already run it once as a control. Those tasks
          still count as not proven in run 1, under its registered rule. Only{" "}
          {totals.attempts_that_built} attempts, in {totals.tasks_where_an_edit_built} tasks, built an edit;{" "}
          {headline.proven} of them were proven. <a href={`${blob}/eval/results/patch-eval-notes.json`}>Read the notes</a>
        </p>
      ) : (
        <p className="patch-harness-note" data-patch-harness-note>
          {harnessSentence(notes)}{" "}
          <a href={`${blob}/eval/results/patch-eval-run2-notes.json`}>Read the notes</a>
        </p>
      )}
      <p className="proof-run-plan">
        <a href={`${repoUrl}/commit/${report.prereg.commit}`}>
          Rule committed in <code>{report.prereg.commit.slice(0, 7)}</code>
        </a>{" "}
        before the run. <a href={`${blob}/${report.prereg.path}`}>Read the rule</a>
      </p>
    </article>
  );
}

function RunCell({ cell, blob, upstreamNote }: { cell: PatchCell; blob: string; upstreamNote: string }) {
  const { run, row, note } = cell;
  const upstream = upstreamCommitUrl(row);
  const blocked = note ? blockedSentence(note.blocked_attempts, note.blocking_line) : "";
  const plain = row.outcome === "PROVEN" ? plainPatch(run.key, row.arvo_id) : "";
  return (
    <div className="patch-run-cell" data-patch-outcome={row.outcome} data-patch-run-cell={run.key}>
      <p className="patch-run-cell-head">
        <span className="patch-run-label">{run.title}</span>
        <Stamp className="stamp-small" icon={OUTCOME_ICON[row.outcome] ?? "•"} tone={OUTCOME_TONE[row.outcome] ?? "slate"}>
          {outcomeText(row.outcome).toUpperCase()}
        </Stamp>
      </p>
      <p className="patch-attempts" data-patch-attempts>
        {row.attempt_outcomes.length
          ? row.attempt_outcomes.map((outcome, index) => `${index + 1}: ${attemptText(outcome)}`).join(" · ")
          : row.detail}
      </p>
      <p className="num">
        {row.model_calls} of {run.report.max_attempts} calls · {dollars(row.model_cost_usd, 5)} ·{" "}
        <a className="proof-link" href={`${blob}/${row.card_path}`}>
          {run.title} card
        </a>
      </p>
      {blocked ? (
        <p className="patch-blocked" data-patch-blocked>
          {blocked}
        </p>
      ) : null}
      {plain ? (
        <p className="patch-plain" data-patch-plain>
          What the edit does: {plain}
        </p>
      ) : null}
      {row.outcome === "PROVEN" ? (
        <details className="patch-diff" data-patch-diff>
          <summary>{run.title}: the edit Nemotron wrote</summary>
          {row.proven_rationale ? <p className="patch-rationale">Nemotron&apos;s reason: {row.proven_rationale}</p> : null}
          <pre aria-label={`${run.title} diff for ARVO ${row.arvo_id}`} tabIndex={0}>
            {row.proven_diff}
          </pre>
          <p className="patch-check">Checked by: {row.proven_regression_check}.</p>
          {upstream ? (
            <p className="patch-upstream">
              Compare with the upstream fix,{" "}
              <a href={upstream}>
                <code>{row.upstream_fix_commits[0]?.slice(0, 7)}</code>
              </a>
              . {upstreamNote}
            </p>
          ) : (
            <p className="patch-upstream">{upstreamNote}</p>
          )}
        </details>
      ) : null}
    </div>
  );
}

const UPSTREAM_NOTE =
  "Proven means it rebuilt and stopped the crash, not that it is the upstream fix or safe to merge.";

function PatchRowItem({ pair, blob }: { pair: PatchTaskPair; blob: string }) {
  const best = pair.cells.some((cell) => cell.row.outcome === "PROVEN") ? "PROVEN" : (pair.cells.at(-1)?.row.outcome ?? "");
  return (
    <li className="proof-row patch-row" data-patch-best={best} data-patch-row={pair.arvo_id}>
      <span className="proof-row-id">
        <span className="display">ARVO {pair.arvo_id}</span>
        <span>{pair.project}</span>
        <span className="proof-row-crash">
          {pair.baseline_crash_type ? displayCrashType(pair.baseline_crash_type) : "No crash measured"}
        </span>
      </span>
      <div className="patch-run-cells">
        {pair.cells.map((cell) => (
          <RunCell blob={blob} cell={cell} key={cell.run.key} upstreamNote={UPSTREAM_NOTE} />
        ))}
      </div>
    </li>
  );
}

export function PatchSection({ runs, repoUrl }: { runs: PatchRun[]; repoUrl: string }) {
  const blob = `${repoUrl}/blob/main`;
  const pairs = pairTasks(runs);
  const maxAttempts = runs[0]?.report.max_attempts ?? 3;
  return (
    <section aria-labelledby="patches-title" className="section" data-patch-section id="patches">
      <div className="section-heading">
        <h2 id="patches-title">Can Nemotron write the fix? An offline test</h2>
        <p className="section-lede">
          For the 10 historical bugs, Nemotron 3 Super got the report, the sanitizer output and the source around the
          crash, and wrote exact-text edits. Each edit was applied inside the bug&apos;s ARVO image, the project was
          rebuilt with <code>arvo compile</code>, and the stored input was run again, with up to {maxAttempts} attempts
          and the build error or the new crash sent back each time. Code decided the result, by a rule committed before
          each run. Run 2 is run 1 with the harness defect below fixed; both are shown as recorded.
        </p>
        <p className="section-lede" data-patch-offline>
          Every patch here was proposed and proven offline, in a local Docker container that was deleted afterwards.
          None was applied upstream, filed, or sent to a project.
        </p>
      </div>
      <div className="proof-runs patch-runs">
        {runs.map((run) => (
          <RunCard blob={blob} key={run.key} repoUrl={repoUrl} run={run} />
        ))}
      </div>
      <ol className="proof-rows">
        {pairs.map((pair) => (
          <PatchRowItem blob={blob} key={pair.arvo_id} pair={pair} />
        ))}
      </ol>
    </section>
  );
}
