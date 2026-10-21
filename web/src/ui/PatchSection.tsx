import { dollars } from "@/lib/eval100";
import { displayCrashType } from "@/lib/crashType";
import {
  attemptText,
  blockedSentence,
  outcomeText,
  patchHeadline,
  upstreamCommitUrl,
  type PatchNotes,
  type PatchReport,
  type PatchRow,
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

function PatchRowItem({
  row,
  note,
  blob,
  maxAttempts,
}: {
  row: PatchRow;
  note: PatchNotes["tasks"][number] | undefined;
  blob: string;
  maxAttempts: number;
}) {
  const upstream = upstreamCommitUrl(row);
  const blocked = note ? blockedSentence(note.blocked_attempts, note.blocking_line) : "";
  return (
    <li className="proof-row patch-row" data-patch-outcome={row.outcome} data-patch-row={row.arvo_id}>
      <span className="proof-row-id">
        <span className="display">ARVO {row.arvo_id}</span>
        <span>{row.project}</span>
      </span>
      <Stamp className="stamp-small" icon={OUTCOME_ICON[row.outcome] ?? "•"} tone={OUTCOME_TONE[row.outcome] ?? "slate"}>
        {outcomeText(row.outcome).toUpperCase()}
      </Stamp>
      <span className="patch-attempts" data-patch-attempts>
        {row.attempt_outcomes.length
          ? row.attempt_outcomes.map((outcome, index) => `${index + 1}: ${attemptText(outcome)}`).join(" · ")
          : row.detail}
      </span>
      <span className="proof-row-crash">{row.baseline_crash_type ? displayCrashType(row.baseline_crash_type) : "No crash measured"}</span>
      <span className="num">
        {row.model_calls} of {maxAttempts} calls · {dollars(row.model_cost_usd, 5)}
      </span>
      <a className="proof-link" href={`${blob}/${row.card_path}`}>
        Card
      </a>
      {blocked ? (
        <p className="patch-blocked" data-patch-blocked>
          {blocked}
        </p>
      ) : null}
      {row.outcome === "PROVEN" ? (
        <details className="patch-diff" data-patch-diff>
          <summary>The edit Nemotron wrote</summary>
          {row.proven_rationale ? <p className="patch-rationale">Nemotron&apos;s reason: {row.proven_rationale}</p> : null}
          <pre aria-label={`Diff for ARVO ${row.arvo_id}`} tabIndex={0}>
            {row.proven_diff}
          </pre>
          <p className="patch-check">Checked by: {row.proven_regression_check}.</p>
          {upstream ? (
            <p className="patch-upstream">
              Compare with the upstream fix,{" "}
              <a href={upstream}>
                <code>{row.upstream_fix_commits[0]?.slice(0, 7)}</code>
              </a>
              . Proven means it rebuilt and stopped the crash, not that it is the upstream fix or safe to merge.
            </p>
          ) : null}
        </details>
      ) : null}
    </li>
  );
}

export function PatchSection({
  report,
  notes,
  repoUrl,
}: {
  report: PatchReport;
  notes: PatchNotes;
  repoUrl: string;
}) {
  const headline = patchHeadline(report);
  const blob = `${repoUrl}/blob/main`;
  const byId = new Map(notes.tasks.map((task) => [task.arvo_id, task]));
  const totals = notes.totals;
  return (
    <section aria-labelledby="patches-title" className="section" data-patch-section id="patches">
      <div className="section-heading">
        <h2 id="patches-title">Can Nemotron write the fix? An offline test</h2>
        <p className="section-lede">
          For the 10 historical bugs, Nemotron 3 Super got the report, the sanitizer output and the source around the
          crash, and wrote exact-text edits. Each edit was applied inside the bug&apos;s ARVO image, the project was
          rebuilt with <code>arvo compile</code>, and the stored input was run again, with up to {report.max_attempts}{" "}
          attempts and the build error or the new crash sent back each time. Code decided the result, by a rule committed
          before the run.
        </p>
        <p className="section-lede" data-patch-offline>
          Every patch here was proposed and proven offline, in a local Docker container that was deleted afterwards.
          None was applied upstream, filed, or sent to a project.
        </p>
      </div>
      <ul className="proof-tiles">
        <li className="proof-tile" data-patch-headline>
          <span className="display proof-tile-value">
            {headline.proven} of {headline.total}
          </span>
          <span>{headline.sentence}</span>
        </li>
        <li className="proof-tile">
          <span className="display proof-tile-value">{headline.calls}</span>
          <span>model calls. {headline.attempts}</span>
        </li>
        <li className="proof-tile">
          <span className="display proof-tile-value">{dollars(headline.costUsd, 4)}</span>
          <span>on Token Factory for all {headline.total}, against a ${report.budget_usd} cap.</span>
        </li>
      </ul>
      <p className="proof-cost" data-patch-breakdown>
        {headline.breakdown.map((row) => row.text).join(", ")}.{" "}
        <a href={`${repoUrl}/commit/${report.prereg.commit}`}>
          Rule committed in <code>{report.prereg.commit.slice(0, 7)}</code>
        </a>{" "}
        before the run. <a href={`${blob}/${report.prereg.path}`}>Read the rule</a>
      </p>
      <p className="proof-cost patch-harness-note" data-patch-harness-note>
        Found during the run: {totals.blocked_attempts} of the {totals.attempts} attempts never tested their edit. In{" "}
        {totals.tasks_with_blocked_attempts} images the build script makes a directory with plain <code>mkdir</code>, so
        its second run in one container stops, and the harness had already run it once as a control. Those tasks still
        count as not proven under the registered rule, and the run was not repeated. Only {totals.attempts_that_built}{" "}
        attempts, in {totals.tasks_where_an_edit_built} tasks, built an edit; {headline.proven} of them were proven.{" "}
        <a href={`${blob}/eval/results/patch-eval-notes.json`}>Read the notes</a>
      </p>
      <ol className="proof-rows">
        {report.tasks.map((row) => (
          <PatchRowItem
            blob={blob}
            key={row.arvo_id}
            maxAttempts={report.max_attempts}
            note={byId.get(row.arvo_id)}
            row={row}
          />
        ))}
      </ol>
    </section>
  );
}
