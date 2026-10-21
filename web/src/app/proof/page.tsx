import Link from "next/link";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import run1Data from "@/content/eval100-run1.json";
import run2Data from "@/content/eval100-run2.json";
import patchData from "@/content/patch-eval.json";
import patchNotesData from "@/content/patch-eval-notes.json";
import patchRun2Data from "@/content/patch-eval-run2.json";
import patchRun2NotesData from "@/content/patch-eval-run2-notes.json";
import { dollars, proofRows, runAgreement, runHeadline, type Eval100Report, type ProofRow, type RunHeadline } from "@/lib/eval100";
import { displayCrashType } from "@/lib/crashType";
import type { PatchNotes, PatchReport, PatchRun } from "@/lib/patchEval";
import { Mark } from "@/ui/Mark";
import { PatchSection } from "@/ui/PatchSection";
import { Stamp, VerdictStamp } from "@/ui/Stamp";

export const metadata: Metadata = {
  title: "Reproof on 100 bugs",
  description: "Every task in Reproof's registered 100-bug evaluation, misses first.",
};

const REPO_URL = "https://github.com/StephenSook/reproof";
const BLOB = `${REPO_URL}/blob/main`;
const RUN1_FILE = "eval/results/eval100.json";
const RUN2_FILE = "eval/results/eval100-run2.json";
const PLAN_FILE = "eval/EVAL100-RUN2.md";
const PLAN_COMMIT = "0383504";

const run1 = run1Data as Eval100Report;
const run2 = run2Data as Eval100Report;
const patchRuns: PatchRun[] = [
  {
    key: "1",
    title: "Run 1",
    report: patchData as unknown as PatchReport,
    notes: patchNotesData as unknown as PatchNotes,
  },
  {
    key: "2",
    title: "Run 2",
    report: patchRun2Data as unknown as PatchReport,
    notes: patchRun2NotesData as unknown as PatchNotes,
  },
];

function Check({ ok, pass, fail }: { ok: boolean; pass: string; fail: string }) {
  return (
    <Stamp className="stamp-small" icon={ok ? "✓" : "×"} tone={ok ? "proof" : "crash"}>
      {ok ? pass : fail}
    </Stamp>
  );
}

function RunCard({ title, when, file, headline, children }: {
  title: string;
  when: string;
  file: string;
  headline: RunHeadline;
  children?: ReactNode;
}) {
  return (
    <article className="proof-run" data-proof-run={title}>
      <h3>{title}</h3>
      <p className="proof-run-when">{when}</p>
      <p className="proof-run-count">
        <span className="display">{headline.completed}</span> of {headline.requested} completed
      </p>
      {headline.failureCauses.length ? (
        <ul className="proof-run-causes">
          {headline.failureCauses.map((row) => (
            <li key={row.cause}>
              {row.count} {row.count === 1 ? "task" : "tasks"}: {row.cause}
            </li>
          ))}
        </ul>
      ) : (
        <p className="proof-run-causes">No task failed to run.</p>
      )}
      {children}
      <a className="proof-link" href={`${BLOB}/${file}`}>
        Read {file}
      </a>
    </article>
  );
}

function Row({ row }: { row: ProofRow }) {
  if (row.kind === "failed") {
    return (
      <li className="proof-row proof-row-failed" data-proof-row={row.failure.arvo_id} data-proof-kind="failed">
        <span className="proof-row-id">
          <span className="display">ARVO {row.failure.arvo_id}</span>
          <span>{row.failure.project}</span>
        </span>
        <Stamp className="stamp-small" icon="!" tone="slate">
          DID NOT RUN
        </Stamp>
        <span className="proof-row-why">{row.cause}. It counts against the 100.</span>
        <span className="num">#{row.position}</span>
      </li>
    );
  }
  const { task } = row;
  return (
    <li
      className={`proof-row ${row.misses.length ? "proof-row-miss" : ""}`.trim()}
      data-proof-kind={row.misses.length ? "miss" : "agree"}
      data-proof-row={task.arvo_id}
    >
      <span className="proof-row-id">
        <span className="display">ARVO {task.arvo_id}</span>
        <span>{task.project}</span>
      </span>
      <VerdictStamp className="stamp-small" verdict={task.verdict} />
      <span className="proof-row-checks">
        <Check fail="OSV differs" ok={task.crash_state_agreement_with_osv} pass="OSV match" />
        <Check fail="Fix not clean" ok={task.fix_clean} pass="Fix clean" />
        <Check fail="Claim differs" ok={task.claim_agreement} pass="Claim agrees" />
      </span>
      <span className="proof-row-crash">{task.crash_type ? displayCrashType(task.crash_type) : "No crash type"}</span>
      <span className="num">
        {dollars(task.cost_usd, 5)} · {task.wall_seconds.toFixed(1)} s · #{row.position}
      </span>
      <a className="proof-link" href={`${BLOB}/${task.card_path}`}>
        Card
      </a>
      {row.misses.length ? (
        <ul className="proof-row-misses">
          {row.misses.map((miss) => (
            <li key={miss}>{miss}</li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export default function ProofPage() {
  const headline = runHeadline(run2);
  const first = runHeadline(run1);
  const rows = proofRows(run2);
  const misses = rows.filter((row) => row.kind === "failed" || row.misses.length).length;
  const agreement = runAgreement(run1, run2);
  const lower = (text: string) => `${text.charAt(0).toLowerCase()}${text.slice(1)}`;
  const causes = headline.failureCauses.length === 1
    ? lower(headline.failureCauses[0].cause)
    : headline.failureCauses.map((row) => `${lower(row.cause)} on ${row.count}`).join(", ");
  const tiles = [
    { value: headline.crashMeasured, text: "crashed on the vulnerable build, as ARVO says they should" },
    { value: headline.fixClean, text: "ran clean on the fixed build" },
    { value: headline.osvAgree, text: "matched the crash state OSV recorded" },
    { value: headline.claimAgree, text: "had a report claim that matched the measured crash" },
  ];
  return (
    <div className="page">
      <a className="skip-link" href="#every-task">
        Skip to every task
      </a>
      <header className="site-head">
        <Link aria-label="Reproof, home" className="brand" href="/">
          <Mark size={34} />
          <span className="brand-name">Reproof</span>
        </Link>
        <nav aria-label="Pages">
          <ul className="nav-links">
            <li>
              <Link className="nav-link" href="/">
                Try a report
              </Link>
            </li>
            <li>
              <Link aria-current="page" className="nav-link" href="/proof">
                100 bugs
              </Link>
            </li>
            <li>
              <a className="nav-link" href={REPO_URL}>
                Code
              </a>
            </li>
          </ul>
        </nav>
      </header>
      <main className="grid min-w-0 gap-3" id="top">
        <section aria-labelledby="proof-title" className="section section-lead">
          <h1 className="hero-title proof-title" id="proof-title">
            {headline.requested} public bugs
          </h1>
          <p className="hero-lede">
            Reproof ran {headline.requested} real OSS-Fuzz crashes from ARVO through the vulnerable and the fixed build
            in Nebius sandboxes: {run2.historical_arvo_ids.length} from the earlier 10-bug evaluation and{" "}
            {run2.random_draw_arvo_ids.length} drawn at random by a rule committed before any of them ran. Of the{" "}
            {headline.requested}:
          </p>
          <ul className="proof-tiles">
            {tiles.map((tile) => (
              <li className="proof-tile" key={tile.text}>
                <span className="display proof-tile-value">{tile.value}</span>
                <span>{tile.text}</span>
              </li>
            ))}
          </ul>
          <p className="proof-cost">
            {dollars(headline.totalCostUsd)} for all {headline.requested}, about{" "}
            {dollars(headline.costPerTaskUsd, 4)} a bug, model and sandboxes together.{" "}
            {headline.failed
              ? `${headline.failed} ${headline.failed === 1 ? "task" : "tasks"} did not run (${causes}) and still count against the ${headline.requested}.`
              : `Every one of the ${headline.requested} ran.`}
          </p>
        </section>

        <section aria-labelledby="runs-title" className="section">
          <div className="section-heading">
            <h2 id="runs-title">Two runs</h2>
            <p className="section-lede">
              Run 1 lost its last tasks to a dropped model connection. Before run 2 started, a plan was committed saying
              what would change, that run 2 would be published whatever it showed, and that there would be no run 3.
              Run 2 then hit a different failure, and those tasks count against it too.
            </p>
            <p className="section-lede" data-run-agreement>
              {agreement.both} tasks completed in both runs.{" "}
              {agreement.sameVerdict === agreement.both
                ? `All ${agreement.both} got the same verdict both times.`
                : `${agreement.sameVerdict} of them got the same verdict both times.`}
            </p>
          </div>
          <div className="proof-runs">
            <RunCard file={RUN1_FILE} headline={first} title="Run 1" when="October 20, 00:37 to 01:15 ET" />
            <RunCard file={RUN2_FILE} headline={headline} title="Run 2" when="October 20, 01:58 to 02:26 ET">
              <p className="proof-run-plan">
                Plan committed in{" "}
                <a href={`${REPO_URL}/commit/${PLAN_COMMIT}`}>
                  <code>{PLAN_COMMIT}</code>
                </a>{" "}
                at 01:57 ET, before run 2 started. <a href={`${BLOB}/${PLAN_FILE}`}>Read the plan</a>
              </p>
            </RunCard>
          </div>
          <details className="proof-rule">
            <summary>How the {headline.requested} were picked</summary>
            <p>{run2.selection_rule}</p>
            {run2.prep_failed.length ? (
              <p>
                {run2.prep_failed.length} drawn {run2.prep_failed.length === 1 ? "bug" : "bugs"} failed to prepare (
                {run2.prep_failed.map((row) => `ARVO ${row.arvo_id}, ${row.project}, ${row.reason}`).join("; ")}), and the
                draw went on, as registered.
              </p>
            ) : null}
          </details>
        </section>

        <PatchSection repoUrl={REPO_URL} runs={patchRuns} />

        <section aria-labelledby="every-task-title" className="section" id="every-task">
          <div className="section-heading">
            <h2 id="every-task-title">Every task</h2>
            <p className="section-lede">
              All {rows.length} from run 2. The {misses} that did not run or missed a check come first, each with the
              reason. Every task that ran links to the card the run wrote.
            </p>
          </div>
          <ol className="proof-rows">
            {rows.map((row) => (
              <Row key={row.kind === "failed" ? row.failure.arvo_id : row.task.arvo_id} row={row} />
            ))}
          </ol>
        </section>
      </main>
      <footer className="site-foot">
        <p>
          Reproof is open source under Apache-2.0. <a href={REPO_URL}>Source on GitHub</a>
        </p>
        <p>
          The typeface is Recursive, used under the SIL Open Font License.{" "}
          <a href="/fonts-LICENSE.txt">Font license</a>
        </p>
      </footer>
    </div>
  );
}
