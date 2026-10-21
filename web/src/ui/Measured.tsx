import Link from "next/link";
import { costComparison, money, measuredSummary, PHASE1_NOTE, seconds, type MeasuredEvaluation } from "@/lib/measured";
import { verdictTone, Stamp } from "@/ui/Stamp";

type MeasuredTask = {
  arvo_id: number;
  project: string;
  verdict: string;
  duplicate_candidates: string[];
  cost_usd: number;
  wall_seconds: number;
};

type MeasuredFile = Omit<MeasuredEvaluation, "tasks"> & {
  tasks: MeasuredTask[];
};

export function Measured({ evaluation }: { evaluation: MeasuredFile }) {
  const lines = measuredSummary(evaluation);
  const tiles = lines.filter((line) => line !== PHASE1_NOTE);
  const verdictLines = new Set(tiles.filter((line) => /^\d+ [A-Z_]+$/.test(line)));
  const cost = costComparison(evaluation.totals);
  return (
    <section aria-labelledby="measured-heading" className="section-card tone-sage-section" id="measured">
      <div className="section-heading">
        <h2 id="measured-heading">Measured</h2>
        <p className="section-lede">These numbers are the saved ARVO 10 evaluation. They are not a new run.</p>
        <p className="section-lede">
          <Link href="/proof">See the registered run on 100 bugs, every task listed, misses first.</Link>
        </p>
      </div>
      <figure className="cost-compare" data-cost-compare>
        <figcaption className="cost-lead">{cost.lead}</figcaption>
        <dl className="cost-bars">
          {cost.bars.map((bar) => (
            <div className={`cost-row cost-row-${bar.key}`} data-cost={bar.key} key={bar.key}>
              <dt>{bar.label}</dt>
              <dd>
                <span aria-hidden="true" className="cost-track">
                  <span className="cost-fill" style={{ width: `${(bar.width * 100).toFixed(1)}%` }} />
                </span>
                <span className="cost-usd">{bar.text}</span>
              </dd>
            </div>
          ))}
        </dl>
        <p className="cost-foot">
          {cost.combined}, from {cost.tokens}.
        </p>
      </figure>
      <ul className="measured-tiles">
        {tiles.map((line) => (
          <li className={`measured-tile ${verdictLines.has(line) ? "measured-tile-lead" : ""}`} key={line}>
            {line}
          </li>
        ))}
      </ul>
      {lines.includes(PHASE1_NOTE) ? <p className="measured-note">{PHASE1_NOTE}</p> : null}
      <ol className="measured-rows">
        {evaluation.tasks.map((task) => (
          <li className="measured-row" data-measured-task={task.arvo_id} key={task.arvo_id}>
            <span className="display">ARVO {task.arvo_id}</span>
            <span>{task.project}</span>
            <Stamp className="stamp-small" data-verdict={task.verdict} tone={verdictTone(task.verdict)}>
              {task.verdict}
            </Stamp>
            <span>
              {task.duplicate_candidates.length ? task.duplicate_candidates.join(", ") : "no duplicate candidate"}
            </span>
            <span className="num">{money(task.cost_usd)} USD</span>
            <span className="num">{seconds(task.wall_seconds)} seconds</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
