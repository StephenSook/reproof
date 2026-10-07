import { money, measuredSummary, PHASE1_NOTE, seconds, type MeasuredEvaluation } from "@/lib/measured";
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
  return (
    <section aria-labelledby="measured-heading" className="section-card tone-sage-section" id="measured">
      <div className="section-heading">
        <p className="hand">the saved run, not a new one</p>
        <h2 id="measured-heading">Measured</h2>
        <p className="section-lede">These numbers are the saved ARVO 10 evaluation. They are not a new run.</p>
      </div>
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
