import { money, measuredSummary, seconds, type MeasuredEvaluation } from "@/lib/measured";

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
  return (
    <section aria-labelledby="measured-heading" className="mt-12 border-t border-[var(--line)] pt-8" id="measured">
      <h2 className="text-4xl" id="measured-heading">
        Measured
      </h2>
      <p className="mt-3 max-w-3xl text-[var(--muted)]">
        These numbers are the saved ARVO 10 evaluation. They are not a new run.
      </p>
      <ul className="mt-4 grid gap-1">
        {lines.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      <ol className="mt-6 grid list-none gap-3 p-0">
        {evaluation.tasks.map((task) => (
          <li
            className="flex min-w-0 flex-wrap gap-x-4 gap-y-1 border border-[var(--line)] bg-[var(--card)] px-3 py-3"
            data-measured-task={task.arvo_id}
            key={task.arvo_id}
          >
            <span>ARVO {task.arvo_id}</span>
            <span>{task.project}</span>
            <span data-verdict={task.verdict}>{task.verdict}</span>
            <span>
              {task.duplicate_candidates.length
                ? task.duplicate_candidates.join(", ")
                : "no duplicate candidate"}
            </span>
            <span>{money(task.cost_usd)} USD</span>
            <span>{seconds(task.wall_seconds)} seconds</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
