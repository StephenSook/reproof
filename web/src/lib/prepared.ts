import { displayCrashType } from "@/lib/crashType";
import type { RecordedTask } from "@/lib/recorded";
import { reportTitle } from "@/lib/reports";

/**
 * A report from the 100-bug run that the door also offers: a committed card shows it ran from the
 * ConTree checkpoint pair the door names and crashed on the vulnerable build. The rows come from
 * reproof/assets/prepared_catalog.json, copied byte for byte to web/src/content/prepared-catalog.json.
 */
export type PreparedTask = {
  arvo_id: number;
  project: string;
  osv_record_id: string;
  report_source: string;
  report_text: string;
  /** The crash type the OSV report states, not the measured one. */
  crash_type: string;
  recorded_in: string;
  recorded_run: string;
  recorded: RecordedTask & { project: string; card_path: string };
};

export type NotOffered = { arvo_id: number; project: string; reason: string; detail: string };

export type PreparedCatalog = { tasks: PreparedTask[]; not_offered: NotOffered[] };

export type ProjectGroup = { project: string; tasks: PreparedTask[] };

function haystack(task: PreparedTask): string {
  return [
    task.project,
    reportTitle(task.report_text),
    task.osv_record_id,
    `arvo ${task.arvo_id}`,
    task.crash_type,
    displayCrashType(task.crash_type),
  ]
    .join(" ")
    .toLowerCase();
}

/** Every word of the query must appear somewhere in the report's names, ids or crash type. */
export function matchesQuery(task: PreparedTask, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const text = haystack(task);
  return words.every((word) => text.includes(word));
}

/** Projects in alphabetical order, each project's reports by ARVO id. */
export function groupByProject(tasks: PreparedTask[]): ProjectGroup[] {
  const groups = new Map<string, PreparedTask[]>();
  for (const task of tasks) groups.set(task.project, [...(groups.get(task.project) ?? []), task]);
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([project, rows]) => ({ project, tasks: [...rows].sort((a, b) => a.arvo_id - b.arvo_id) }));
}

export function projectCount(tasks: PreparedTask[]): number {
  return new Set(tasks.map((task) => task.project)).size;
}

const REASON_TEXT: Record<string, (count: number) => string> = {
  no_checkpoint_pair: (count) => `${count} never got both sandbox checkpoints`,
  no_crash_measured: (count) => `${count} ran but measured no crash on either build`,
  never_completed: (count) => `${count} ${count === 1 ? "has" : "have"} both checkpoints but no run that finished`,
};

/** One sentence saying how many of the 90 drawn tasks are not offered, and why, from the committed list. */
export function notOfferedSentence(rows: NotOffered[]): string {
  if (!rows.length) return "Every drawn task is offered.";
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.reason, (counts.get(row.reason) ?? 0) + 1);
  const parts = [...counts.entries()]
    .sort(([, a], [, b]) => b - a)
    .map(([reason, count]) => (REASON_TEXT[reason] ?? ((n: number) => `${n}: ${reason}`))(count));
  const list = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}` : parts[0];
  return `${rows.length} other drawn tasks are not offered: ${list}.`;
}
