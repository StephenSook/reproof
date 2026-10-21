/** How a maintainer names a report: the project and the bug first, the tracker ids second. */
export type ReportNames = {
  project: string;
  osv_record_id: string;
  arvo_id: number;
  report_text: string;
};

/** The report's own first line, for example "Heap-buffer-overflow in decToString". */
export function reportTitle(text: string): string {
  return text.split("\n").find((line) => line.trim())?.trim() ?? "";
}

/** "Heap-buffer-overflow" reads as "heap-buffer-overflow" after a colon; an acronym keeps its case. */
function lowerFirst(text: string): string {
  if (text.length > 1 && /[A-Z]/.test(text[0]!) && /[a-z]/.test(text[1]!)) return text[0]!.toLowerCase() + text.slice(1);
  return text;
}

/** "jq: heap-buffer-overflow in decToString", or the project alone when the report has no text. */
export function reportLabel(task: ReportNames): string {
  const title = reportTitle(task.report_text);
  return title ? `${task.project}: ${lowerFirst(title)}` : task.project;
}

/** "ARVO 42530604, OSV-2023-1239" */
export function reportIds(task: ReportNames): string {
  return `ARVO ${task.arvo_id}, ${task.osv_record_id}`;
}
