export type DoorStepEvent = {
  step: string;
  kind?: string | null;
  payload: Record<string, unknown>;
};

export type DoorEvent = {
  type: string;
  step?: DoorStepEvent;
  result?: Record<string, unknown>;
};

export const REQUIRED_STEP_KEYS = [
  "claim",
  "sandbox:vul",
  "sandbox:fix",
  "crash",
  "duplicates",
  "verdict",
  "result",
] as const;

export function takeLines(buffer: string): { lines: string[]; rest: string } {
  const parts = buffer.split("\n");
  const rest = parts.pop() ?? "";
  return { lines: parts.filter((line) => line.length > 0), rest };
}

export function parseNdjson(text: string): unknown[] {
  const finished = text.endsWith("\n") ? text : `${text}\n`;
  const { lines } = takeLines(finished);
  return lines.map((line) => JSON.parse(line) as unknown);
}

export function stepKey(step: DoorStepEvent): string {
  return step.step === "sandbox" ? `sandbox:${step.kind ?? ""}` : step.step;
}

export function missingSteps(events: DoorEvent[]): string[] {
  const have = new Set<string>();
  for (const event of events) {
    if (event.type === "result") have.add("result");
    if (event.type === "step" && event.step) have.add(stepKey(event.step));
  }
  return REQUIRED_STEP_KEYS.filter((key) => !have.has(key));
}

export function isLimitPayload(status: number, body: unknown): boolean {
  if (status !== 429 || body === null || typeof body !== "object") return false;
  const record = body as {
    error?: unknown;
    limits?: { per_ip_per_hour?: unknown };
  };
  return (
    typeof record.error === "string" &&
    !("verdict" in record) &&
    typeof record.limits?.per_ip_per_hour === "number"
  );
}
