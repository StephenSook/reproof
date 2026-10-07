import type { ReactNode } from "react";

export type Tone = "proof" | "crash" | "dup" | "info" | "slate";

const VERDICT_TONE: Record<string, Tone> = {
  REPRODUCED: "proof",
  DUPLICATE: "dup",
  NOT_REPRODUCED: "slate",
  NEEDS_INFO: "info",
};

const VERDICT_ICON: Record<string, string> = {
  REPRODUCED: "✓",
  DUPLICATE: "=",
  NOT_REPRODUCED: "×",
  NEEDS_INFO: "?",
};

export function verdictTone(verdict: string): Tone {
  return VERDICT_TONE[verdict] ?? "slate";
}

/** A state word in a tilted ink box. The word always carries the meaning; the tone only repeats it. */
export function Stamp({
  children,
  tone,
  icon,
  className = "",
  ...data
}: {
  children: ReactNode;
  tone: Tone;
  icon?: string;
  className?: string;
  [key: `data-${string}`]: string | undefined;
}) {
  return (
    <span className={`stamp tone-${tone} ${className}`.trim()} {...data}>
      {icon ? <span aria-hidden="true">{icon}</span> : null}
      <span>{children}</span>
    </span>
  );
}

export function VerdictStamp({ verdict, className = "" }: { verdict: string; className?: string }) {
  return (
    <Stamp className={className} icon={VERDICT_ICON[verdict] ?? "•"} tone={verdictTone(verdict)}>
      {verdict}
    </Stamp>
  );
}
