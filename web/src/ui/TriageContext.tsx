"use client";

import { createContext, useContext, useMemo, useRef, type ReactNode } from "react";

/** What the door can do for a control outside it, such as the hero's buttons. */
export type TriageHandlers = {
  run: (arvoId: number) => void;
  showRecorded: (arvoId: number) => void;
};

type TriageChannel = TriageHandlers & { register: (handlers: TriageHandlers | null) => void };

const Channel = createContext<TriageChannel | null>(null);

/** Lets the hero start the same triage the door's own buttons start. The door registers itself. */
export function TriageProvider({ children }: { children: ReactNode }) {
  const handlers = useRef<TriageHandlers | null>(null);
  const value = useMemo<TriageChannel>(
    () => ({
      register: (next) => {
        handlers.current = next;
      },
      run: (arvoId) => handlers.current?.run(arvoId),
      showRecorded: (arvoId) => handlers.current?.showRecorded(arvoId),
    }),
    [],
  );
  return <Channel.Provider value={value}>{children}</Channel.Provider>;
}

export function useTriageChannel(): TriageChannel | null {
  return useContext(Channel);
}
