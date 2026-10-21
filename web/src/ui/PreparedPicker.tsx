"use client";

import Link from "next/link";
import { useId, useMemo, useState } from "react";
import { displayCrashType } from "@/lib/crashType";
import { groupByProject, matchesQuery, type PreparedTask } from "@/lib/prepared";
import { reportIds, reportLabel, reportTitle } from "@/lib/reports";

/**
 * The reports from the 100-bug run, in a closed disclosure under the featured ten. Their rows are
 * loaded only when the disclosure first opens, so the first paint carries the count and nothing else.
 */
export function PreparedPicker({
  count,
  projects,
  note,
  tasks,
  error,
  selected,
  onOpen,
  onSelect,
}: {
  count: number;
  projects: number;
  /** Why the other drawn tasks are not offered, from the committed list. */
  note: string;
  /** Null until the rows have loaded. */
  tasks: PreparedTask[] | null;
  error: string | null;
  selected: number;
  onOpen: () => void;
  onSelect: (arvoId: number) => void;
}) {
  const [query, setQuery] = useState("");
  const id = useId();
  const shown = useMemo(() => (tasks ?? []).filter((task) => matchesQuery(task, query)), [tasks, query]);
  const groups = useMemo(() => groupByProject(shown), [shown]);
  const status =
    tasks === null
      ? (error ?? "Loading the reports.")
      : shown.length === tasks.length
        ? `All ${tasks.length} reports, ${projects} projects.`
        : shown.length
          ? `${shown.length} of ${tasks.length} reports match.`
          : `No report matches "${query.trim()}".`;
  const chosen = tasks?.find((task) => task.arvo_id === selected) ?? null;

  return (
    <details
      className="disclosure more"
      data-more-reports
      onToggle={(event) => {
        if (event.currentTarget.open) onOpen();
      }}
    >
      <summary>
        <span className="more-heading">
          <span className="disclosure-title">{count} more from the 100-bug run</span>
          <span className="more-gist">{projects} projects. Search by project, bug, crash type or id.</span>
        </span>
        <span aria-hidden="true" className="disclosure-caret" />
      </summary>
      <div className="more-body">
        <label className="more-label" htmlFor={`${id}-search`}>
          Search by project, bug, crash type, OSV id or ARVO id
        </label>
        <input
          autoComplete="off"
          className="more-search"
          disabled={tasks === null}
          id={`${id}-search`}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="libxml2, use-after-free, OSV-2022"
          spellCheck={false}
          type="search"
          value={query}
        />
        <p className="more-count" data-more-count role="status">
          {status}
        </p>
        {chosen ? (
          <p className="more-chosen" data-more-chosen>
            Chosen: {reportLabel(chosen)}. <a href="#work-heading">Go to the report</a>
          </p>
        ) : null}
        {groups.length ? (
          <div className="more-list" data-lenis-prevent>
            {groups.map((group, index) => (
              <div className="more-group" data-project={group.project} key={group.project}>
                <p className="more-project" id={`${id}-group-${index}`}>
                  {group.project} <span className="more-project-count">{group.tasks.length}</span>
                </p>
                <div aria-labelledby={`${id}-group-${index}`} className="picker" role="radiogroup">
                  {group.tasks.map((task) => (
                    <label className="pick" data-task={task.arvo_id} key={task.arvo_id}>
                      <input
                        checked={task.arvo_id === selected}
                        name="arvo-report"
                        onChange={() => onSelect(task.arvo_id)}
                        type="radio"
                        value={task.arvo_id}
                      />
                      <span className="grid min-w-0">
                        <span className="pick-title">{reportTitle(task.report_text) || task.project}</span>
                        <span className="pick-ids">{reportIds(task)}</span>
                        <span className="pick-type">{displayCrashType(task.crash_type)}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : null}
        <p className="more-note">
          {note} <Link href="/proof">Every task of the run</Link>
        </p>
      </div>
    </details>
  );
}
