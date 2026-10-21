import { describe, expect, it } from "vitest";
import catalog from "../src/content/catalog.json";
import preparedData from "../src/content/prepared-catalog.json";
import {
  groupByProject,
  matchesQuery,
  notOfferedSentence,
  projectCount,
  type PreparedCatalog,
  type PreparedTask,
} from "../src/lib/prepared";
import { recordedView } from "../src/lib/recorded";

const prepared = preparedData as unknown as PreparedCatalog;

function task(overrides: Partial<PreparedTask>): PreparedTask {
  const base = prepared.tasks[0]!;
  return { ...base, ...overrides };
}

describe("the 100-bug run's reports", () => {
  it("offers only reports whose recorded run crashed, none of them featured", () => {
    expect(prepared.tasks.length).toBeGreaterThanOrEqual(53);
    const featured = new Set(catalog.tasks.map((row) => row.arvo_id));
    for (const row of prepared.tasks) {
      expect(featured.has(row.arvo_id), String(row.arvo_id)).toBe(false);
      expect(["REPRODUCED", "DUPLICATE"]).toContain(row.recorded.verdict);
      expect(row.recorded.arvo_id).toBe(row.arvo_id);
      // Show recorded result builds its view from this row, so every row must carry both branches.
      const view = recordedView(row.recorded);
      expect(view.verdict).toBe(row.recorded.verdict);
      expect(row.crash_type).not.toBe("");
    }
  });

  it("matches every word against project, bug, crash type, OSV id and ARVO id", () => {
    const row = task({
      project: "libxml2",
      arvo_id: 42486565,
      osv_record_id: "OSV-2021-1234",
      crash_type: "Heap-use-after-free READ {*}",
      report_text: "Heap-use-after-free in xmlXPathNextAncestor\n\nmore",
    });
    expect(matchesQuery(row, "")).toBe(true);
    expect(matchesQuery(row, "   ")).toBe(true);
    expect(matchesQuery(row, "LIBXML2")).toBe(true);
    expect(matchesQuery(row, "xmlxpath")).toBe(true);
    expect(matchesQuery(row, "osv-2021")).toBe(true);
    expect(matchesQuery(row, "42486565")).toBe(true);
    expect(matchesQuery(row, "arvo 4248")).toBe(true);
    expect(matchesQuery(row, "use-after-free read")).toBe(true);
    expect(matchesQuery(row, "any size")).toBe(true);
    expect(matchesQuery(row, "libxml2 overflow")).toBe(false);
    expect(matchesQuery(row, "gpac")).toBe(false);
  });

  it("groups by project in alphabetical order and keeps every report", () => {
    const groups = groupByProject(prepared.tasks);
    const names = groups.map((group) => group.project);
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
    expect(groups.length).toBe(projectCount(prepared.tasks));
    expect(groups.flatMap((group) => group.tasks.map((row) => row.arvo_id)).sort()).toEqual(
      prepared.tasks.map((row) => row.arvo_id).sort(),
    );
    for (const group of groups) {
      const ids = group.tasks.map((row) => row.arvo_id);
      expect(ids).toEqual([...ids].sort((a, b) => a - b));
      expect(group.tasks.every((row) => row.project === group.project)).toBe(true);
    }
  });

  it("says why the other drawn tasks are not offered, counted from the committed list", () => {
    const sentence = notOfferedSentence(prepared.not_offered);
    const count = (reason: string) => prepared.not_offered.filter((row) => row.reason === reason).length;
    expect(sentence).toBe(
      `${prepared.not_offered.length} other drawn tasks are not offered: ` +
        `${count("no_checkpoint_pair")} never got both sandbox checkpoints, ` +
        `${count("no_crash_measured")} ran but measured no crash on either build and ` +
        `${count("never_completed")} has both checkpoints but no run that finished.`,
    );
    expect(prepared.tasks.length + prepared.not_offered.length).toBe(90);
    expect(notOfferedSentence([])).toBe("Every drawn task is offered.");
    expect(
      notOfferedSentence([
        { arvo_id: 1, project: "p", reason: "never_completed", detail: "" },
        { arvo_id: 2, project: "p", reason: "never_completed", detail: "" },
      ]),
    ).toBe("2 other drawn tasks are not offered: 2 have both checkpoints but no run that finished.");
  });
});
