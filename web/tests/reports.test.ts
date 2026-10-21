import { describe, expect, it } from "vitest";
import catalog from "../src/content/catalog.json";
import { reportIds, reportLabel, reportTitle } from "../src/lib/reports";

describe("report names", () => {
  it("names every catalog report by project and bug, from the report's own first line", () => {
    for (const task of catalog.tasks) {
      const first = task.report_text.split("\n")[0] ?? "";
      expect(reportTitle(task.report_text)).toBe(first);
      expect(reportLabel(task).toLowerCase()).toBe(`${task.project}: ${first}`.toLowerCase());
      expect(reportLabel(task).startsWith(`${task.project}: `)).toBe(true);
      expect(reportIds(task)).toBe(`ARVO ${task.arvo_id}, ${task.osv_record_id}`);
    }
    const jq = catalog.tasks.find((task) => task.arvo_id === 42530604);
    expect(reportLabel(jq!)).toBe("jq: heap-buffer-overflow in decToString");
  });

  it("keeps an acronym's case and falls back to the project", () => {
    const base = { project: "demo", osv_record_id: "OSV-1", arvo_id: 1 };
    expect(reportLabel({ ...base, report_text: "UAF in parse\n" })).toBe("demo: UAF in parse");
    expect(reportLabel({ ...base, report_text: "\n\n  Stack-buffer-overflow in f  \nmore" })).toBe(
      "demo: stack-buffer-overflow in f",
    );
    expect(reportLabel({ ...base, report_text: "" })).toBe("demo");
  });
});
