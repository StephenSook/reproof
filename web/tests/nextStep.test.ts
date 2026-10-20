import { describe, expect, it } from "vitest";
import evaluation from "../src/content/arvo10.json";
import receiptJson from "../src/content/door-42530604.json";
import type { DoorStepEvent } from "../src/lib/events";
import { nextStep } from "../src/lib/nextStep";
import { receiptSummary, type DoorReceipt } from "../src/lib/receipt";
import { liveSummary, recordedSummary } from "../src/lib/summary";

const STATES = [
  "PUBLICLY_KNOWN_FIXED",
  "PUBLICLY_KNOWN_OPEN",
  "RELATED_VARIANTS_ONLY",
  "SOURCE_DISPUTE",
  "NO_PUBLIC_FINDINGS",
  "LOOKUP_UNAVAILABLE",
];

function step(name: string, payload: Record<string, unknown>): DoorStepEvent {
  return { step: name, kind: null, payload };
}

function summaryFor(
  verdict: string,
  publicPayload: Record<string, unknown> | null,
  duplicates: string[] = [],
  missing: string[] = [],
) {
  const steps = [
    step("duplicates", { candidates: duplicates.map((id) => ({ id })) }),
    ...(publicPayload ? [step("public_status", publicPayload)] : []),
    step("verdict", { verdict, missing_details: missing }),
  ];
  return liveSummary(steps, null, { ended: true });
}

const fixedRow = {
  url: "https://example.org/advisory",
  title: "Advisory",
  ancestry: "CONTAINS_FIX",
  upstream_version: "2.0",
  checked_tag: "v2.0",
  checked_commit: "0123456789abcdef0123456789abcdef01234567",
};

describe("next step", () => {
  it("leads the recorded jq response with the release that fixed it", () => {
    const receipt = receiptJson as DoorReceipt;
    const card = receipt.events.at(-1)?.result?.card as {
      project: string;
      public_status: { evidence: { upstream_version: string; checked_tag: string; checked_commit: string }[] };
    };
    const row = card.public_status.evidence[0];
    expect(nextStep(receiptSummary(receipt))).toEqual({
      finding: `Already fixed in ${card.project} ${row?.upstream_version} (tag ${row?.checked_tag} contains ${row?.checked_commit.slice(0, 7)}).`,
      action: "Close it and point the reporter to the release.",
    });
    expect(nextStep(receiptSummary(receipt))?.finding).toBe("Already fixed in jq 1.7.1 (tag jq-1.7.1 contains 71c2ab5).");
  });

  it("takes the project, version, tag and commit from the result, not from one report", () => {
    const summary = summaryFor("REPRODUCED", { state: "PUBLICLY_KNOWN_FIXED", project: "libfoo", evidence: [fixedRow] });
    expect(nextStep(summary)?.finding).toBe("Already fixed in libfoo 2.0 (tag v2.0 contains 0123456).");
    const other = summaryFor("REPRODUCED", {
      state: "PUBLICLY_KNOWN_FIXED",
      project: "libbar",
      evidence: [{ ...fixedRow, upstream_version: "3.1", checked_tag: "release-3.1", checked_commit: "fedcba9876543210" }],
    });
    expect(nextStep(other)?.finding).toBe("Already fixed in libbar 3.1 (tag release-3.1 contains fedcba9).");
  });

  it("gives every reproduced public state its own line", () => {
    const lines = STATES.map((state) => {
      const evidence = state === "NO_PUBLIC_FINDINGS" || state === "LOOKUP_UNAVAILABLE" ? [] : [{ ...fixedRow, ancestry: "NOT_CHECKABLE" }];
      const found = nextStep(summaryFor("REPRODUCED", { state, project: "libfoo", evidence }));
      expect(found?.finding, state).toBeTruthy();
      expect(found?.action, state).toBeTruthy();
      return `${found?.finding} ${found?.action}`;
    });
    expect(new Set(lines).size).toBe(STATES.length);
    expect(nextStep(summaryFor("REPRODUCED", { state: "NO_PUBLIC_FINDINGS", evidence: [] }))).toEqual({
      finding: "Real crash, and no public page matched it.",
      action: "Treat it as a new bug and start a fix.",
    });
    expect(nextStep(summaryFor("REPRODUCED", { state: "LOOKUP_UNAVAILABLE", evidence: [] }))?.finding).toBe(
      "Real crash. The public-status lookup did not read any page.",
    );
  });

  it("names the duplicate ids and keeps a fixed release when there is one", () => {
    const saved = evaluation.tasks.find((task) => task.arvo_id === 42508524);
    expect(saved).toBeDefined();
    expect(nextStep(recordedSummary(saved!))).toEqual({
      finding: "Duplicate of OSV-2022-147.",
      action: "Close it as a duplicate of OSV-2022-147.",
    });
    expect(
      nextStep(summaryFor("DUPLICATE", { state: "PUBLICLY_KNOWN_FIXED", project: "libfoo", evidence: [fixedRow] }, ["OSV-1", "OSV-2", "OSV-3"])),
    ).toEqual({
      finding: "Duplicate of OSV-1, OSV-2, and OSV-3, already fixed in libfoo 2.0 (tag v2.0 contains 0123456).",
      action: "Close it as a duplicate and point the reporter to the release.",
    });
  });

  it("says what to ask for when the crash did not reproduce or a detail is missing", () => {
    expect(nextStep(summaryFor("NOT_REPRODUCED", null))).toEqual({
      finding: "Not reproduced: the vulnerable build ran clean.",
      action: "Ask the reporter for the exact input and build.",
    });
    expect(nextStep(summaryFor("NEEDS_INFO", null, [], ["the affected version"]))).toEqual({
      finding: "Not decided: the run is missing a detail.",
      action: "Read the missing detail below before you reply.",
    });
  });

  it("says when a saved row has no public status, and gives nothing before a verdict", () => {
    const saved = evaluation.tasks.find((task) => task.arvo_id === 42507851);
    expect(nextStep(recordedSummary(saved!))?.finding).toBe("Real crash. This saved row has no public-status lookup.");
    expect(nextStep(liveSummary([], null))).toBeNull();
  });
});
