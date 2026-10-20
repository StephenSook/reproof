import type { DoorSummary, FixedIn } from "@/lib/summary";

/**
 * The maintainer's next step for a finished result: what the run found, in one clause, and what to
 * do about it. Built only from the summary's verdict, public status, fix row, duplicate ids and
 * missing details, so a different result gives a different line. A result with no verdict yet has
 * no next step.
 */
export type NextStep = { finding: string; action: string };

function fixedClause(fixed: FixedIn): string {
  return `${fixed.project} ${fixed.version} (tag ${fixed.tag} contains ${fixed.shortCommit})`;
}

function listIds(ids: string[]): string {
  if (ids.length <= 2) return ids.join(" and ");
  return `${ids.slice(0, -1).join(", ")}, and ${ids.at(-1)}`;
}

function reproducedStep(summary: DoorSummary): NextStep {
  const status = summary.publicStatus;
  if (status.kind === "NOT_RECORDED") {
    return {
      finding: "Real crash. This saved row has no public-status lookup.",
      action: "Run Triage to check public status before you reply.",
    };
  }
  if (status.kind !== "STATUS") {
    return {
      finding: "Real crash. This result has no public-status step.",
      action: "Search for it in public before you reply.",
    };
  }
  if (status.fixedIn) {
    return {
      finding: `Already fixed in ${fixedClause(status.fixedIn)}.`,
      action: "Close it and point the reporter to the release.",
    };
  }
  switch (status.state) {
    case "PUBLICLY_KNOWN_FIXED":
      return {
        finding: "Real crash, and a public page says it is fixed.",
        action: "Check that page's version before you close it.",
      };
    case "PUBLICLY_KNOWN_OPEN":
      return {
        finding: "Real crash, already public, with no fix confirmed.",
        action: "Link the report to the public page and keep it open.",
      };
    case "RELATED_VARIANTS_ONLY":
      return {
        finding: "Real crash. Public pages describe related crashes, not this fix.",
        action: "Treat it as a new bug and compare it with the linked page.",
      };
    case "SOURCE_DISPUTE":
      return {
        finding: "Real crash, and public sources disagree about it.",
        action: "Read the linked page before you reply.",
      };
    case "NO_PUBLIC_FINDINGS":
      return {
        finding: "Real crash, and no public page matched it.",
        action: "Treat it as a new bug and start a fix.",
      };
    case "LOOKUP_UNAVAILABLE":
      return {
        finding: "Real crash. The public-status lookup did not read any page.",
        action: "Search for it in public before you reply.",
      };
    default:
      return {
        finding: `Real crash. Public status: ${status.state}.`,
        action: "Read the public-status evidence before you reply.",
      };
  }
}

export function nextStep(summary: DoorSummary): NextStep | null {
  const verdict = summary.verdict;
  if (!verdict) return null;
  const status = summary.publicStatus;
  const fixed = status.kind === "STATUS" ? status.fixedIn : null;
  if (verdict === "REPRODUCED") return reproducedStep(summary);
  if (verdict === "DUPLICATE") {
    const ids = summary.duplicateIds;
    const of = ids.length ? `Duplicate of ${listIds(ids)}` : "Duplicate of an earlier OSV report";
    if (fixed) {
      return {
        finding: `${of}, already fixed in ${fixedClause(fixed)}.`,
        action: "Close it as a duplicate and point the reporter to the release.",
      };
    }
    return {
      finding: `${of}.`,
      action: ids.length ? `Close it as a duplicate of ${ids[0]}.` : "Close it as a duplicate.",
    };
  }
  if (verdict === "NOT_REPRODUCED") {
    return {
      finding: "Not reproduced: the vulnerable build ran clean.",
      action: "Ask the reporter for the exact input and build.",
    };
  }
  if (verdict === "NEEDS_INFO") {
    return {
      finding: "Not decided: the run is missing a detail.",
      action: summary.details.length
        ? "Read the missing detail below before you reply."
        : "Read the evidence below before you reply.",
    };
  }
  return { finding: `The service returned ${verdict}.`, action: "Read the evidence below before you reply." };
}
