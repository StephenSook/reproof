"use client";

import { useRef } from "react";
import type { AncestryRibbon as RibbonData } from "@/lib/summary";
import { drawRibbon, useArrival } from "@/ui/motion/motion";

/**
 * The git proof as a picture: the release tag on the left, the OSV fix commit on the right, and the
 * relation between them. Drawn only from the evidence row's tag, commit and ancestry; there are no
 * commits drawn in between, because the ancestry check does not report them.
 */
export function AncestryRibbon({ ribbon }: { ribbon: RibbonData }) {
  const contains = ribbon.ancestry === "CONTAINS_FIX";
  const figureRef = useRef<HTMLElement>(null);
  useArrival(figureRef, `${ribbon.ancestry}:${ribbon.tag}:${ribbon.commit}`, drawRibbon);
  return (
    <figure
      ref={figureRef}
      className={`ribbon ${contains ? "ribbon-contains" : "ribbon-missing"}`}
      data-ribbon={ribbon.ancestry}
    >
      <div className="ribbon-track">
        <span className="ribbon-end ribbon-tag">
          <span className="ribbon-kicker">release tag</span>
          <code>{ribbon.tag}</code>
        </span>
        <span className="ribbon-link">
          <span aria-hidden="true" className="ribbon-line" />
          <span className="ribbon-word">
            <span aria-hidden="true">{contains ? "✓" : "✕"}</span> {contains ? "contains" : "does not contain"}
          </span>
        </span>
        <span className="ribbon-end ribbon-commit" title={ribbon.commit}>
          <span className="ribbon-kicker">OSV fix commit</span>
          <code>{ribbon.shortCommit}</code>
        </span>
      </div>
      <figcaption>Git ancestry from the GitHub compare of this tag and this commit.</figcaption>
    </figure>
  );
}
