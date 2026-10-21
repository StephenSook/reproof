"use client";

import { gsap } from "gsap";
import type Lenis from "lenis";
import { useEffect, type RefObject } from "react";

/**
 * Motion for the door. Only arrivals move: a verdict stamp presses in, a build state settles, and the
 * ancestry ribbon draws from the tag to the commit. Nothing tilts and nothing animates opacity, so a frame
 * caught mid-motion still has full contrast. Under prefers-reduced-motion nothing moves.
 */

let lenis: Lenis | null = null;

export function setLenis(instance: Lenis | null) {
  lenis = instance;
}

export function reducedMotion(): boolean {
  return typeof window === "undefined" || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Scroll an element to the top of the view, through Lenis when it is running. The target is computed from
 * window.scrollY, which is always current: a native scroll in the same frame (a keyboard press, or a test
 * driver scrolling a button into view) has not reached Lenis yet, and Lenis would aim from a stale position.
 * The content has just grown, so Lenis re-measures before it clamps the target.
 */
export function scrollToElement(element: HTMLElement) {
  if (lenis && !reducedMotion()) {
    lenis.resize();
    const top = Math.max(0, element.getBoundingClientRect().top + window.scrollY - 16);
    lenis.scrollTo(top, { duration: 0.9 });
    return;
  }
  element.scrollIntoView({ block: "start", behavior: "auto" });
}

type Animate = (element: HTMLElement) => void;

/** Run an entrance each time `key` changes to a non-empty value. */
export function useArrival(ref: RefObject<HTMLElement | null>, key: string | null, animate: Animate) {
  useEffect(() => {
    const element = ref.current;
    if (!element || !key || reducedMotion()) return;
    const context = gsap.context(() => animate(element), element);
    return () => context.revert();
  }, [ref, key, animate]);
}

export const plop: Animate = (element) => {
  gsap.fromTo(
    element,
    { scale: 1.12 },
    { scale: 1, duration: 0.45, ease: "power3.out", clearProps: "transform" },
  );
};

export const settle: Animate = (element) => {
  gsap.fromTo(element, { y: 6 }, { y: 0, duration: 0.4, ease: "power2.out", clearProps: "transform" });
};

export const drawRibbon: Animate = (element) => {
  const vertical = window.matchMedia("(max-width: 480px)").matches;
  const timeline = gsap.timeline();
  timeline.fromTo(
    element.querySelector(".ribbon-line"),
    vertical ? { scaleY: 0 } : { scaleX: 0 },
    { ...(vertical ? { scaleY: 1 } : { scaleX: 1 }), duration: 0.6, ease: "power2.out", clearProps: "transform" },
  );
  timeline.fromTo(
    element.querySelector(".ribbon-word"),
    { scale: 0.8 },
    { scale: 1, duration: 0.3, ease: "power2.out", clearProps: "transform" },
    "-=0.15",
  );
  timeline.fromTo(
    element.querySelector(".ribbon-commit"),
    { x: -8 },
    { x: 0, duration: 0.35, ease: "power2.out", clearProps: "transform" },
    "-=0.2",
  );
};
