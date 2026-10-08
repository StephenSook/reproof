"use client";

import { gsap } from "gsap";
import Lenis from "lenis";
import { useEffect } from "react";
import { reducedMotion, setLenis } from "@/ui/motion/motion";

/**
 * Lenis smooth scroll on GSAP's ticker, calmer than the reference (lerp 0.14). It smooths the wheel only;
 * touch, keyboard and anchor jumps stay native, so the skip link and focus order behave as usual.
 */
export function SmoothScroll() {
  useEffect(() => {
    if (reducedMotion()) return;
    const lenis = new Lenis({ lerp: 0.14, wheelMultiplier: 0.9, smoothWheel: true, anchors: false });
    const tick = (time: number) => lenis.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);
    setLenis(lenis);
    return () => {
      gsap.ticker.remove(tick);
      setLenis(null);
      lenis.destroy();
    };
  }, []);
  return null;
}
