import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import type { ReactNode } from "react";
import { SmoothScroll } from "@/ui/motion/SmoothScroll";
import "lenis/dist/lenis.css";
import "./globals.css";

const display = localFont({
  src: "./fonts/bricolage-grotesque-latin.woff2",
  variable: "--font-display",
  weight: "700 800",
  display: "swap",
});

const body = localFont({
  src: "./fonts/figtree-latin.woff2",
  variable: "--font-body",
  weight: "500 800",
  display: "swap",
});

const hand = localFont({
  src: "./fonts/caveat-latin.woff2",
  variable: "--font-hand",
  weight: "500 700",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Reproof judge door",
  description: "Triage one of 10 public ARVO reports. No login and no key.",
};

export const viewport: Viewport = {
  themeColor: "#f3f1ea",
  colorScheme: "light",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html className={`${display.variable} ${body.variable} ${hand.variable}`} lang="en">
      <body>
        <SmoothScroll />
        {children}
      </body>
    </html>
  );
}
