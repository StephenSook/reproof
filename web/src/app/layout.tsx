import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import type { ReactNode } from "react";
import { SmoothScroll } from "@/ui/motion/SmoothScroll";
import "lenis/dist/lenis.css";
import "./globals.css";

// Recursive, one variable family: its MONO axis sets machine values, its sans sets prose.
const recursive = localFont({
  src: "./fonts/recursive-latin.woff2",
  variable: "--font-recursive",
  weight: "300 1000",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Reproof judge door",
  description: "Triage one of 10 public ARVO reports. No login and no key.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#e8edea" },
    { media: "(prefers-color-scheme: dark)", color: "#11171a" },
  ],
  colorScheme: "light dark",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html className={recursive.variable} lang="en">
      <body>
        <SmoothScroll />
        {children}
      </body>
    </html>
  );
}
