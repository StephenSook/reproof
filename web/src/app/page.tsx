import evaluation from "@/content/arvo10.json";
import catalog from "@/content/catalog.json";
import limits from "@/content/limits.json";
import { limitsSentence } from "@/lib/measured";
import { Door } from "@/ui/Door";
import { Mark } from "@/ui/Mark";
import { Measured } from "@/ui/Measured";

export default function Page() {
  return (
    <main className="mx-auto min-w-0 max-w-6xl px-4 py-8">
      <a
        className="absolute left-4 top-4 -translate-y-24 bg-[var(--card)] px-3 py-2 focus:translate-y-0"
        href="#reports"
      >
        Skip to reports
      </a>
      <header className="flex min-w-0 items-center gap-3">
        <Mark />
        <div>
          <p className="text-sm text-[var(--muted)]">No login. No key.</p>
          <h1 className="text-5xl sm:text-6xl">Reproof</h1>
        </div>
      </header>
      <p className="mt-4 max-w-3xl">
        Pick one of the 10 public ARVO reports. Triage runs the claim, both builds, the crash parse,
        the duplicate search, and a public-status lookup.
      </p>
      <p className="mt-3 max-w-3xl border border-[var(--line)] bg-[var(--card)] p-3" data-limits>
        {limitsSentence(limits)}
      </p>
      <Door recordedTasks={evaluation.tasks} tasks={catalog.tasks} />
      <Measured evaluation={evaluation} />
      <footer className="mt-10 text-sm text-[var(--muted)]">
        Fonts are Bricolage Grotesque, Figtree, and Caveat, used under the SIL Open Font License.{" "}
        <a className="underline" href="/fonts-LICENSE.txt">
          Font license
        </a>
      </footer>
    </main>
  );
}
