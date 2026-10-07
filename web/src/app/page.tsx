import evaluation from "@/content/arvo10.json";
import catalog from "@/content/catalog.json";
import limits from "@/content/limits.json";
import { limitsSentence } from "@/lib/measured";
import { Door } from "@/ui/Door";
import { Mark } from "@/ui/Mark";
import { Measured } from "@/ui/Measured";
import { SquashButton } from "@/ui/SquashButton";
import { VerdictStamp } from "@/ui/Stamp";

const REPO_URL = "https://github.com/StephenSook/reproof";

const LEGEND = [
  {
    verdict: "REPRODUCED",
    text: "The vulnerable build produced a measured sanitizer crash and the fixed build was clean.",
  },
  { verdict: "DUPLICATE", text: "The measured crash state matched one or more public OSV records." },
  { verdict: "NOT_REPRODUCED", text: "The vulnerable build completed cleanly without a sanitizer crash." },
  { verdict: "NEEDS_INFO", text: "The run cannot support another verdict. The card says what is missing." },
];

export default function Page() {
  const count = catalog.tasks.length;
  return (
    <div className="page">
      <a className="skip-link" href="#reports">
        Skip to reports
      </a>
      <header className="site-head">
        <a aria-label="Reproof, top of page" className="brand-pill" href="#top">
          <Mark size={34} />
          <span className="display">Reproof</span>
        </a>
        <nav aria-label="Page sections">
          <ul className="nav-pills">
            <li>
              <a className="nav-pill" href="#reports">
                Reports
              </a>
            </li>
            <li>
              <a className="nav-pill" href="#measured">
                Measured
              </a>
            </li>
            <li>
              <a className="nav-pill" href={REPO_URL}>
                Code
              </a>
            </li>
          </ul>
        </nav>
      </header>
      <main className="grid min-w-0 gap-3" id="top">
        <section aria-labelledby="hero-title" className="section-card tone-ink-section">
          <div className="hero-grid">
            <div className="min-w-0">
              <p className="hand hero-note">No login. No key.</p>
              <h1 className="hero-title" id="hero-title">
                Reproof
              </h1>
              <p className="hero-tagline">Is this crash real, already reported, or already fixed?</p>
              <p className="hero-lede">
                Reproof reads a public security report and runs its input against the vulnerable and the fixed
                build in disposable sandboxes. It searches OSV for the same crash and checks public pages. When a
                page names a fixed version, it checks that the release&apos;s git tag contains the fix commit. A
                person makes the decision. Reproof files nothing upstream.
              </p>
              <div className="hero-actions">
                <SquashButton href="#reports" onInk>
                  Pick a report
                </SquashButton>
                <SquashButton href="#measured" icon={"↓"} onInk variant="secondary">
                  See the saved evaluation
                </SquashButton>
              </div>
            </div>
            <aside aria-labelledby="legend-title" className="legend-card">
              <h2 id="legend-title">What a verdict says</h2>
              <ul className="legend-list">
                {LEGEND.map((row) => (
                  <li key={row.verdict}>
                    <VerdictStamp className="stamp-small" verdict={row.verdict} />
                    <p>{row.text}</p>
                  </li>
                ))}
              </ul>
              <p className="legend-foot">Public status is a separate line. It does not change the verdict.</p>
            </aside>
          </div>
        </section>
        <section aria-labelledby="door-title" className="section-card tone-sky-section">
          <div className="section-heading door-intro">
            <p className="hand">pick one, then run it</p>
            <h2 id="door-title">{count} public reports</h2>
            <p className="section-lede">
              Pick one of the {count} public ARVO reports. Triage runs the claim, both builds, the crash parse, the
              duplicate search, and a public-status lookup.
            </p>
            <p className="limits-note" data-limits>
              {limitsSentence(limits)}
            </p>
          </div>
          <Door recordedTasks={evaluation.tasks} tasks={catalog.tasks} />
        </section>
        <Measured evaluation={evaluation} />
      </main>
      <footer className="site-foot">
        <p>
          Reproof is open source under Apache-2.0.{" "}
          <a href={REPO_URL}>Source on GitHub</a>
        </p>
        <p>
          Fonts are Bricolage Grotesque, Figtree, and Caveat, used under the SIL Open Font License.{" "}
          <a href="/fonts-LICENSE.txt">Font license</a>
        </p>
      </footer>
    </div>
  );
}
