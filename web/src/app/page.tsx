import Link from "next/link";
import evaluation from "@/content/arvo10.json";
import catalog from "@/content/catalog.json";
import jqReceipt from "@/content/door-42530604.json";
import limits from "@/content/limits.json";
import preparedCatalog from "@/content/prepared-catalog.json";
import { limitsSentence } from "@/lib/measured";
import { notOfferedSentence, projectCount, type PreparedCatalog } from "@/lib/prepared";
import { receiptArvoId, type DoorReceipt } from "@/lib/receipt";
import { Door, type PreparedSummary } from "@/ui/Door";
import { HeroAnswer } from "@/ui/HeroAnswer";
import { Mark } from "@/ui/Mark";
import { Measured } from "@/ui/Measured";
import { TriageProvider } from "@/ui/TriageContext";

const REPO_URL = "https://github.com/StephenSook/reproof";
// The recorded live response for ARVO 42530604 (eval/results/door-42530604.json).
const HERO_RECEIPT = jqReceipt as DoorReceipt;
const RECEIPTS: DoorReceipt[] = [HERO_RECEIPT];
// The rows stay on the server: the client gets these counts, and loads the rows when the list opens.
const PREPARED = preparedCatalog as unknown as PreparedCatalog;
const PREPARED_SUMMARY: PreparedSummary = {
  count: PREPARED.tasks.length,
  projects: projectCount(PREPARED.tasks),
  note: notOfferedSentence(PREPARED.not_offered),
};

export default function Page() {
  const count = catalog.tasks.length;
  const total = count + PREPARED_SUMMARY.count;
  const heroTask = catalog.tasks.find((task) => task.arvo_id === receiptArvoId(HERO_RECEIPT));
  return (
    <div className="page">
      <a className="skip-link" href="#reports">
        Skip to reports
      </a>
      <header className="site-head">
        <a aria-label="Reproof, top of page" className="brand" href="#top">
          <Mark size={34} />
          <span className="brand-name">Reproof</span>
        </a>
        <nav aria-label="Page sections">
          <ul className="nav-links">
            <li>
              <a className="nav-link" href="#reports">
                Reports
              </a>
            </li>
            <li>
              <a className="nav-link" href="#measured">
                Measured
              </a>
            </li>
            <li>
              <Link className="nav-link" href="/proof">
                100 bugs
              </Link>
            </li>
            <li>
              <a className="nav-link" href={REPO_URL}>
                Code
              </a>
            </li>
          </ul>
        </nav>
      </header>
      <TriageProvider>
      <main className="grid min-w-0 gap-3" id="top">
        <section aria-labelledby="hero-title" className="section section-lead">
          <div className="hero-grid">
            <div className="min-w-0">
              <h1 className="hero-title" id="hero-title">
                Is this crash real, already reported, or already fixed?
              </h1>
              <p className="hero-lede">
                Reproof runs a report&apos;s input against the vulnerable and the fixed build, searches OSV and public
                pages for the same crash, and checks git ancestry before it says a release has the fix. A person makes
                the decision. Reproof files nothing upstream.
              </p>
              <p className="hero-more">
                No login and no key. <a href="#reports">Pick one of the {total} reports</a> or{" "}
                <a href="#measured">read the saved evaluation</a>.
              </p>
            </div>
            {heroTask ? <HeroAnswer receipt={HERO_RECEIPT} task={heroTask} /> : null}
          </div>
        </section>
        <section aria-labelledby="door-title" className="section">
          <div className="section-heading door-intro">
            <h2 id="door-title">{total} public reports</h2>
            <p className="section-lede">
              Pick one of the {count} featured ARVO reports, or open the {PREPARED_SUMMARY.count} more from the 100-bug
              run and search them. Each has already run from its
              sandbox checkpoints in a recorded evaluation. Triage runs the claim, both builds,
              the crash parse, the duplicate search, and a public-status lookup.
            </p>
          </div>
          <Door
            limitsNote={limitsSentence(limits)}
            prepared={PREPARED_SUMMARY}
            receipts={RECEIPTS}
            recordedTasks={evaluation.tasks}
            tasks={catalog.tasks}
          />
        </section>
        <Measured evaluation={evaluation} />
      </main>
      </TriageProvider>
      <footer className="site-foot">
        <p>
          Reproof is open source under Apache-2.0.{" "}
          <a href={REPO_URL}>Source on GitHub</a>
        </p>
        <p>
          The typeface is Recursive, used under the SIL Open Font License.{" "}
          <a href="/fonts-LICENSE.txt">Font license</a>
        </p>
      </footer>
    </div>
  );
}
