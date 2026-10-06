# Reproof

Reproof is an open-source triage tool for maintainers receiving security reports. It reads a
report, reproduces the supplied input against vulnerable and fixed builds in Nebius Token Factory
Sandboxes through ConTree, and writes a JSON triage card. A human makes the decision. Reproof does
not file reports or change upstream projects.

Phase 1 supports public ARVO tasks and public OSS-Fuzz OSV records. The evaluation uses no personal
data and no private reports.

## Verdicts

- `REPRODUCED`: the vulnerable build produced a measured sanitizer crash and the fixed build was
  clean.
- `NOT_REPRODUCED`: the vulnerable build completed cleanly without a sanitizer crash. The card
  lists every input tried.
- `DUPLICATE`: the measured crash state matched one or more public OSV records. The card returns
  every exact or inline-tolerant match, with every fixed commit recorded by OSV.
- `NEEDS_INFO`: the run cannot support one of the other verdicts. The card states the missing or
  conflicting detail.

## Method

1. `reproof.arvo` reads task metadata from ARVO's public SQLite table. The database stays local and
   is excluded from Git.
2. `reproof.slice` uses `docker create` and `docker cp` on a stopped container. It never runs the
   source container. It copies the ARVO wrapper, PoC, fuzz target, LLVM symbolizer, loader, and
   recursively resolved glibc dependencies. It patches `PT_INTERP` to `/arvo/ld.so`, records the
   original and patched SHA-256 and size for every file, writes a manifest, removes the task image
   tag, and verifies that the tag is absent. A cached slice is accepted only when every file still
   matches its recorded patched hash and size.
3. `reproof.sandbox` uploads the slice into a named ConTree checkpoint based on
   `python:3.12-slim`. It caches checkpoint UUIDs locally and runs vulnerable and fixed branches in
   parallel with `disposable=True`. Cached checkpoint records keep the checkpoint creation cost
   and operation UUID.
4. `reproof.crash` parses sanitizer output with `clusterfuzz==2.6.0`.
5. `reproof.dup` checks same-project records in the public OSS-Fuzz OSV archive after excluding
   every record mapped to the task's own OSS-Fuzz issue. Matching is exact first, then tolerant of
   inline sibling frames at the same program counter.
6. `reproof.claims` asks `nvidia/nemotron-3-super-120b-a12b` for the strict report claim, with
   temperature 0 and thinking disabled. Deterministic code compares the claimed bug class and
   functions with the measured crash.
7. `reproof.triage` writes the verdict, sanitizer excerpt, crash type and state, fixed result,
   excluded OSV IDs, duplicate candidates, claim comparison, model calls, sandbox operations,
   slice hashes, cost, and wall time. A conclusive verdict requires a clean fixed build.

### Why runtime slices are used

Full OCI import of the ARVO images fails today on two ConTree behaviors. Phase 1 uses the verified
runtime-slice path instead.

1. Importing some symlinks raises
   `NotImplementedError: chmod: follow_symlinks unavailable on this platform`. Captured ConTree
   operation or request IDs:
   `01a10cea-f810-744e-bb11-236d7fc1df9b`,
   `01a10cf2-45f5-739b-8ad2-a3632e3ab07a`,
   `01a10cf2-e1b0-76d8-bc02-7b1cf97d7d8e`,
   `01a10cf4-05ce-7485-ad75-40d98c724326`, and
   `01a10d02-6fc1-76bb-aedf-33a9a9777e68`.
2. A wasm3 OCI import returned success but did not preserve the merged-usr loader symlink, so
   `/bin/bash` could not execute. Import operation IDs:
   `01a10cf4-05de-7021-90d9-4a72f1450b3e` and
   `01a10d02-6fa3-723e-b1be-177694820fc3`. Execution operation IDs:
   `01a10cf6-62c4-7431-9729-eba088ed909d` and
   `01a10d04-d34e-71e0-af06-d43bb65c90dc`.

The runtime slice is not presented as a full OCI import.

## Install and run

Requirements are Python 3.12, uv, Docker, `NEBIUS_API_KEY`, and `NEBIUS_PROJECT_ID`.

```powershell
uv sync --locked --dev
uv run reproof triage --arvo 42530604
uv run reproof triage --arvo 42530604 --report .\report.txt
uv run reproof eval --n 10
```

For a task without a cached slice, place local images named
`n132/arvo:<id>-vul` and `n132/arvo:<id>-fix` in Docker before `triage`. The eval command pulls its
selected images. Each task image tag is removed after its slice and manifest are written.

An interrupted eval can reuse strict cards that were already written:

```powershell
uv run reproof eval --n 10 --resume
```

Local caches, runtime slices, databases, zip archives, card details, and credentials are excluded
from Git. The aggregate eval result is tracked at `eval/results/arvo10.json`. It includes the model
request IDs, ConTree checkpoint and run operation UUIDs, crash evidence, token counts, costs, slice
manifest hashes, and source-data hashes needed to audit the aggregate. Provenance records the
immutable source hash that executed paid work separately from the source hash that later derived
or refreshed saved evidence.

## ARVO 10 evaluation

Selection always includes 42530604, 42507851, and 42496387. The remaining tasks are the smallest
by `max(vulnerable GB, fixed GB)` among the spike's frozen 2026-10-05 memory-safety candidate table
that have a mapped public OSV record. Ties use ARVO ID. Each report is the mapped public OSS-Fuzz
OSV summary plus details, not a private report.

| ARVO | Project | Verdict | OSV state agrees | Fixed clean | OSV candidates | Claim agrees | Cost USD | Seconds |
|---:|---|---|---|---|---|---|---:|---:|
| 42530604 | jq | REPRODUCED | yes | yes | none | yes | 0.00089983 | 4.728560 |
| 42507851 | libplist | REPRODUCED | yes | yes | none | yes | 0.00085585 | 3.681775 |
| 42496387 | wasm3 | REPRODUCED | no | yes | none | yes | 0.00088013 | 3.801278 |
| 42508524 | libplist | DUPLICATE | yes | yes | OSV-2022-147 | yes | 0.00082598 | 3.790634 |
| 42536108 | miniz | REPRODUCED | yes | yes | none | yes | 0.00091249 | 3.865316 |
| 42536112 | miniz | REPRODUCED | yes | yes | none | yes | 0.00091473 | 4.976644 |
| 42508390 | libplist | DUPLICATE | no | yes | OSV-2022-93 | yes | 0.00086489 | 4.181501 |
| 42531297 | jq | DUPLICATE | yes | yes | OSV-2025-363 | yes | 0.00107367 | 4.021922 |
| 42531223 | jq | REPRODUCED | no | yes | none | yes | 0.00106409 | 3.637580 |
| 42476752 | libspng | DUPLICATE | yes | yes | OSV-2020-307 | yes | 0.00087638 | 4.023811 |

On 2026-10-05, review of the saved cards found that the phase 1 table counted four self-matches;
the duplicate search now excludes every OSV record mapped to the task's own OSS-Fuzz issue.

Measured totals:

- 10 of 10 tasks completed.
- 6 tasks were `REPRODUCED` and 4 were `DUPLICATE`.
- 7 of 10 measured crash states agreed exactly or inline-tolerantly with a mapped OSV state.
- 10 of 10 fixed builds were clean.
- 10 of 10 claim comparisons agreed on both bug class and top crash function.
- 4 duplicate candidates were returned.
- Nemotron used 1,349 input tokens and 1,125 output tokens. At the published price of $0.30 per
  million input tokens and $0.90 per million output tokens, model cost was $0.00141720.
- ConTree checkpoint and sandbox-run cost was $0.00775084.
- Combined eval cost was $0.00916804.
- Summed per-task wall time was 40.709021 seconds.

The three OSV state disagreements remain visible in the result. They are not converted into
successes. An earlier claim disagreement exposed a deterministic normalization defect for the
phrase `READ of size 2`; it was corrected before this final run.

## Public status evaluation

Registered on 2026-10-05, before any Tavily or Nemotron call for this stage. The frozen inputs are
`eval/public_status_prereg.json`. A later results table uses only numbers printed by the committed
run. This section does not contain those results.

Set A is the 10 tasks in `eval/results/arvo10.json`. Frames and crash type are the saved measured
crash states. No sandbox is rerun, and that file is not overwritten. Fix commits are the 40-hex GIT
fixes on each task's mapped OSV id, read from the spike archive below. Owner and repo are the
OSS-Fuzz map in `reproof/door_data.py`. For these 10, that map and the OSV range name the same
repository. A project site is included only when the map has one: jq (`https://jqlang.github.io/jq`)
and libspng (`https://libspng.org`).

ARVO 42531223 maps to OSV-2023-1329. The saved crash state is `decNumberCopy`, `decNaNs`,
`decCompareOp`, so the top frame sent to search is `decNumberCopy`. The OSV record lists `decNaNs`,
`decCompareOp`, `decNumberCompare`. This run does not replace the saved order. The OSV fix commit is
`b86ff49f46a4a37e5a8e75a140cb5fd6e1331384`. Ancestry compares tag `jq-1.7.1` with that commit. A page
whose patched version does not contain the commit is a related variant, not the fix. The compare
response is recorded. An earlier ahead count is not copied into the result.

Set B is 30 OSV records: the 15 OSS-Fuzz projects with the most records in the spike zip, two
records each. The label is OSV-recorded crash state. No sandbox run.

The spike zip that was counted is sha256
`6a77d78ba6d5e9987da236561fe7b3820185476682c420112d9cfbe838bac02a` (3,103,668 bytes, 4,253 JSON
records, 359 projects with a package name, 107 records that `parse_osv_record` did not parse). That
hash is not the `osv_archive_sha256` in `eval/results/arvo10.json`
(`bb40a3b2d1b5c612f172bc03e9164b05c105a724826bdb794ac60568b363d13c`).

Eligibility, chosen before the draw: `parse_osv_record` succeeds, at least one crash-state frame of
length 4 or more, a non-empty crash type, at least one fixed commit matching `^[0-9a-f]{40}$`, and a
github.com GIT range with a non-empty owner and repo (a `.git` suffix is stripped). The first such
range is stored. Projects are ordered by raw record count descending, then name ascending. A project
with fewer than 2 eligible records is skipped. The first 15 that remain are kept. `ghostscript`
(201 records, 0 eligible) and `libxml2` (56 records, 0 eligible) were skipped before that 15th
project. The draw is `random.Random(20261005).sample` of 2 ids from the eligible ids sorted
ascending, and the chosen ids are stored sorted. The committed list is the authority.

| Project | Records | Eligible | OSV ids |
|---|---:|---:|---|
| ndpi | 145 | 145 | OSV-2020-956, OSV-2025-80 |
| harfbuzz | 113 | 112 | OSV-2020-121, OSV-2020-1606 |
| pcapplusplus | 100 | 87 | OSV-2020-1331, OSV-2020-208 |
| opensc | 84 | 81 | OSV-2023-1276, OSV-2023-586 |
| libredwg | 83 | 70 | OSV-2021-535, OSV-2022-1252 |
| fluent-bit | 81 | 69 | OSV-2020-2133, OSV-2021-838 |
| mruby | 78 | 75 | OSV-2022-605, OSV-2024-29 |
| c-blosc2 | 75 | 68 | OSV-2021-897, OSV-2022-322 |
| matio | 70 | 20 | OSV-2026-623, OSV-2026-752 |
| clamav | 66 | 28 | OSV-2020-1365, OSV-2021-1507 |
| openh264 | 64 | 64 | OSV-2020-1855, OSV-2020-2274 |
| radare2 | 61 | 56 | OSV-2020-455, OSV-2020-522 |
| arrow | 60 | 60 | OSV-2020-144, OSV-2020-187 |
| openthread | 53 | 53 | OSV-2020-383, OSV-2020-396 |
| php | 51 | 50 | OSV-2020-1700, OSV-2020-1779 |

A page counts only when the top usable frame and the crash-type keyword are both exact
case-insensitive substrings of the extracted text, or at least two measured frames are. Frames
shorter than 4 characters are ignored. The crash-type keyword drops a trailing access size. The
result host must be the task's GitHub repository, or an NVD, cve.org, or oss-security page that
names the project. GitHub advisory list pages are not mapped or crawled. This batch does not crawl.
Crawl stays a fallback for a project's own `SECURITY.md` or releases, and the batch turns that
fallback off.

Per task the run reports state, evidence URLs, matched frames, CVE and GHSA ids, Tavily credits,
and latency. Per set it reports verified references, false fixed-in claims prevented by ancestry,
unrelated pages rejected by the gate, and credits and latency per triage. A repository or tag that
cannot be resolved is `not checkable`. A verified reference passed the frame gate and the host
check. A fixed-in claim counts only when ancestry says the stated version contains every recorded
OSV fix commit. A version that does not contain the commit is a related variant, and that
patched-version field is marked stale.

The pre-registered expectation, from a 2026-10-05 research pass and not from this run, is that
about 3 of the 10 ARVO tasks have a public reference and the other 7 are `NO_PUBLIC_FINDINGS`. The
committed run replaces that sentence with the measured counts. States are `PUBLICLY_KNOWN_FIXED`
(only after ancestry), `PUBLICLY_KNOWN_OPEN`, `RELATED_VARIANTS_ONLY`, `SOURCE_DISPUTE`, and
`NO_PUBLIC_FINDINGS`. `NO_PUBLIC_FINDINGS` names the queries that were sent and any source that
failed.

The no-Tavily baseline uses the same two sets and no model. It calls paginated
`GET /repos/{owner}/{repo}/security-advisories` (`per_page=100`) and NVD CVE API 2.0
`keywordSearch` set to the top usable frame
(`https://services.nvd.nist.gov/rest/json/cves/2.0`). The GitHub global advisory route
`GET /advisories/{ghsa_id}` has no crash-text search. On 2026-10-05 it returned 404 for
`GHSA-x6c3-qv5r-7q22`, `GHSA-7hmr-442f-qc8j`, `GHSA-686w-5m7m-54vc`, and `GHSA-p7rr-28xf-3m5w`.
The baseline does not use it. A failed repository list or a failed NVD call is a failed source,
not an empty finding. NVD's published unauthenticated limit is 5 requests in a rolling 30 second
window (https://nvd.nist.gov/developers/start-here). The baseline waits 6 seconds between NVD
calls. HTTP 429 is a failed source.

The task budget is 200 Tavily credits and 120 Nemotron calls, including 7 credits already recorded
in `tests/fixtures/tavily`. The eval ledger starts at 7. Each call sets `include_usage`. The
`/usage` endpoint is not called. The batch stops before a call that would pass either budget, and
a task that was not started is reported as not run.

## Tests

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy reproof
uv run pytest -m "not live"
$env:REPROOF_LIVE = "1"
uv run pytest -m live
```

CI runs Ruff, mypy, and the non-live Python tests on Ubuntu 24.04. A second job runs the web
typecheck, lint, unit tests, production build, and non-live Playwright checks. Live tests make
paid Token Factory and ConTree requests and run only when `REPROOF_LIVE=1`.

## Judge door

A judge opens one site, with no login and no key, picks one of the 10 public ARVO reports, and
presses Triage. The page shows that report's public text and its source OSV id. The browser does
not receive `NEBIUS_API_KEY` or the Nebius project id. Those values stay in the Python process.

Triage streams each step as it finishes. Nemotron 3 Super extracts the claim. The vulnerable and
fixed builds run in parallel disposable branches of that task's cached ConTree checkpoint. The
sanitizer output is parsed. Duplicates are searched in the committed per-project OSV index, and
the task's own issue is excluded. A public-status lookup then runs on the measured crash. The page
shows that state, the links, the matched frames, the Tavily request ids, the credits, and the caps.
The verdict field is unchanged. The verdict card still shows the model calls, sandbox operation ids,
cost, and time. If the committed checkpoint is missing, the result is `NEEDS_INFO` and the server
does not build a replacement from a local slice.

Show recorded result fills the same steps from `eval/results/arvo10.json` and labels the card
`RECORDED`. It does not call the model or a sandbox. The Measured section is rendered from that
file. It shows 6 `REPRODUCED`, 4 `DUPLICATE`, the saved costs, and the 2026-10-05 note that the
phase 1 table counted four self-matches.

This browser can run 1 triage at a time. This address can start 8 triages per hour. Everyone
shares 60 triages per day. The Python service keeps the counts. On Vercel, each function instance
keeps its own count file, and instances do not share a disk. A refused start returns HTTP 429 and
does not invent a verdict.

The triage service is a Vercel Python function beside the Next.js app, configured in `vercel.json`.
The measured runtime tree is 166,799,055 bytes. A fresh local process imported `reproof.door` in
3.615514 seconds. That figure is a local import, not a deployed cold start. `maxDuration` is 120
seconds. Vercel's function limits, updated 2026-08-24, set a 500 MB uncompressed maximum for Python
and a 300 second Hobby maximum, and duration includes a streamed response
(https://vercel.com/docs/functions/limitations). 120 seconds is under that Hobby maximum. The
sandbox command timeout in `reproof/sandbox.py` is 600 seconds, so the platform can end a hung call
before the sandbox returns. The account plan was not queried. A container is not used.

The door is deployed at https://reproof-web.vercel.app (Vercel project `reproof-web`, deployed
2026-10-05). A Vercel function can write only under `/tmp`, so the first deployment answered every
triage with HTTP 500 (`Read-only file system: '.cache'`). The production environment sets four
variables: `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID` as secrets, plus `REPROOF_LIMITS_PATH`
(`/tmp/reproof/door-limits.json`) and `REPROOF_CACHE_DIR` (`/tmp/reproof`). After that change, a live
triage of ARVO 42530604 through the deployed page returned `REPRODUCED` with both sandbox operation
ids at a total cost of 0.00090867 USD. `/tmp` is per instance and short-lived, so the caps are best
effort, as stated above.

Locally, start the Python service and the web app. The Next.js route proxies `/api/triage` to
`http://127.0.0.1:8765` unless `REPROOF_DOOR_ORIGIN` is set. On Vercel, `vercel.json` sends
`/api/triage` and `/api/health` to the Python service before Next.js runs.

```powershell
uv run python -m reproof.door_asgi
cd web
pnpm install
pnpm dev
```

From `web/`:

```powershell
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm e2e
```

`pnpm e2e` checks the picker, the recorded result, the Measured section, horizontal overflow at
390, 768, 1024, and 1440 px, and axe. It skips the paid triage. To run that one triage, start both
servers, then:

```powershell
$env:REPROOF_LIVE = "1"
$env:BASE_URL = "http://127.0.0.1:3117"
pnpm exec playwright test tests/e2e/live.spec.ts
```

`node scripts/agent-check.mjs <url>` opens that URL, runs ARVO 42530604, and fails unless the
verdict and every step arrive, including both sandbox operation ids. A missing URL exits 2.
`.github/workflows/live.yml` runs the probe on `ubuntu-24.04` once a day at 15:17 UTC and when
started by hand. The URL is a required workflow input, or the repository variable
`REPROOF_DOOR_URL`. An empty URL fails the job. Until a public URL is set, the scheduled run is
red. GitHub can delay a scheduled run, so a green run is not a liveness guarantee.

CI on Ubuntu 24.04 runs the Python gates and a separate web job for typecheck, lint, unit tests,
the production build, and the non-live Playwright checks. CI does not set `REPROOF_LIVE`.

## License

Apache-2.0. See `LICENSE`.
