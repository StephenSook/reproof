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
`eval/public_status_prereg.json`. The measured tables below use only fields in
`eval/results/public_status.json`.

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

Page text is untrusted. Nemotron is told not to follow instructions in it, a quote must appear
verbatim on the page (a run of spaces or line breaks compares as one space; case, punctuation and
every character inside a word must match), draft lines are built from fixed sentences, and a
fixed-in claim needs git ancestry, never the model alone. When a quote is not on the page, Nemotron
is asked once more with a note that names the failure but not the quote; the second answer passes
the same guard, and both calls count toward cost. The remaining risk: anyone can post a GitHub issue that names the
measured frames, and the model's same-bug or open call on that page can be steered. The worst case
is a link to a real public page that does mention the crash, labelled with the wrong relation.

Per task the run reports state, evidence URLs, matched frames, CVE and GHSA ids, Tavily credits,
and latency. Per set it reports verified references, false fixed-in claims prevented by ancestry,
unrelated pages rejected by the gate, and credits and latency per triage. A repository or tag that
cannot be resolved is `not checkable`. A verified reference passed the frame gate and the host
check. A fixed-in claim counts only when ancestry says the stated version contains every recorded
OSV fix commit. A version that does not contain the commit is a related variant, and that
patched-version field is marked stale.

When a kept page is a GitHub security advisory on the task's own repository, the lookup also
reads that advisory's structured record from the GitHub API. `vulnerabilities[].patched_versions`
is a claim about a version, the same kind of claim as a version in the page text. Git ancestry
is still the only check that can mark the crash `PUBLICLY_KNOWN_FIXED`. If the advisory request
fails, times out, or is not the expected shape, the page keeps the state it would have had
without that request, and the failure is listed with the other failed sources.

The pre-registered expectation, from a 2026-10-05 research pass and not from this run, was that
about 3 of the 10 ARVO tasks would have a public reference and the other 7 would be
`NO_PUBLIC_FINDINGS`. States are `PUBLICLY_KNOWN_FIXED` (only after ancestry),
`PUBLICLY_KNOWN_OPEN`, `RELATED_VARIANTS_ONLY`, `SOURCE_DISPUTE`, `NO_PUBLIC_FINDINGS`, and
`LOOKUP_UNAVAILABLE`. `NO_PUBLIC_FINDINGS` means the search ran and no page it returned passed
the gates. It names the queries that were sent and any source that failed. `LOOKUP_UNAVAILABLE`
means no search result or page was read: there was no measured frame, the Tavily key was missing,
the search failed, every query was refused or stopped before a result list was read, extract
could not read any page the search returned, or the lookup stopped with an error. It claims nothing
either way. No task in the run below was `LOOKUP_UNAVAILABLE`: every task sent two searches and read
their result lists, and every task whose search kept a page extracted at least one page.

The stored `queries_sent` and the note's "Searched queries" list in `eval/results/public_status.json`
come from the planner, not from the searches. On 18 of the 40 tasks the planner wrote 3 queries and
the two-search cap sent 2, so those rows list one query that was never sent. Each row's
`tavily_calls` lists the queries actually searched. The code now records only sent queries. The
result file is left as it was written.

### Measured run

`eval/run_public_status.py` wrote `eval/results/public_status.json`. Its `prereg_sha256` is
`8f93a6e0e5dd69af452a1c6e67144e949f96b3f71f5e96f4a2c7800dba8bea9e`, the same hash as the committed
pre-registration file. The batch did not crawl. All 40 tasks ran. None stopped for the credit or
Nemotron budget.

This run recorded 174 Tavily credits: 80 search calls account for 160, and 22 extract calls account
for 14. The ledger started at the 7 recorded fixture credits and ended at 181. Nemotron calls: 54.
The sum of the stored per-task `model_cost_usd` values is 0.0131517. Summed triage latency is
85.535945 seconds on set A and 299.08624 seconds on set B.

GitHub compare of `jqlang/jq` tag `jq-1.7.1` against
`b86ff49f46a4a37e5a8e75a140cb5fd6e1331384` returned status `ahead`, `ahead_by` 102, `behind_by` 0,
and an empty error. Under the rule above, that tag does not contain the OSV fix commit.
`GHSA-7hmr-442f-qc8j` does not appear in the result file. No kept page and no baseline reference
stored a patched version, an upstream version, or `FIXED`. The fixed-in counter is 0 precise, 0
prevented, and 0 not checkable. `stale_fields` is empty on all 7 evidence pages. Each of those
pages has ancestry `NOT_CHECKABLE`: the page stated nothing the checker could compare, so the
upstream fix is not checkable.

Set A kept a verified reference on 3 of 10 tasks. All 3 are `PUBLICLY_KNOWN_OPEN`. The other 7 are
`NO_PUBLIC_FINDINGS`. `PUBLICLY_KNOWN_FIXED`, `RELATED_VARIANTS_ONLY`, and `SOURCE_DISPUTE` are 0.
Rejections before the card: frame 22, host 10, snippet 1, unrelated 0, quote guard 2, source file
5. Credits 46. Model calls 16. The 3 references are wasm3 42496387, jq 42531297, and jq 42531223.

| Task | Project | State | Credits | Latency (s) | Model calls | Evidence |
|---|---|---|---:|---:|---:|---|
| 42530604 | jq | NO_PUBLIC_FINDINGS | 5 | 12.351041 | 2 | none |
| 42507851 | libplist | NO_PUBLIC_FINDINGS | 5 | 8.898709 | 1 | none |
| 42496387 | wasm3 | PUBLICLY_KNOWN_OPEN | 4 | 11.13846 | 2 | [wasm3#458](https://github.com/wasm3/wasm3/issues/458) (`ForEachModule`, `Runtime_Release`, `m3_FreeRuntime`) |
| 42508524 | libplist | NO_PUBLIC_FINDINGS | 5 | 8.229591 | 1 | none |
| 42536108 | miniz | NO_PUBLIC_FINDINGS | 4 | 5.426646 | 1 | none |
| 42536112 | miniz | NO_PUBLIC_FINDINGS | 4 | 7.204559 | 1 | none |
| 42508390 | libplist | NO_PUBLIC_FINDINGS | 5 | 1.832194 | 1 | none |
| 42531297 | jq | PUBLICLY_KNOWN_OPEN | 4 | 13.009655 | 3 | [GHSA-p7rr-28xf-3m5w](https://github.com/jqlang/jq/security/advisories/GHSA-p7rr-28xf-3m5w) (`jv_string_vfmt`, `jv_string_fmt`, `jv_get`); [jq releases](https://github.com/jqlang/jq/releases) (`jv_string_vfmt`, `jv_get`) |
| 42531223 | jq | PUBLICLY_KNOWN_OPEN | 5 | 12.449279 | 3 | [GHSA-x6c3-qv5r-7q22](https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22) (`decNumberCopy`, `decNaNs`, `decCompareOp`) |
| 42476752 | libspng | NO_PUBLIC_FINDINGS | 5 | 4.995811 | 1 | none |

Set B kept a verified reference on 2 of 30 tasks, both `PUBLICLY_KNOWN_OPEN`: ndpi OSV-2025-80 and
php OSV-2020-1700. The other 28 are `NO_PUBLIC_FINDINGS`. The other three states are 0. Rejections
before the card: frame 33, host 49, snippet 65, unrelated 0, quote guard 2, source file 39.
Credits 128. Model calls 38. Two tasks used the deterministic query fallback after the planner did
not return an acceptable query: OSV-2020-208 and OSV-2020-144. Two tasks recorded a rejected query
reason `missing_project_and_frame`: OSV-2022-322 and OSV-2020-144. No Tavily call failed.

| OSV id | Project | State | Credits | Latency (s) | Model calls | Evidence |
|---|---|---|---:|---:|---:|---|
| OSV-2020-956 | ndpi | NO_PUBLIC_FINDINGS | 5 | 9.710887 | 1 | none |
| OSV-2025-80 | ndpi | PUBLICLY_KNOWN_OPEN | 4 | 16.272163 | 2 | [412ca87](https://github.com/ntop/nDPI/commit/412ca8700fc53da705c6aa386c736a400279a614) |
| OSV-2020-121 | harfbuzz | NO_PUBLIC_FINDINGS | 5 | 9.69678 | 1 | none |
| OSV-2020-1606 | harfbuzz | NO_PUBLIC_FINDINGS | 4 | 9.758406 | 1 | none |
| OSV-2020-1331 | pcapplusplus | NO_PUBLIC_FINDINGS | 4 | 9.424525 | 1 | none |
| OSV-2020-208 | pcapplusplus | NO_PUBLIC_FINDINGS | 4 | 10.714157 | 2 | none |
| OSV-2023-1276 | opensc | NO_PUBLIC_FINDINGS | 4 | 8.07384 | 1 | none |
| OSV-2023-586 | opensc | NO_PUBLIC_FINDINGS | 4 | 8.598424 | 1 | none |
| OSV-2021-535 | libredwg | NO_PUBLIC_FINDINGS | 5 | 8.052583 | 1 | none |
| OSV-2022-1252 | libredwg | NO_PUBLIC_FINDINGS | 4 | 6.812974 | 1 | none |
| OSV-2020-2133 | fluent-bit | NO_PUBLIC_FINDINGS | 4 | 6.98163 | 1 | none |
| OSV-2021-838 | fluent-bit | NO_PUBLIC_FINDINGS | 4 | 11.738294 | 1 | none |
| OSV-2022-605 | mruby | NO_PUBLIC_FINDINGS | 5 | 10.673764 | 1 | none |
| OSV-2024-29 | mruby | NO_PUBLIC_FINDINGS | 4 | 10.147043 | 1 | none |
| OSV-2021-897 | c-blosc2 | NO_PUBLIC_FINDINGS | 4 | 7.856186 | 1 | none |
| OSV-2022-322 | c-blosc2 | NO_PUBLIC_FINDINGS | 4 | 6.492893 | 2 | none |
| OSV-2026-623 | matio | NO_PUBLIC_FINDINGS | 4 | 9.769041 | 1 | none |
| OSV-2026-752 | matio | NO_PUBLIC_FINDINGS | 4 | 9.003484 | 1 | none |
| OSV-2020-1365 | clamav | NO_PUBLIC_FINDINGS | 4 | 12.027222 | 1 | none |
| OSV-2021-1507 | clamav | NO_PUBLIC_FINDINGS | 4 | 10.083734 | 1 | none |
| OSV-2020-1855 | openh264 | NO_PUBLIC_FINDINGS | 5 | 7.038912 | 1 | none |
| OSV-2020-2274 | openh264 | NO_PUBLIC_FINDINGS | 5 | 7.031268 | 1 | none |
| OSV-2020-455 | radare2 | NO_PUBLIC_FINDINGS | 4 | 8.53007 | 1 | none |
| OSV-2020-522 | radare2 | NO_PUBLIC_FINDINGS | 4 | 8.319241 | 1 | none |
| OSV-2020-144 | arrow | NO_PUBLIC_FINDINGS | 4 | 9.270874 | 2 | none |
| OSV-2020-187 | arrow | NO_PUBLIC_FINDINGS | 4 | 10.437632 | 1 | none |
| OSV-2020-383 | openthread | NO_PUBLIC_FINDINGS | 4 | 10.785392 | 1 | none |
| OSV-2020-396 | openthread | NO_PUBLIC_FINDINGS | 4 | 10.886189 | 1 | none |
| OSV-2020-1700 | php | PUBLICLY_KNOWN_OPEN | 5 | 20.329323 | 4 | [php#18844](https://github.com/php/php-src/issues/18844), [php#14969](https://github.com/php/php-src/issues/14969) |
| OSV-2020-1779 | php | NO_PUBLIC_FINDINGS | 5 | 14.569309 | 2 | none |

Every kept page was classified `SAME_BUG` with upstream status `UNKNOWN` and dispute false. The
id columns are ids found in the extracted text. A GHSA id that appears only in the URL is not
repeated as an extracted id.

| Task | Page | Match | Frames | Extracted CVE ids | Extracted GHSA ids | Ancestry |
|---|---|---|---|---|---|---|
| 42496387 | wasm3#458 | top frame and crash type | `ForEachModule`, `Runtime_Release`, `m3_FreeRuntime` | none | none | NOT_CHECKABLE |
| 42531297 | GHSA-p7rr-28xf-3m5w | top frame and crash type | `jv_string_vfmt`, `jv_string_fmt`, `jv_get` | none | none | NOT_CHECKABLE |
| 42531297 | jqlang/jq releases | two frames | `jv_string_vfmt`, `jv_get` | CVE-2024-23337, CVE-2024-53427, CVE-2025-48060, CVE-2026-32316, CVE-2026-33947, CVE-2026-33948, CVE-2026-39956, CVE-2026-39979, CVE-2026-40164, CVE-2026-40612, CVE-2026-41256 | none | NOT_CHECKABLE |
| 42531223 | GHSA-x6c3-qv5r-7q22 | top frame and crash type | `decNumberCopy`, `decNaNs`, `decCompareOp` | none | none | NOT_CHECKABLE |
| OSV-2025-80 | nDPI 412ca87 | two frames | `ndpi_snprintf`, `process_ndpi_collected_info` | none | none | NOT_CHECKABLE |
| OSV-2020-1700 | php#18844 | two frames | `zend_gc_delref`, `i_zval_ptr_dtor` | none | none | NOT_CHECKABLE |
| OSV-2020-1700 | php#14969 | two frames | `zend_gc_delref`, `i_zval_ptr_dtor` | none | none | NOT_CHECKABLE |

The 11 CVE ids on the jq releases row are every id the regex found on that index. They are not
each scored as ARVO 42531297. `CVE-2024-27530` and `CVE-2023-50268` do not appear in the result
file. Tavily request ids for the five tasks with evidence:

- 42496387: `9bf889cd-f0c2-450f-bda7-3594e9c319c1`, `0b9c7ef0-f35f-4ba4-8718-c12b2f9bc88a`, `37ac7024-0068-4d00-a9bf-d1334ff0163d`
- 42531297: `727c2f85-9061-4ef9-a497-7653dbd6c6b1`, `a388cbb7-f568-4bad-9682-cae63768fa16`, `2ec443bf-e367-49dd-9837-da2a529b5ed4`
- 42531223: `a0ca9d92-60a3-4111-aea4-9d297baa4d21`, `73e3c263-792a-4785-89e8-5f1e361a40c3`, `15b31f29-4cbf-4c23-9e06-2f481a2f1384`
- OSV-2025-80: `568f0b0b-b3ef-431e-88d2-5fef4dbe5f4a`, `7a24813d-89c5-4eef-b451-d22643a9511c`, `5900b8a9-284f-43b8-b636-8a6e02dbe7aa`
- OSV-2020-1700: `d012b96d-45f8-4fbd-bccb-250c60a84820`, `8d8ae35e-5e51-41b7-a933-afacbda52995`, `d7ac3060-b7d1-4803-ae5c-1029286dd3dc`

The no-Tavily baseline kept 3 references, all from
`GET /repos/jqlang/jq/security-advisories`. NVD `keywordSearch` added none. Failed sources: 0 on
all 40 tasks. Set A baseline latency is 42.719854 seconds, with 82 frame rejects and 14 host
rejects. Set B baseline latency is 180.699298 seconds, with 175 frame rejects, 22 host rejects,
and 0 references. The baseline fixed-in counter is 0 precise, 0 prevented, and 0 not checkable.
Each baseline reference has an empty patched-version list and ancestry `NOT_CHECKABLE`.

| Task | Advisory | GHSA id | CVE id | Frames | Ancestry |
|---|---|---|---|---|---|
| 42530604 | [GHSA-686w-5m7m-54vc](https://github.com/jqlang/jq/security/advisories/GHSA-686w-5m7m-54vc) | GHSA-686w-5m7m-54vc | CVE-2023-50246 | `decToString`, `decNumberToString`, `jvp_literal_number_literal` | NOT_CHECKABLE |
| 42531297 | [GHSA-p7rr-28xf-3m5w](https://github.com/jqlang/jq/security/advisories/GHSA-p7rr-28xf-3m5w) | GHSA-p7rr-28xf-3m5w | CVE-2025-48060 | `jv_string_vfmt`, `jv_string_fmt`, `jv_get` | NOT_CHECKABLE |
| 42531223 | [GHSA-x6c3-qv5r-7q22](https://github.com/jqlang/jq/security/advisories/GHSA-x6c3-qv5r-7q22) | GHSA-x6c3-qv5r-7q22 | CVE-2024-53427 | `decNumberCopy`, `decNaNs`, `decCompareOp` | NOT_CHECKABLE |

Tavily kept no page for ARVO 42530604. The baseline kept GHSA-686w-5m7m-54vc for that task. Tavily
and the baseline both kept GHSA-p7rr-28xf-3m5w and GHSA-x6c3-qv5r-7q22.

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

### Advisory rescore, registered before the run

For every kept evidence page and every baseline reference in `eval/results/public_status.json` whose URL is a GitHub security advisory on that task's own repository, `eval/rescore_advisories.py` reads `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}` and runs the existing ancestry check against that task's OSV fix commits. It writes `eval/results/advisory_rescore.json`, including the GitHub API URLs it called. It does not modify `eval/results/public_status.json`. It does not call Tavily or Nemotron. The advisory record is a version claim. The result state is `PUBLICLY_KNOWN_FIXED` only when ancestry says the tag contains the fix. A failed read, a patched version git cannot check, or an empty patched-version string is `NOT_CHECKABLE`. A version git contradicts is not `FIXED`.

Hand check before this run, not a result: baseline 42530604 `GHSA-686w-5m7m-54vc` may become `FIXED` in 1.7.1. `GHSA-x6c3-qv5r-7q22` on 42531223 and `GHSA-p7rr-28xf-3m5w` on 42531297 are unknown until the script measures them.

The run wrote `eval/results/advisory_rescore.json`. Its `source_sha256` is `c47fb739cd362f6a7e7cb7488d7ac1b451dbcb0c60b822405ee7a33488388334`, the hash of `eval/results/public_status.json`, which this run did not modify. `tavily_calls` is 0. `nemotron_calls` is 0. GitHub API URLs called, in order:

1. `https://api.github.com/repos/jqlang/jq/security-advisories/GHSA-p7rr-28xf-3m5w`
2. `https://api.github.com/repos/jqlang/jq/security-advisories/GHSA-x6c3-qv5r-7q22`
3. `https://api.github.com/repos/jqlang/jq/security-advisories/GHSA-686w-5m7m-54vc`
4. `https://api.github.com/repos/jqlang/jq/tags?per_page=100&page=1`
5. `https://api.github.com/repos/jqlang/jq/compare/jq-1.7.1...71c2ab509a8628dbbad4bc7b3f98a64aa90d3297`

| Task | Role | Advisory | patched_versions | Tag | Compare | ahead_by | behind_by | Ancestry | State |
|---|---|---|---|---|---|---|---|---|---|
| 42531297 | evidence | GHSA-p7rr-28xf-3m5w | `""` | | | null | null | NOT_CHECKABLE | NOT_CHECKABLE |
| 42531223 | evidence | GHSA-x6c3-qv5r-7q22 | `""` | | | null | null | NOT_CHECKABLE | NOT_CHECKABLE |
| 42530604 | baseline | GHSA-686w-5m7m-54vc | `1.7.1` | `jq-1.7.1` | identical | 0 | 0 | CONTAINS_FIX | PUBLICLY_KNOWN_FIXED |
| 42531297 | baseline | GHSA-p7rr-28xf-3m5w | `""` | | | null | null | NOT_CHECKABLE | NOT_CHECKABLE |
| 42531223 | baseline | GHSA-x6c3-qv5r-7q22 | `""` | | | null | null | NOT_CHECKABLE | NOT_CHECKABLE |

`patched_versions` `""` is the empty string the advisory API returned. Those four rows have no usable version, so ancestry did not compare a tag. Baseline 42530604 is `PUBLICLY_KNOWN_FIXED` because tag `jq-1.7.1` is `identical` to OSV fix `71c2ab509a8628dbbad4bc7b3f98a64aa90d3297` (`ahead_by` 0, `behind_by` 0).

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

The result starts with the answer. A summary at the top shows the verdict and one sentence, the
vulnerable and fixed builds side by side (crashed or clean, the crash type, the top frame, and each
exit code), the public-status line, and the wall time, cost, Tavily credits, and model calls. It is
labelled `LIVE` or `RECORDED`. When git ancestry decided the fix, the public-status line gives the
sentence, for example `Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5.`, a
link to the page, and a ribbon that joins the release tag to the fix commit. Every value in the
summary comes from the stream or the saved row. A value that has not arrived says so.

Triage streams each step as it finishes, and the summary fills in as the steps arrive. Nemotron 3
Super extracts the claim. The vulnerable and fixed builds run in parallel disposable branches of
that task's cached ConTree checkpoint. The sanitizer output is parsed. Duplicates are searched in
the committed per-project OSV index, and the task's own issue is excluded. A public-status lookup
then runs on the measured crash, with git ancestry and the advisory read going to the GitHub REST
API without a token (GitHub allows 60 unauthenticated requests per hour per address; a refused call
is listed as a failed source). The public status does not change the verdict. If the committed
checkpoint is missing, the result is `NEEDS_INFO` and the server does not build a replacement from
a local slice.

Below the summary, under Evidence, each step is a disclosure. It is open while the stream runs and
closes when the verdict arrives. It holds every id and cost: the model request id, both sandbox
operation ids, the matched frames, the Tavily request ids, the credits and caps, the checked tag and
commit, and the triage card's model calls. The ancestry sentence appears once, in the summary.

Show recorded result fills the summary and the same steps from `eval/results/arvo10.json` and labels
them `RECORDED`. It does not call the model or a sandbox. That file holds no public-status lookup,
and the summary says so. The Measured section is rendered from that file. It shows 6 `REPRODUCED`,
4 `DUPLICATE`, the saved costs, and the 2026-10-05 note that the phase 1 table counted four
self-matches.

The page uses GSAP and Lenis for motion. When the browser asks for reduced motion, nothing moves.

This browser can run 1 triage at a time. This address can start 8 triages per hour. Everyone
shares 60 triages per day. The Python service keeps the counts. On Vercel, each function instance
keeps its own count file, and instances do not share a disk. A refused start returns HTTP 429 and
does not invent a verdict.

Tavily spend on the door: each lookup holds 5 credits (2 advanced searches and one basic extract)
against 100 credits per UTC day on that server instance, and sends no search when the hold does not
fit or the count file cannot be used. Its ledger stops at 5, counting calls that were sent but got no
readable answer. The day is then charged the larger of the hold and what the lookup reported or may
have been billed, so a lookup can take the day past 100 only if Tavily reports more than its
estimate; all 102 calls in the stored evaluation were billed at or under it. For 60 minutes, the same
measured crash is answered from the stored card, which shows that lookup's time and request ids and
spends 0 new credits, but only while the public-status code is unchanged: the reuse key includes a
hash of `door.py` and the four lookup modules, so a deploy that changes them starts fresh; a `LOOKUP_UNAVAILABLE` card is never saved or reused. The count is per instance
and starts again on a new instance, so it is not a ceiling across Vercel's instances; the account
balance is. Rules and edge cases: `reproof/door_limits.py`, `reproof/assets/limits.json`.

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

`pnpm e2e` checks the picker, the recorded result, the summary and the evidence disclosures, the
ancestry ribbon, reduced motion, the Measured section, horizontal overflow at 390, 768, 1024, and
1440 px, and axe. The live summary tests replay `web/tests/fixtures/door-stream.ndjson`, which a
test in `tests/test_door.py` writes from `reproof/door.py` and the door's NDJSON serializer with
stubbed services; that Python test fails when the stored file no longer matches. Regenerate it with
`REPROOF_WRITE_WEB_FIXTURE=1 uv run pytest tests/test_door.py -k web_stream`. The e2e suite skips
the paid triage. To run that one triage, start both servers, then:

```powershell
$env:REPROOF_LIVE = "1"
$env:BASE_URL = "http://127.0.0.1:3117"
pnpm exec playwright test tests/e2e/live.spec.ts
```

`node scripts/agent-check.mjs <url>` opens that URL, runs ARVO 42530604, and fails unless the
verdict and every step arrive, including both sandbox operation ids. A missing URL exits 2.
On a failed attempt, it records the `/api/triage` request and response metadata, browser errors,
failed requests, and the first 500 characters of a non-200 body. It retries once after 60 seconds
in a fresh browser context and saves the JSON report and Playwright trace under `web/test-results/`.
`.github/workflows/live.yml` runs the probe on `ubuntu-24.04` once a day at 15:17 UTC and when
started by hand. The URL is a required workflow input, or the repository variable
`REPROOF_DOOR_URL`. An empty URL fails the job. Until a public URL is set, the scheduled run is
red. GitHub can delay a scheduled run, so a green run is not a liveness guarantee.

CI on Ubuntu 24.04 runs the Python gates and a separate web job for typecheck, lint, unit tests,
the production build, and the non-live Playwright checks. CI does not set `REPROOF_LIVE`.

## License

Apache-2.0. See `LICENSE`.
