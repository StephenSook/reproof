# Changelog

## Unreleased

- Added Playwright checks for the report picker, the recorded step view, the Measured section, horizontal overflow, and axe. The real triage check stays off unless REPROOF_LIVE=1. CI runs the non-live web gates.
- Added a live probe for ARVO 42530604. It fails unless the verdict and every triage step arrive, including both sandbox operation ids. The scheduled workflow requires a public door URL and fails when that URL is empty.
- Added the judge door page and triage caps. The page lists the 10 public reports, streams one triage, and can show the saved ARVO 10 row labelled RECORDED. One browser can run one triage at a time, one address can start 8 per hour, and everyone shares 60 per day. On Vercel, each function instance keeps its own count file.
- Chose a Vercel Python function beside the Next.js app for the judge door. The measured runtime tree is 166,799,055 bytes and the local cold import of reproof.door is 3.615514 seconds. maxDuration is 120 seconds. Nothing was deployed.
- Added a cached-checkpoint triage entry point, a committed ConTree checkpoint manifest, and a per-project OSV index for jq, libplist, wasm3, miniz, and libspng. A missing checkpoint returns NEEDS_INFO and is not rebuilt from a local slice.
- Added the Python 3.12 package, local-only data controls, Apache-2.0 license, and CI gates.
- Added typed ARVO metadata access and ClusterFuzz 2.6.0 crash parsing.
- Added OSS-Fuzz OSV indexing with exact and inline-tolerant matching that keeps every candidate and every fixed commit.
- Added stopped-container runtime-slice extraction with recursive ELF dependency resolution, explicit before and after measurements, symbolizer-path fallback, and local image deletion.
- Added strict Nemotron claim extraction, cached ConTree checkpoints, parallel disposable reproduction, JSON triage cards, CLI commands, and resumable evaluation.
- Measured 10 public ARVO tasks: 6 reproduced reports, 4 duplicates, 7 OSV crash-state agreements, 10 clean fixed builds, 10 claim agreements, 4 independent duplicate candidates, and $0.00916804 full operation-lifecycle cost.
- On 2026-10-05, review of the saved cards found that the phase 1 table counted four self-matches; duplicate search now excludes every OSV record mapped to the task's own OSS-Fuzz issue and records those IDs on each card.
- Corrected sanitizer detection for ClusterFuzz `UNKNOWN` labels, fixed-build verdict gating, claim normalization, checkpoint cost persistence, cache validation, and failure ID capture after independent review.
- Added eval provenance hashes, evidence-bound card validation, a frozen candidate table, and a derived-card refresh script that does not rerun paid work.
- Hardened sanitizer excerpts, deterministic verdict validation, image-deletion verification, persistence failure IDs, failed model-call accounting, and resume provenance after independent review.
- Required unsanitized fatal vulnerable runs to return `NEEDS_INFO` instead of `NOT_REPRODUCED`, with the exit code and missing evidence recorded.
- Rejected header-only sanitizer output as conclusive crash evidence, supported canonical frame formats, and bound `NEEDS_INFO` details to the measured execution failure.
- Verified the current package with 99 non-live tests, Ruff formatting, Ruff lint, mypy, and the provenance-validated ARVO 10 evaluation.
