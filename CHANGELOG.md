# Changelog

## Unreleased

- Added the Python 3.12 package, local-only data controls, Apache-2.0 license, and CI gates.
- Added typed ARVO metadata access and ClusterFuzz 2.6.0 crash parsing.
- Added OSS-Fuzz OSV indexing with exact and inline-tolerant matching that keeps every candidate and every fixed commit.
- Added stopped-container runtime-slice extraction with recursive ELF dependency resolution, explicit before and after measurements, symbolizer-path fallback, and local image deletion.
- Added strict Nemotron claim extraction, cached ConTree checkpoints, parallel disposable reproduction, JSON triage cards, CLI commands, and resumable evaluation.
- Measured 10 public ARVO tasks: 7 OSV crash-state agreements, 10 clean fixed builds, 10 claim agreements, 11 duplicate candidates, and $0.00916804 full operation-lifecycle cost.
- Corrected sanitizer detection for ClusterFuzz `UNKNOWN` labels, fixed-build verdict gating, claim normalization, checkpoint cost persistence, cache validation, and failure ID capture after independent review.
- Added eval provenance hashes, evidence-bound card validation, a frozen candidate table, and a derived-card refresh script that does not rerun paid work.
- Hardened sanitizer excerpts, deterministic verdict validation, image-deletion verification, persistence failure IDs, failed model-call accounting, and resume provenance after independent review.
- Verified the package with 54 unit tests, 2 paid live tests, Ruff formatting, Ruff lint, a real CLI triage, and the full ARVO 10 evaluation.
