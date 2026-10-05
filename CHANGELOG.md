# Changelog

## Unreleased

- Added the Python 3.12 package, local-only data controls, Apache-2.0 license, and CI gates.
- Added typed ARVO metadata access and ClusterFuzz 2.6.0 crash parsing.
- Added OSS-Fuzz OSV indexing with exact and inline-tolerant matching that keeps every candidate and every fixed commit.
- Added stopped-container runtime-slice extraction with recursive ELF dependency resolution, explicit before and after measurements, symbolizer-path fallback, and local image deletion.
- Added strict Nemotron claim extraction, cached ConTree checkpoints, parallel disposable reproduction, JSON triage cards, CLI commands, and resumable evaluation.
- Measured 10 public ARVO tasks: 7 OSV crash-state agreements, 10 clean fixed builds, 9 claim agreements, 11 duplicate candidates, and $0.00908576 combined cost.
- Verified the package with 16 unit tests, 2 paid live tests, Ruff formatting, Ruff lint, a real CLI triage, and the full ARVO 10 evaluation.
