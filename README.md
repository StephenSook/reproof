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
- `NOT_REPRODUCED`: the vulnerable build did not produce a sanitizer crash. The card lists every
  input tried.
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
   original and patched SHA-256 and size for every file, writes a manifest, and deletes the local
   Docker image.
3. `reproof.sandbox` uploads the slice into a named ConTree checkpoint based on
   `python:3.12-slim`. It caches checkpoint UUIDs locally and runs vulnerable and fixed branches in
   parallel with `disposable=True`.
4. `reproof.crash` parses sanitizer output with `clusterfuzz==2.6.0`.
5. `reproof.dup` checks every same-project record in the public OSS-Fuzz OSV archive. Matching is
   exact first, then tolerant of inline sibling frames at the same program counter.
6. `reproof.claims` asks `nvidia/nemotron-3-super-120b-a12b` for the strict report claim, with
   temperature 0 and thinking disabled. Deterministic code compares the claimed bug class and
   functions with the measured crash.
7. `reproof.triage` writes the verdict, sanitizer excerpt, crash type and state, fixed result,
   duplicate candidates, claim comparison, model calls, sandbox operations, cost, and wall time.

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
selected images. Each image is deleted after its slice and manifest are written.

An interrupted eval can reuse strict cards that were already written:

```powershell
uv run reproof eval --n 10 --resume
```

Local caches, runtime slices, databases, zip archives, card details, and credentials are excluded
from Git. The aggregate eval result is tracked at `eval/results/arvo10.json`.

## ARVO 10 evaluation

Selection always includes 42530604, 42507851, and 42496387. The remaining tasks are the smallest
by `max(vulnerable GB, fixed GB)` among the spike's frozen 2026-10-05 memory-safety candidate table
that have a mapped public OSV record. Ties use ARVO ID. Each report is the mapped public OSS-Fuzz
OSV summary plus details, not a private report.

| ARVO | Project | Verdict | OSV state agrees | Fixed clean | OSV candidates | Claim agrees | Cost USD | Seconds |
|---:|---|---|---|---|---|---|---:|---:|
| 42530604 | jq | DUPLICATE | yes | yes | OSV-2023-1239 | yes | 0.00079247 | 4.944027 |
| 42507851 | libplist | DUPLICATE | yes | yes | OSV-2022-93 | yes | 0.00086026 | 19.777161 |
| 42496387 | wasm3 | REPRODUCED | no | yes | none | yes | 0.00090432 | 23.620587 |
| 42508524 | libplist | DUPLICATE | yes | yes | OSV-2022-147, OSV-2022-158 | yes | 0.00086470 | 39.494779 |
| 42536108 | miniz | DUPLICATE | yes | yes | OSV-2024-550 | yes | 0.00091783 | 65.302103 |
| 42536112 | miniz | DUPLICATE | yes | yes | OSV-2024-551 | yes | 0.00091361 | 20.233260 |
| 42508390 | libplist | DUPLICATE | no | yes | OSV-2022-93 | yes | 0.00084522 | 27.917757 |
| 42531297 | jq | DUPLICATE | yes | yes | OSV-2023-1344, OSV-2025-363 | no | 0.00105939 | 43.747241 |
| 42531223 | jq | REPRODUCED | no | yes | none | yes | 0.00106674 | 36.503697 |
| 42476752 | libspng | DUPLICATE | yes | yes | OSV-2020-307, OSV-2020-344 | yes | 0.00086122 | 39.510942 |

Measured totals:

- 10 of 10 tasks completed.
- 7 of 10 measured crash states agreed exactly or inline-tolerantly with a mapped OSV state.
- 10 of 10 fixed builds were clean.
- 9 of 10 claim comparisons agreed on both bug class and top crash function.
- 11 duplicate candidates were returned.
- Nemotron used 1,349 input tokens and 1,180 output tokens. At the published price of $0.30 per
  million input tokens and $0.90 per million output tokens, model cost was $0.00146670.
- ConTree sandbox cost was $0.00761906.
- Combined eval cost was $0.00908576.
- Summed per-task wall time was 321.051554 seconds.

The three OSV state disagreements and the one claim disagreement remain visible in the result.
They are not converted into successes.

## Tests

```powershell
uv run ruff format --check .
uv run ruff check .
uv run pytest -m "not live"
$env:REPROOF_LIVE = "1"
uv run pytest -m live
```

CI runs Ruff and the non-live tests. Live tests make paid Token Factory and ConTree requests and
run only when `REPROOF_LIVE=1`.

## License

Apache-2.0. See `LICENSE`.
