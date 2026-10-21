# Offline patch evaluation, run 2: registration

Written 2026-10-21, after run 1 and before run 2's scored run, and committed and pushed before
that run starts. Run 2 is run once. Its result is published whatever it shows, in
`eval/results/patch-eval-run2.json`, one card per task in `eval/results/patch-eval-run2-cards/`,
and on the `/proof` page beside run 1. Run 1 (`eval/PATCH-PREREG.md`, `eval/results/patch-eval.json`,
`eval/results/patch-cards/`) stays published unchanged. There is no tuning and no third run to
improve the number.

## Why a second run

Run 1 was registered in `bc162af` and run once on 2026-10-21 from 15:21 to 15:42 UTC: 2 of 10
proven. A harness defect was found in its cards and written down after it, in
`eval/results/patch-eval-notes.json`: in 5 of the 10 images (wasm3 42496387, miniz 42536108 and
42536112, jq 42531297, libspng 42476752) the build script makes a directory with plain `mkdir`.
The harness's control compile ran that script first, in the same container as every attempt, so
every later `arvo compile` there stopped at `mkdir: cannot create directory '...': File exists`
and 12 of the 29 attempts never tested their edit. Run 2 asks the same question with that defect
fixed.

## The same as run 1

Everything in `eval/PATCH-PREREG.md` holds for run 2 except the four changes below. In particular:

- The 10 tasks, in the same order (42530604, 42507851, 42496387, 42508524, 42536108, 42536112,
  42508390, 42531297, 42531223, 42476752), with a denominator of 10 whatever happens to any task.
- Model `nvidia/nemotron-3-super-120b-a12b` on Nebius Token Factory, temperature 0, `max_tokens`
  4,096, thinking disabled, the same strict JSON schema, `SYSTEM_PROMPT` verbatim, and the same
  first message built the same way: project, source tree, OSV report text, the baseline's parsed
  sanitizer report (at most 6,000 characters) and the source windows (80 lines before and 40
  after each chosen frame, merged, up to 40,000 characters), with frames chosen as in run 1
  except for change 3.
- N = 3 attempts per task; the whole conversation and the failure sent back after a failed
  attempt; one retry after 30 seconds on a transport error or HTTP 5xx.
- The edit rules (absolute path inside the source tree, not a fuzz harness, test or build file,
  existing in the image, `old_text` non-empty and occurring exactly once).
- The time limits (compile 30 minutes, PoC 5 minutes, seed run 15 minutes) and the 3 GB memory
  cap per container.
- The harness checks that make a task `HARNESS_FAILED` before any model call, the attempt and
  task outcomes, and the definition of `PROVEN`: `arvo compile` exits 0, the PoC rerun exits 0
  with no sanitizer report, and, when the image has a seed corpus that ran clean on the control
  build, the fuzz target exits 0 with no sanitizer report on the same first 500 seed files.
- `PROVEN` is a mechanical result. It does not show the edit is the upstream fix, is complete,
  or is safe to merge. Every patch is proposed and proven offline, in local Docker containers
  that are deleted afterwards. Nothing is pushed, filed or posted to any project.
- The budget: Token Factory spend for run 2 stops at $3, by the same rule as run 1. Run 1 spent
  $0.073146 on 29 calls.

## What changes

### 1. Every compile starts from the state the control compile started from

Per task, after the pull and the start: the stored PoC runs on the shipped binary (the baseline),
the seed corpus is unpacked (change 2), and the container is committed with `docker commit` as
the snapshot `reproof-patch-<id>:clean`. The control compile, its PoC run and its seed run then
run in that same container, so the control compile starts from exactly the snapshot's files.
The files the baseline's frames name are read from it after the control build (change 3).

From then on, anything that reads the source for the model or compiles an edit runs in a fresh
container started from the snapshot, with the same 3 GB cap. The source shown to the model is
read from one. Each attempt that has edits to apply first replaces the container with a fresh
one, unless nothing but reads has run in the current container since it started. So every
attempt's `arvo compile` starts from the files the control compile started from, whatever the
build script made, moved or left behind, and without depending on any build script. The edited
files are still written back after each attempt, as in run 1, but nothing depends on it.

The card records the snapshot's image id (`snapshot_image`) and how many fresh containers were
started (`clean_containers`). The container, the snapshot and the image are removed after each
task.

### 2. The seed corpus is unpacked before the snapshot

Run 1 unpacked `/out/<fuzz target>_seed_corpus.zip` after the control compile. Run 2 unpacks the
zip the image ships, before the snapshot, so every container holds the same seed files. The seed
check itself is unchanged: the first 500 files sorted by path, run once each by the fuzz target,
first on the control build, and after a patch only when it ran clean on the control build.

### 3. Frames in files the build generates

A frame whose file does not exist in the snapshot, the source tree before the build, was named
in a file the build generated. In run 1 this is miniz 42536108 and 42536112: their crash frames
are in `/src/miniz/build/amalgamation/miniz.c`, which the build script writes into a `build`
directory and regenerates on every build. In run 1 the model was shown, and edited, that
generated file. The rule, fixed here before the run and applied the same way to every task:

- The harness takes the frame's line and up to 2 whole lines on each side of it from the file as
  the control build generated it.
- It lists the C and C++ source and header files under the source tree (`.c .cc .cpp .cxx .h .hh
  .hpp .hxx .inc`, at most 200, sorted by path) that contain the longest of those lines, and
  looks for the whole block, as whole lines, in them.
- If the block occurs exactly once across those files, the frame is shown from that file at the
  matching line, and its window header also names the generated file and line it was reported
  at. Its section, index and function are unchanged.
- Otherwise, or when the frame's file is in neither the source tree nor the build's output, the
  frame is skipped, a later frame of the same stack can take its place within the same limits (4
  crash frames, 2 allocation and 2 free frames), and the card's `frame_notes` say why.
- Frames whose files are in the source tree are chosen exactly as in run 1.
- An edit must still name a file that exists before the build, so the generated file itself
  cannot be edited.

### 4. Where it writes, and the command

`uv run reproof patch-eval` now runs run 2. It refuses to start if `reproof/` or this file has
uncommitted changes, or if run 2's result already exists, and records this file's SHA-256, its
commit, `HEAD` and `reproof.provenance.source_sha256()`. The report and the cards keep run 1's
format; the cards add `snapshot_image`, `clean_containers`, `frame_notes`, and, on a located
frame, `generated_path` and `generated_line`.

The run-1 post-hoc check of blocked attempts (`eval/annotate_patch_eval.py`) is applied unchanged
to run 2's cards and published as `eval/results/patch-eval-run2-notes.json`.

## If the harness process dies

As in run 1: rerun with `uv run reproof patch-eval --resume`. Cards already written are kept
unchanged and tasks without a card start from the beginning; a container or snapshot left by the
dead run is removed first. Any restart is reported with the result. This is not a second run.

## Headline

"N of 10 proven" for run 2, shown beside run 1's "2 of 10", with the attempt on which each was
proven, the model calls, the tokens, the Token Factory cost and the count of each other outcome,
and, for each proven task, the diff, the regression check that ran, and the upstream fix commit.

## Checks before registration (no model call)

`eval/check_patch_harness.py` ran on 2026-10-21 from 16:12 to 16:30 UTC on the harness at
`94e4967`, with no uncommitted changes, and wrote `eval/results/patch-harness-check.json`. It
made no model call. For each of the 10 images it ran the harness exactly as a scored task does up
to the first model call (`prepare_harness`, the run-1 harness checks, `build_source`), then the
attempt path (`apply_and_prove`) twice with a no-op edit: one exact-text edit whose new text equals
its old text, starting at the first chosen frame's line. The first attempt ran in the fresh
container the source had been read from and the second in a new one, so each image used 2 fresh
containers from its snapshot. When the image has a seed corpus, the fuzz target then ran
over it in the last attempt's container. The container, the snapshot and the image were removed
after each image.

| ARVO | Project | Control compile | The two attempt compiles | PoC after each | Seed corpus | Run 1 attempts stopped at mkdir |
|---|---|---|---|---|---|---|
| 42530604 | jq | exit 0, 41 s | exit 0, 38 s; exit 0, 39 s | crashed, Heap-buffer-overflow WRITE 1 | none | none |
| 42507851 | libplist | exit 0, 12 s | exit 0, 12 s; exit 0, 12 s | crashed, Heap-buffer-overflow READ 2 | 2 files, clean on both | none |
| 42496387 | wasm3 | exit 0, 5 s | exit 0, 4 s; exit 0, 4 s | crashed, Heap-use-after-free READ 8 | none | 1, 2, 3 |
| 42508524 | libplist | exit 0, 13 s | exit 0, 12 s; exit 0, 12 s | crashed, Heap-buffer-overflow READ 1 | 2 files, clean on both | none |
| 42536108 | miniz | exit 0, 8 s | exit 0, 6 s; exit 0, 7 s | crashed, Heap-buffer-overflow READ (any size) | 1 file, clean on both | 2, 3 |
| 42536112 | miniz | exit 0, 8 s | exit 0, 7 s; exit 0, 7 s | crashed, Heap-buffer-overflow READ (any size) | 1 file, clean on both | 1, 3 |
| 42508390 | libplist | exit 0, 12 s | exit 0, 12 s; exit 0, 12 s | crashed, Heap-buffer-overflow READ 2 | 2 files, clean on both | none |
| 42531297 | jq | exit 0, 39 s | exit 0, 39 s; exit 0, 38 s | crashed, Heap-buffer-overflow READ 2 | 19 files, clean on both | 2, 3 |
| 42531223 | jq | exit 0, 39 s | exit 0, 39 s; exit 0, 39 s | crashed, Stack-buffer-overflow WRITE 2 | none | none |
| 42476752 | libspng | exit 0, 28 s | exit 0, 27 s; exit 0, 27 s | crashed, Heap-buffer-overflow READ (any size) | 175 files, clean on both | 1, 2, 3 |

All 10 images: 20 of 20 attempt compiles exited 0, and in all 20 the stored PoC still crashed
the unpatched code with the baseline's crash type, so the attempt path reaches the PoC with an
untouched tree in every image, including the 5 whose build scripts stopped run 1. "Clean on
both" means the seed run exited 0 with no sanitizer report on the control build and again in the
last attempt's container. Each attempt compile takes about as long as the control compile,
because it starts from the tree the control compile started from instead of reusing the control
build's objects.

What else the check showed:

- The seed counts (0, 2, 0, 2, 1, 1, 2, 19, 0, 175) are the same as run 1's, which unpacked the
  zip after the control compile.
- For the 8 tasks without a generated file, the chosen frames are the same paths and lines as in
  run 1, and the source text shown to the model has the same length in characters as in run 1.
- Rule 3 applied to the two miniz tasks only, and located every frame it was given. 42536108:
  crash frames #1 `mz_zip_mem_read_func` (`miniz.c:4050`), #2 `mz_zip_reader_read_central_dir`
  (`miniz.c:3885`) and #3 `mz_zip_reader_init_mem` (`miniz.c:4079`) are shown from
  `/src/miniz/miniz_zip.c` lines 1036, 871 and 1065. 42536112: #1 `mz_zip_mem_read_func`
  (`miniz.c:4050`) and #2 `mz_zip_validate_file` (`miniz.c:5410`) from `/src/miniz/miniz_zip.c`
  lines 1036 and 2396. No frame was skipped in any image.

The two harness checks of run 1's registration (ARVO 42530604 with the upstream fix, and the
seed-corpus check of 42507851) used images whose build scripts run twice cleanly, which is why
they did not catch the defect. This check runs every image.
