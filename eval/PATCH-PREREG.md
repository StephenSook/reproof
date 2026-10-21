# Offline patch evaluation: registration

Written 2026-10-21 and committed before the first scored run. The result is published whatever
it shows, in `eval/results/patch-eval.json`, one card per task in `eval/results/patch-cards/`, and
its own section on the `/proof` page. There is no tuning and rerun to improve the number.

## Question

Given a crash report, the sanitizer output and the source around the crash, can Nemotron 3 Super
write a source edit that the ARVO image itself proves: the project rebuilds, the stored
proof-of-concept input no longer crashes, and the fuzz target still runs on its seed corpus when
the image has one? Code decides success, never the model.

This is offline only. The judge door cannot rebuild: its runtime slices carry the fuzz binary,
the PoC and the loader, not the compiler or `/src`. A local spike on 2026-10-20, whose notes are
not committed, found that, and found that all three Nemotron unified diffs it asked for on ARVO
42530604 were rejected by `git apply`; this evaluation asks for exact-text edits instead.

## Tasks

The 10 historical ARVO tasks, in the order of `selection.historical_arvo_ids` in
`eval/eval100_prereg.json`: 42530604, 42507851, 42496387, 42508524, 42536108, 42536112,
42508390, 42531297, 42531223, 42476752. The denominator is 10 whatever happens to any task.

## Code and command

`reproof/patch_eval.py` at the commit that adds this file, run as `uv run reproof patch-eval`.
The run refuses to start if `reproof/` or this file has uncommitted changes, and records this
file's SHA-256, its commit, `HEAD`, and `reproof.provenance.source_sha256()`.

## Per task

1. Pull `n132/arvo:<id>-vul` only. One image on disk at a time.
2. Start it as a container running `sleep infinity`, memory capped at 3 GB.
3. Baseline: run `arvo` (the stored PoC on the shipped fuzz binary).
4. Harness control: `arvo compile` on the untouched tree, then `arvo` again. Before every
   compile, this one and each attempt's, the fuzz target binary in `/out` is deleted, so the PoC can
   only run on a binary that compile produced. A compile that exits 0 without producing it counts as
   a failed compile.
5. Seed corpus: if `/out/<fuzz target>_seed_corpus.zip` exists, unpack it and run the fuzz target
   over the first 500 files (sorted by path) on the control build.
6. The task is `HARNESS_FAILED`, and no model call is made, if the pull or the container start
   fails, the baseline shows no parsed sanitizer report, the control compile exits non-zero, or the
   rebuilt untouched binary does not crash on the PoC. It counts as not proven in the 10.

## What the model gets

- System prompt: `SYSTEM_PROMPT` in `reproof/patch_eval.py`, verbatim.
- One user message with the project and its source tree (the image's working directory), the OSV
  report text from `reproof/assets/catalog.json`, the baseline's parsed sanitizer report (at most
  6,000 characters), and source windows: up to 4 frames from the crash stack and up to 2 from each
  of the allocated and freed stacks, keeping only files under the source tree that are not fuzz
  harness, test or build files, and skipping a frame whose file and function an earlier chosen
  frame already has. Each window runs from 80 lines before the frame's line to 40 after, counting
  lines on newline characters only; overlapping windows in one file are merged; windows are added
  in frame order up to 40,000 characters. The text is the file's own text, carriage returns
  included, with a header naming the path and line range.
- Model `nvidia/nemotron-3-super-120b-a12b` on Nebius Token Factory, temperature 0, `max_tokens`
  4,096, thinking disabled, and a strict JSON schema: `rationale` and 1 to 4 `edits`, each with
  `path`, `old_text` and `new_text`.

## Edits and attempts

- An edit applies only if its path is absolute, inside the source tree, not a fuzz harness, test
  or build file, exists in the image, and its `old_text` is non-empty and occurs exactly once.
  Edits apply in order. One refused edit refuses the whole reply (`APPLY_FAILED`).
- An attempt writes the edited files, runs `arvo compile` (30-minute limit), runs `arvo` (5-minute
  limit), and, when the image has a seed corpus that ran clean on the control build, runs the fuzz
  target over the same seeds (15-minute limit). Every edited file is then put back byte for byte.
  Every attempt starts from the original tree.
- N = 3 attempts per task, fixed before the run.
- After a failed attempt, the next call carries the whole conversation: the first message, each
  earlier reply, and what happened to it. That is the apply errors; or up to 20 error lines and the
  last 40 lines of the build log; or the new sanitizer report; or the PoC exit code and its last 40
  lines; or the seed run's last 40 lines.
- A connection error, timeout or HTTP 5xx from Token Factory is retried once after 30 seconds
  inside the same attempt, and the client makes no retries of its own. A second failure is
  `MODEL_ERROR` and uses the attempt.
- If the harness itself fails inside an attempt (for example a file write in the container), that
  attempt is recorded as `HARNESS_ERROR` with its model call and cost, and the task ends
  `HARNESS_FAILED`.

## Success

`PROVEN` means all of these, measured in the container:

1. `arvo compile` exits 0.
2. The PoC rerun exits 0 with no sanitizer report.
3. If the image has a seed corpus that ran clean on the control build, the fuzz target exits 0
   with no sanitizer report on those seeds. Without one, check 2 is the only run, and the card
   says so.

## Failures

Attempt outcomes: `MODEL_ERROR` (no reply, a reply that is not valid for the schema, or a reply
that did not end with `finish_reason=stop`), `APPLY_FAILED`, `COMPILE_FAILED`, `STILL_CRASHES`
(a parsed sanitizer report on the PoC rerun), `POC_NOT_CLEAN` (non-zero exit or time limit
without a parsed report), `REGRESSION` (the seed run fails), `HARNESS_ERROR`. Edited text that
cannot be written back as UTF-8 is `APPLY_FAILED`.

Task outcomes: `PROVEN`, `NOT_PROVEN` (3 attempts, none proven), `HARNESS_FAILED`,
`BUDGET_STOPPED`.

## What PROVEN does not mean

It is a mechanical result. It does not show the edit is the upstream fix, is complete, or is safe
to merge. Each card shows the diff, and the upstream fix commit from the task's OSV record, so a
person can compare them. Every patch is proposed and proven offline, in a local Docker container
that is deleted afterwards. Nothing is pushed, filed or posted to any project.

## Headline

"N of 10 proven", the attempt on which each was proven, the model calls, the Token Factory cost,
and the count of each other outcome.

## Budget

Token Factory spend for this evaluation stops at $3. Before each call, if the spend has reached
$3, no call is made. The current task keeps the attempts it already made (`NOT_PROVEN`, with the
stop noted, or `BUDGET_STOPPED` if it made none), and every later task is `BUDGET_STOPPED` without
pulling its image. Expected spend is far lower: about 10,000 input and at most 4,096 output tokens
per call is under $0.01, and 30 calls are under $0.30.

## Before registration (not scored)

- One schema smoke call on a made-up five-line C function, not one of the 10 tasks: request
  `7f252b8fc901610f215a181e8c0869e5`, 326 input and 175 output tokens, $0.0002553. The strict
  schema was accepted.
- One harness check with no model call: ARVO 42530604 with the `src/jv.c` line of upstream fix
  `71c2ab5` written as an edit. It was `PROVEN` in 128 s: the pull took 49 s, the PoC crashed the
  shipped binary (`Heap-buffer-overflow WRITE 1`), `arvo compile` of the untouched tree exited 0
  in 44 s and its binary still crashed, the edited tree compiled in 30 s, and the PoC then exited
  0 with no sanitizer report. The image has no seed corpus. The container and image were removed.
- One check of the seed-corpus path with no compile and no model call: ARVO 42507851 (libplist).
  `/out/jplist_fuzzer_seed_corpus.zip` unpacked to 2 files and the shipped fuzz target ran both
  and exited 0. The image was removed.
- The three unified-diff calls of the 2026-10-20 spike ($0.0043365) are not part of this
  evaluation.

## If the harness process dies

Rerun with `uv run reproof patch-eval --resume`. Cards already written are kept unchanged and
tasks without a card start from the beginning; a container left by the dead run is removed first.
Any restart is reported with the result.

## Review before registration

A code review of `reproof/patch_eval.py` against this file, before it was committed, found five
problems, all fixed before this commit: a container left by a dead run would have blocked
`--resume`; an exception inside an attempt dropped that attempt's record and cost; line numbers
were counted with `str.splitlines()`, which also splits on form feeds; the frame selection's
file-and-function rule was not written here; and the OpenAI client's own two retries would have
run on top of the registered single retry. The stale-binary guard in step 4 came from the same
review. The harness checks above ran before these fixes; the compile guard was then checked in a
throwaway container (compile exits 0 with the target built: 0; exits 0 without it: 99; exits 2:
2), and the ARVO 42530604 harness check was run again on the fixed code, still with no model call:
`PROVEN` in 118 s (control compile 44 s, edited compile 28 s), image removed.
