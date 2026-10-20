# Eval-100 run 2: plan, committed before the run starts

Written 2026-10-20 before run 2 starts. This file was committed in `0383504` at
2026-10-20T05:57:19Z (01:57:19 ET) and pushed before the run began, so its commit time is
earlier than the run's first card.

Correction added after the run started: an earlier draft of this line said "about 02:05 ET",
which was wrong. The first launch at 01:57:34 ET exited at startup, before any task ran,
because `REPROOF_CACHE_DIR` was not set and the OSV archive was not found. Run 2 was relaunched
at 01:58:01 ET with `REPROOF_CACHE_DIR` set to the same shared cache run 1 used
(`reproof/app/.cache/reproof`), which holds the pinned OSV archive and the ConTree checkpoint
registry.

## What happened in run 1

Run 1 used the registered selection in `eval/eval100_prereg.json` (SHA-256
`e774c26140ad82d46f039e73d7a8051013801f740c4a636c3d6e3eb6ce6bb675`) and ran from 00:37 to
01:15 ET on 2026-10-20. Its report is `eval/results/eval100.json` and its cards are in
`eval/results/eval100_cards/`. Both are committed exactly as the run wrote them and will not
be edited or deleted.

- 50 of 100 tasks completed.
- 49 tasks failed with `APIConnectionError` or `APITimeoutError` from Token Factory claim
  extraction. They are the last 49 tasks in run order (positions 52 to 100). Every one failed
  twice, the second time a few seconds after the first, between 01:09 and 01:15 ET. A chat call
  to the same endpoint succeeded at 01:53 ET. Whether the cause was the endpoint or this
  machine's network is not established.
- 1 task (ARVO 42533590, gpac) failed because ConTree SDK 0.3.6 decodes command output as
  strict UTF-8 and the crash output held a 0xff byte.
- Under the registered rule (one transport retry, then RUN_FAILED) all 50 failures stand for
  run 1.

## What changes for run 2

Two code changes, both on this branch before this file:

1. `64b5357` asks ConTree for raw bytes and decodes them with replacement characters.
2. `35cd8ba` holds the one transport retry until Token Factory answers a model listing,
   probing every 30 seconds for at most 20 minutes. It adds no retry. A task that fails
   twice is still RUN_FAILED.

Run 2 execution source SHA-256 (`reproof.provenance.source_sha256`):
`3c1fa93ebc87b9e47131f498b5c10cfdc0e5c02c5163553bfbc6c3b034c458e7`.

## Run 2 rules

- Same registration file, same 100 selected ARVO IDs, same prepare ledger
  (`eval/results/eval100_prep.json`, SHA-256
  `6d15d27cc99c7b30317eadb2a52ddc563ae0d554753ac23125d1eacb15653709`).
- Every task runs again from the start. No run 1 card is reused. Cached ConTree checkpoints
  from run 1 may be reused. A cache hit is charged zero construction cost and its original
  cost is kept as historical metadata, the same rule run 1 ran under, so run 2's total cost
  is lower than a cold run would be.
- Output: `eval/results/eval100-run2.json` and `eval/results/eval100-run2-cards/`.
- Command: `uv run reproof eval --prereg eval/eval100_prereg.json --output
  eval/results/eval100-run2.json --cards-dir eval/results/eval100-run2-cards`
- Run 2 is committed and published whatever it shows.
- Run 2 is the result quoted in the submission, with run 1 shown beside it and linked. That
  choice is made here, before any run 2 result exists.
- No run 3 before the submission deadline. If run 2 loses tasks, they stay failures and the
  denominator stays 100.
