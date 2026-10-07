# Reproof facts

This is the source for numbers and technical claims used in the README, Devpost writeup, and demo video narration. Each fact names its evidence and status.

## What Reproof does

Reproof reads a public security report, extracts its claims, runs the reported input against vulnerable and fixed builds in disposable ConTree branches, parses sanitizer evidence, searches OSV for duplicate crash states, checks public status with Tavily and GitHub ancestry, and returns a triage card for a maintainer. A human makes the filing or disclosure decision; Reproof does not file upstream.

## ARVO 10 evaluation

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Requested ARVO tasks | `10` | `eval/results/arvo10.json#totals.tasks_requested` | MEASURED |
| Completed ARVO tasks | `10` | `eval/results/arvo10.json#totals.tasks_completed` | MEASURED |
| Verdict counts | `6 REPRODUCED; 4 DUPLICATE` | PowerShell `Group-Object` over `eval/results/arvo10.json` task verdicts; output `DUPLICATE=4; REPRODUCED=6` | MEASURED |
| Fixed builds that completed cleanly | `10` | `eval/results/arvo10.json#totals.fixes_clean` | MEASURED |
| Claims that agreed with measured bug class and top crash function | `10` | `eval/results/arvo10.json#totals.claims_agree` | MEASURED |
| Crash states that agreed with the mapped OSV state | `7` | `eval/results/arvo10.json#totals.crash_state_agreements` | MEASURED |
| Independent duplicate candidates returned | `4` | `eval/results/arvo10.json#totals.total_duplicate_candidates` | MEASURED |
| Nemotron input tokens | `1349` | `eval/results/arvo10.json#totals.total_input_tokens` | MEASURED |
| Nemotron output tokens | `1125` | `eval/results/arvo10.json#totals.total_output_tokens` | MEASURED |
| Nemotron cost in US dollars | `0.0014172` | `eval/results/arvo10.json#totals.total_model_cost_usd` | MEASURED |
| ConTree checkpoint and sandbox cost in US dollars | `0.00775084` | `eval/results/arvo10.json#totals.total_sandbox_cost_usd` | MEASURED |
| Combined evaluation cost in US dollars | `0.00916804` | `eval/results/arvo10.json#totals.total_cost_usd` | MEASURED |
| Summed per-task wall time in seconds | `40.709021` | `eval/results/arvo10.json#totals.total_wall_seconds` | MEASURED |

## Public status evaluation

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Pre-registration date | `2026-10-05` | `eval/public_status_prereg.json#registered_on` | MEASURED |
| Sampling seed | `20261005` | `eval/public_status_prereg.json#seed` | MEASURED |
| Pre-registered set sizes | `A=10; B=30` | PowerShell array counts from `eval/public_status_prereg.json`; output `set_a_arvo10=10; set_b_osv30=30` | MEASURED |
| Batch crawl setting | `false` | `eval/public_status_prereg.json#batch_crawl` | MEASURED |
| Pre-registered Tavily credit budget | `200` | `eval/public_status_prereg.json#tavily_credit_budget` | MEASURED |
| Pre-registered Nemotron call budget | `120` | `eval/public_status_prereg.json#nemotron_call_budget` | MEASURED |
| Set A tasks run | `10` | `eval/results/public_status.json#tavily_summary.by_set.A.ran` | MEASURED |
| Set A tasks with a verified reference | `3` | `eval/results/public_status.json#tavily_summary.by_set.A.with_verified_reference` | MEASURED |
| Set A tasks with no public findings | `7` | `eval/results/public_status.json#tavily_summary.by_set.A.no_public_findings` | MEASURED |
| Set A Tavily credits | `46` | `eval/results/public_status.json#tavily_summary.by_set.A.tavily_credits` | MEASURED |
| Set A Tavily calls | `28` | PowerShell count of every Set A `tasks[].tavily_calls` array in `eval/results/public_status.json`; output `20 search; 8 extract; 0 crawl; 28 total` | MEASURED |
| Set A Nemotron calls | `16` | `eval/results/public_status.json#tavily_summary.by_set.A.model_calls` | MEASURED |
| Set A rejected pages and snippets | `frame=22; host=10; snippet=1; quote=2; unrelated=0; source_file=5` | PowerShell key read from `eval/results/public_status.json`; output matches the value | MEASURED |
| Set A summed latency in seconds | `85.535945` | `eval/results/public_status.json#tavily_summary.by_set.A.latency_seconds` | MEASURED |
| Set B tasks run | `30` | `eval/results/public_status.json#tavily_summary.by_set.B.ran` | MEASURED |
| Set B tasks with a verified reference | `2` | `eval/results/public_status.json#tavily_summary.by_set.B.with_verified_reference` | MEASURED |
| Set B tasks with no public findings | `28` | `eval/results/public_status.json#tavily_summary.by_set.B.no_public_findings` | MEASURED |
| Set B Tavily credits | `128` | `eval/results/public_status.json#tavily_summary.by_set.B.tavily_credits` | MEASURED |
| Set B Tavily calls | `74` | PowerShell count of every Set B `tasks[].tavily_calls` array in `eval/results/public_status.json`; output `60 search; 14 extract; 0 crawl; 74 total` | MEASURED |
| Set B Nemotron calls | `38` | `eval/results/public_status.json#tavily_summary.by_set.B.model_calls` | MEASURED |
| Set B rejected pages and snippets | `frame=33; host=49; snippet=65; quote=2; unrelated=0; source_file=39` | PowerShell key read from `eval/results/public_status.json`; output matches the value | MEASURED |
| Set B summed latency in seconds | `299.08624` | `eval/results/public_status.json#tavily_summary.by_set.B.latency_seconds` | MEASURED |
| Verified Tavily evidence pages across both sets | `7` | `eval/results/public_status.json#tavily_summary.evidence_pages` | MEASURED |
| Tavily-only evidence pages | `5` | PowerShell URL set difference between `tasks[].evidence` and `baseline[].references` in `eval/results/public_status.json`; output `wasm3 issue 458; jq releases; nDPI commit 412ca87; PHP issues 18844 and 14969` | MEASURED |
| Tavily calls across both sets | `102` | PowerShell count of every `tasks[].tavily_calls` array in `eval/results/public_status.json`; output `80 search; 22 extract; 0 crawl; 102 total` | MEASURED |
| Tavily credits charged by this run | `174` | `eval/results/public_status.json#tavily_credits_this_run` | MEASURED |
| Recorded Tavily credits before this run | `7` | `eval/results/public_status.json#ledger_start_credits` | MEASURED |
| Tavily ledger credits after this run | `181` | `eval/results/public_status.json#tavily_credits_used_including_recorded` | MEASURED |
| Nemotron calls across both sets | `54` | `eval/results/public_status.json#nemotron_calls` | MEASURED |
| Baseline verified references across both sets | `3` | `eval/results/public_status.json#baseline_verified_references` | MEASURED |
| Baseline frame rejections across both sets | `257` | `eval/results/public_status.json#baseline_frame_rejected` | MEASURED |
| Baseline host rejections across both sets | `36` | `eval/results/public_status.json#baseline_host_rejected` | MEASURED |
| Baseline Set A result | `3 references; 82 frame rejects; 14 host rejects; 42.719854 seconds` | PowerShell sums over Set A `baseline` rows in `eval/results/public_status.json`; output matches the value | MEASURED |
| Baseline Set B result | `0 references; 175 frame rejects; 22 host rejects; 180.699298 seconds` | PowerShell sums over Set B `baseline` rows in `eval/results/public_status.json`; output matches the value | MEASURED |

## Advisory rescore

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Rescore Tavily calls | `0` | `eval/results/advisory_rescore.json#tavily_calls` | MEASURED |
| Rescore Nemotron calls | `0` | `eval/results/advisory_rescore.json#nemotron_calls` | MEASURED |
| Rescore GitHub API calls | `5` | PowerShell count of `eval/results/advisory_rescore.json` `github_api_urls`; output `5` | MEASURED |
| Rescore outcomes | `1 PUBLICLY_KNOWN_FIXED; 4 NOT_CHECKABLE` | PowerShell `Group-Object` over `eval/results/advisory_rescore.json` row states; output `NOT_CHECKABLE=4; PUBLICLY_KNOWN_FIXED=1` | MEASURED |
| Fixed rescore task | `42530604` | `eval/results/advisory_rescore.json#rows[2].task_id` | MEASURED |
| Fixed rescore role | `baseline` | `eval/results/advisory_rescore.json#rows[2].role` | MEASURED |
| Fixed rescore advisory | `GHSA-686w-5m7m-54vc` | `eval/results/advisory_rescore.json#rows[2].ghsa_id` | MEASURED |
| Fixed rescore version | `1.7.1` | `eval/results/advisory_rescore.json#rows[2].usable_versions[0]` | MEASURED |
| Fixed rescore tag | `jq-1.7.1` | `eval/results/advisory_rescore.json#rows[2].tag` | MEASURED |
| Fixed rescore comparison | `identical` | `eval/results/advisory_rescore.json#rows[2].compare_status` | MEASURED |
| Fixed rescore ancestry | `CONTAINS_FIX` | `eval/results/advisory_rescore.json#rows[2].ancestry` | MEASURED |
| Fixed rescore public state | `PUBLICLY_KNOWN_FIXED` | `eval/results/advisory_rescore.json#rows[2].state` | MEASURED |

## Live

These values are only for the two recorded runs named in the source column.

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Curl triage verdict | `REPRODUCED` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Curl public status | `PUBLICLY_KNOWN_FIXED` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Curl public-status card line | `Fixed in jq 1.7.1. Git ancestry: tag jq-1.7.1 contains OSV fix 71c2ab5.` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Curl Tavily request ids | `2f8216d4-b08e-42ab-a56b-89cbba228098, 6c7a310d-91fd-4ad1-b701-1c470e8aaca3, d2c783b6-cffd-4183-a66b-5b7c319dbe32` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Curl Tavily credits | `5` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Curl total cost in US dollars | `0.00163346` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Curl elapsed time in seconds | `9.2` | Main-session live curl of `https://reproof-web.vercel.app/api/triage`, recorded `2026-10-06 06:28 UTC` | LIVE |
| Browser triage elapsed time in seconds | `15.7` | Main-session browser triage, recorded `2026-10-06 near 18:00 UTC` | LIVE |
| Browser triage state | `REPRODUCED; PUBLICLY_KNOWN_FIXED` | Main-session browser triage, recorded `2026-10-06 near 18:00 UTC` | LIVE |

## Tests and CI

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Ruff format check | `47 files already formatted` | `uv run ruff format --check .`; output `47 files already formatted`; run `2026-10-07` | MEASURED |
| Ruff lint check | `0 findings` | `uv run ruff check .`; output `All checks passed!`; run `2026-10-07` | MEASURED |
| Mypy check | `0 issues in 21 source files` | `uv run mypy reproof`; output `Success: no issues found in 21 source files`; run `2026-10-07` | MEASURED |
| Non-live pytest check | `241 passed; 3 deselected; 1 warning` | `uv run pytest -m "not live"`; output summary `241 passed, 3 deselected, 1 warning`; run `2026-10-07` | MEASURED |
| CI workflow jobs | `test; web` | `.github/workflows/ci.yml:7-42` | MEASURED |
| Live probe workflow job | `probe` | `.github/workflows/live.yml:15-38` | MEASURED |

## Models and services

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Nemotron model id | `nvidia/nemotron-3-super-120b-a12b` | `reproof/claims.py:18` and the call at `reproof/claims.py:105-106`; `reproof/public_model.py:20-24,293-295,342-344` reuses it | MEASURED |
| Token Factory OpenAI-compatible base URL | `https://api.tokenfactory.nebius.com/v1/` | `reproof/claims.py:19,101` | MEASURED |
| ConTree SDK version | `contree-sdk==0.3.6` | `pyproject.toml:14` | MEASURED |
| ConTree client and checkpoint lookup | `ContreeSync; images.use` | `reproof/sandbox.py:110-124,163-165,243-245` | MEASURED |
| ConTree checkpoint creation | `apply_files; tag_as` | `reproof/sandbox.py:175-192` | MEASURED |
| ConTree vulnerable and fixed execution | `checkpoint.run with disposable=true` | `reproof/sandbox.py:269-321` | MEASURED |
| Tavily SDK version | `tavily-python==0.8.4` | `pyproject.toml:18` | MEASURED |
| Tavily API operations | `search; extract; crawl` | `reproof/public_tavily.py:407-416,480-490,618-626,672-681` | MEASURED |
| GitHub tag-list endpoint | `/repos/{owner}/{repo}/tags?per_page=100&page={page}` | `reproof/public_status.py:301-307` | MEASURED |
| GitHub compare endpoint | `/repos/{owner}/{repo}/compare/{base}...{head}` | `reproof/public_status.py:317-326` | MEASURED |
| GitHub single-advisory endpoint | `/repos/{owner}/{repo}/security-advisories/{ghsa_id}` | `reproof/public_status.py:338-348` | MEASURED |
| GitHub advisory-list endpoint used by the evaluation baseline | `/repos/{owner}/{repo}/security-advisories?per_page=100&page={page}&state=published` | `eval/run_public_status.py:331-332` | MEASURED |

## Judge door limits

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Concurrent triages per visitor | `1` | `reproof/assets/limits.json#in_flight_per_visitor` | MEASURED |
| Triage starts per address per hour | `8` | `reproof/assets/limits.json#per_ip_per_hour` | MEASURED |
| Triage starts per server instance per day | `60` | `reproof/assets/limits.json#global_per_day` | MEASURED |
| Tavily credits per server instance per UTC day | `100` | `reproof/assets/limits.json#tavily_credits_per_day` | MEASURED |
| Public-status reuse window in seconds | `3600` | `reproof/assets/limits.json#public_reuse_seconds` | MEASURED |
| Limits schema version | `1` | `reproof/assets/limits.json#schema_version` | MEASURED |
| Limits file constant | `reproof/assets/limits.json` | `reproof/door_limits.py:20-22` | MEASURED |
| Visitor cookie name | `reproof_visitor` | `reproof/door_limits.py:23` | MEASURED |
| In-flight lease in seconds | `180` | `reproof/door_limits.py:24` | MEASURED |
| Lock wait in seconds | `5.0` | `reproof/door_limits.py:25` | MEASURED |
| Stale lock age in seconds | `30.0` | `reproof/door_limits.py:26` | MEASURED |

## Drift found

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| The README live example and the dated curl record are different executions with different total costs | `README=0.00090867 USD; 2026-10-06 curl=0.00163346 USD` | `README.md:466-473`; main-session live curl record from `2026-10-06 06:28 UTC` | LIVE |
| Required ARVO, public-status, advisory-rescore, model, service, and limit values that disagree with their primary repo sources | `0` | Manual comparison of the required README fields against the cited JSON and code sources on `2026-10-07` | MEASURED |

## Do not claim

| Claim | Exact value | Source | Tag |
|---|---:|---|---|
| Time saved for a real maintainer | `NOT VERIFIED` | Verify with a timed study of maintainers using Reproof and their normal triage process | NOT VERIFIED |
| Any real maintainer has used Reproof on an incoming report | `NOT VERIFIED` | Verify with consented usage records or a maintainer interview tied to a recorded run | NOT VERIFIED |
| Accuracy on security reports outside the evaluated ARVO tasks | `NOT VERIFIED` | Verify on a pre-registered external report set with labelled outcomes | NOT VERIFIED |
| Accuracy on public-status records outside the evaluated OSV records | `NOT VERIFIED` | Verify on a pre-registered external record set with labelled public status | NOT VERIFIED |
| A global spend ceiling across Vercel instances | `NOT VERIFIED` | Verify only after adding a shared cross-instance budget store and testing concurrent instances against the account ledger | NOT VERIFIED |
