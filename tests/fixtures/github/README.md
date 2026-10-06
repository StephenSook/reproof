# GitHub API fixtures

| File | Label | What it is |
|---|---|---|
| `RECORDED-advisory-GHSA-686w-5m7m-54vc.json` | RECORDED | `GET /repos/jqlang/jq/security-advisories/GHSA-686w-5m7m-54vc` on 2026-10-06. HTTP 200. `response` is that body. |
| `RECORDED-compare-jq-1.7.1-71c2ab5.json` | RECORDED | `GET /repos/jqlang/jq/compare/jq-1.7.1...71c2ab509a8628dbbad4bc7b3f98a64aa90d3297` on 2026-10-06. HTTP 200. `response` is that body. |
| `HAND-BUILT-advisory-stale.json` | HAND-BUILT | Not a GitHub response. No recorded jq advisory was checked as a patched version that misses its own OSV fix, so the stale-version test uses this body. No compare body is invented here. |

Whitespace in the recorded files comes from `json.dumps` of the parsed response. The field values are the API values.
