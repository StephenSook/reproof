# Hosting fit

Measured on 2026-10-05 on this Windows PC. Nothing in this file was deployed.

## What was measured

A new virtual environment, outside the repo, on CPython 3.12.15. `uv` installed the runtime dependencies from `pyproject.toml` and not the dev group:

- clusterfuzz==2.6.0
- contree-sdk==0.3.6
- openai==2.54.0
- pyelftools==0.33
- pydantic==2.13.5

`uv` resolved 68 packages. mypy, pytest, and ruff were not installed.

The import timed in a fresh process was `import reproof.door`, with `PYTHONPATH` set to this repo. `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID` were removed from that process. The timer starts immediately before the import and stops when the import returns. It does not include process startup.

## Size

Uncompressed `site-packages` before that import: 166,596,774 bytes, 6,065 files. 15,345 of those bytes were already `.pyc`.

`reproof` Python source at the same moment: 149,830 bytes, 15 files. Committed assets: 52,451 bytes.

Sum: 166,799,055 bytes (159.1 MB). That is the deployable tree this measurement is willing to claim: installed runtime packages, plus the package source, plus the committed assets.

Largest directories inside `site-packages`:

| Path | Bytes |
| --- | --- |
| googleapiclient | 112,192,982 |
| grpc | 12,685,253 |
| google | 7,161,055 |
| openai | 6,220,123 |
| pydantic_core | 5,370,197 |
| clusterfuzz | 4,344,407 |
| setuptools | 2,722,956 |
| pydantic | 1,773,212 |

`googleapiclient` is a dependency of clusterfuzz. contree-sdk is in the same total and is smaller than this list.

After the three import processes below, a second walk of the same `site-packages` found 31,835,064 bytes of `.py` files and 141,832,374 bytes of everything else, 173,667,438 bytes in total. The tree grew by 7,070,664 bytes. Those bytes are bytecode written by the import. Vercel also compiles Python to bytecode and includes `.pyc` when space allows. This measurement did not compile every `.py` file. The `.py` files are 31,835,064 bytes, so a second copy of each of them would add about 32 MB. 166.8 MB plus 32 MB is still under 200 MB.

`reproof/door_asgi.py` was added after this size walk. It is source only. It does not add a dependency.

## Cold import

Three fresh processes, in order:

| Process | Seconds | Bytecode on disk |
| --- | --- | --- |
| 1 | 3.615514 | almost none (15,345 bytes of `.pyc` already in the tree) |
| 2 | 1.708923 | bytecode left by process 1 |
| 3 | 1.619702 | bytecode left by process 1 |

Only 3.615514 seconds is a cold import. The later two are the same import after bytecode was written. This is a local interpreter import. It is not a cold start of a Vercel function. No deployment was made, so a platform cold start was not measured.

## Limits that were read

These pages were fetched on 2026-10-05:

- [Vercel Functions limits](https://vercel.com/docs/functions/limitations), last updated 2026-08-24. Fluid compute. Uncompressed bundle 250 MB, or 500 MB for Python. Hobby duration is 300 seconds default and maximum. Pro and Enterprise default is 300 seconds, maximum 800 seconds. Duration includes streamed responses. Request body and response body are each 4.5 MB. Memory on Hobby is 2 GB and 1 vCPU. File descriptors are 1,024 shared. `includeFiles` and `excludeFiles` are not supported inside Next.js.
- [Python runtime](https://vercel.com/docs/functions/runtimes/python), last updated 2026-08-12. An ASGI callable must be named `app`. `tool.vercel.entrypoint` is `module:variable`. Python 3.12 is the default. `uv` installs from `pyproject.toml`. There is no tree-shaking. Bytecode is included when space allows. Streaming is on by default. A Python backend and another framework go together through Services. `excludeFiles` is a glob relative to the project root, under the `functions` key.
- [Services](https://vercel.com/docs/services), last updated 2026-08-10. Services are in beta on all plans. `services` in `vercel.json` builds each root separately. A top-level rewrite with `destination.service` exposes a service. With `services` present, `functions` and `framework` move into the service. The entrypoint example is `main:app`.
- [Service configuration](https://vercel.com/docs/services/config-reference), last updated 2026-06-30. `root` is required. `entrypoint` and `functions` are per service.
- [Services routing](https://vercel.com/docs/services/routing), last updated 2026-06-30. The service receives the original path. `POST /api/triage` arrives as `/api/triage`.

This account's plan was not queried. The choice uses the Hobby column, which is the tighter published duration.

## Choice

A Vercel Python function, in the same project as the Next.js app, using Services. Not a container.

166,799,055 bytes is under the 250 MB general limit and under the 500 MB Python limit. The local cold import is 3.6 seconds. The slowest saved triage wall in `eval/results/arvo10.json` is 4.976644 seconds. `maxDuration` is 120 seconds, which is under the Hobby maximum of 300 seconds.

`reproof/sandbox.py` calls the sandbox with `timeout=600`. That is longer than 120 seconds. A sandbox that hangs until that client timeout will be cut off by the platform. This configuration does not claim the hung run can finish.

The public routes are `POST /api/triage` and `GET /api/health` on the Python service, and every other path on the Next.js service rooted at `web/`. The judge door in `web/` is a separate change. `vercel.json` excludes `web/`, tests, slices, caches, and virtual environments from the Python function bundle so the function does not pick up the frontend.

No Dockerfile. Clusterfuzz stays, because the crash parser depends on it, and the size still fits.
