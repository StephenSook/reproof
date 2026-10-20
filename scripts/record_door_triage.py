"""Record one triage from the judge door as a receipt, byte for byte.

The door streams NDJSON from POST /api/triage. This script sends one request, keeps the raw
response body unchanged in <stem>.ndjson, and writes <stem>.json beside it with the request,
the HTTP status, the client-side timing, the SHA-256 of the raw body, and the parsed events.
tests/test_door_receipt.py checks that the two files still agree.

The request spends real Token Factory, ConTree and Tavily credit on the server that answers it.
No credential is read or sent by this script. It refuses to write a receipt whose body contains
the value of a credential variable set in this process.

Usage:
    uv run python scripts/record_door_triage.py --url https://reproof-web.vercel.app \
        --arvo 42530604 --out eval/results/door-42530604
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CREDENTIAL_NAMES = ("NEBIUS_API_KEY", "NEBIUS_PROJECT_ID", "TAVILY_API_KEY")
TIMEOUT_SECONDS = 180


def leaked_credentials(body: bytes, environ: dict[str, str]) -> list[str]:
    """Names of credential variables whose value appears in the body. Short values are skipped."""

    text = body.decode("utf-8", errors="replace")
    return [
        name
        for name in CREDENTIAL_NAMES
        if len(environ.get(name, "")) >= 8 and environ[name] in text
    ]


def parse_events(body: bytes) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in body.decode("utf-8").split("\n"):
        if line.strip():
            events.append(json.loads(line))
    return events


def record(url: str, arvo_id: int) -> tuple[dict[str, Any], bytes]:
    endpoint = url.rstrip("/") + "/api/triage"
    payload = json.dumps({"arvo_id": arvo_id}).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"content-type": "application/json", "user-agent": "reproof-receipt/1"},
        method="POST",
    )
    recorded_at = datetime.now(UTC)
    started = time.perf_counter()
    chunks: list[bytes] = []
    first_byte: float | None = None
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        status = response.status
        content_type = response.headers.get("content-type", "")
        while True:
            chunk = response.read(4096)
            if not chunk:
                break
            if first_byte is None:
                first_byte = time.perf_counter() - started
            chunks.append(chunk)
    elapsed = time.perf_counter() - started
    body = b"".join(chunks)
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "recorded_at_utc": recorded_at.isoformat(timespec="seconds"),
        "url": endpoint,
        "method": "POST",
        "request_body": {"arvo_id": arvo_id},
        "http_status": status,
        "content_type": content_type,
        "client_first_byte_seconds": round(first_byte or 0.0, 3),
        "client_elapsed_seconds": round(elapsed, 3),
        "recorder": "scripts/record_door_triage.py",
        "ndjson_bytes": len(body),
        "ndjson_sha256": hashlib.sha256(body).hexdigest(),
    }
    return receipt, body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True, help="door origin, for example https://host")
    parser.add_argument("--arvo", required=True, type=int)
    parser.add_argument("--out", required=True, help="output stem; .json and .ndjson are added")
    args = parser.parse_args(argv)

    receipt, body = record(args.url, args.arvo)
    leaked = leaked_credentials(body, dict(os.environ))
    if leaked:
        print(f"refusing to write: the body contains {', '.join(leaked)}", file=sys.stderr)
        return 3
    stem = Path(args.out)
    stem.parent.mkdir(parents=True, exist_ok=True)
    receipt["ndjson_path"] = stem.with_suffix(".ndjson").as_posix()
    # The raw body is written before anything parses it, so a bad line cannot lose a paid run.
    stem.with_suffix(".ndjson").write_bytes(body)
    receipt["events"] = parse_events(body) if receipt["http_status"] == 200 else []
    stem.with_suffix(".json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"status {receipt['http_status']}, {receipt['ndjson_bytes']} bytes, "
        f"{len(receipt['events'])} events, {receipt['client_elapsed_seconds']} s"
    )
    return 0 if receipt["http_status"] == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
