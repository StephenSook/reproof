"""ASGI entry for one cached triage. Vercel loads the callable named app.

Local use: python -m reproof.door_asgi
The process listens on 127.0.0.1:8765 unless REPROOF_DOOR_HOST or REPROOF_DOOR_PORT is set.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from reproof.door import iter_cached_triage, scrub_text

MAX_BODY_BYTES = 65536
TRIAGE_PATH = "/api/triage"
HEALTH_PATH = "/api/health"
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class DoorHttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def _parse_arvo_id(body: bytes) -> int:
    if len(body) > MAX_BODY_BYTES:
        raise DoorHttpError(413, "request body is too large")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise DoorHttpError(400, "body must be JSON") from error
    if not isinstance(payload, dict) or "arvo_id" not in payload:
        raise DoorHttpError(400, "body must be a JSON object with arvo_id")
    value = payload["arvo_id"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise DoorHttpError(400, "arvo_id must be an integer")
    if value < 0:
        raise DoorHttpError(400, "arvo_id must be an integer")
    return value


def iter_triage_lines(arvo_id: int) -> Iterator[bytes]:
    """Yield one NDJSON line per door event. Lines are scrubbed."""

    for event in iter_cached_triage(arvo_id):
        raw = json.dumps(event, sort_keys=True, separators=(",", ":"))
        yield (scrub_text(raw) + "\n").encode("utf-8")


def dispatch(method: str, path: str, body: bytes) -> tuple[int, str, Iterator[bytes]]:
    """Return status, content type, and body chunks for one request."""

    if method == "GET" and path == HEALTH_PATH:
        return 200, "application/json; charset=utf-8", iter((_json_bytes({"ok": True}),))
    if method != "POST" or path != TRIAGE_PATH:
        message = _json_bytes({"error": "not found"})
        return 404, "application/json; charset=utf-8", iter((message,))
    try:
        arvo_id = _parse_arvo_id(body)
    except DoorHttpError as error:
        message = _json_bytes({"error": error.message})
        return error.status, "application/json; charset=utf-8", iter((message,))
    return (
        200,
        "application/x-ndjson; charset=utf-8",
        iter_triage_lines(arvo_id),
    )


async def _read_body(receive: Receive) -> bytes:
    chunks = bytearray()
    while True:
        message = await receive()
        chunks.extend(message.get("body", b""))
        if len(chunks) > MAX_BODY_BYTES:
            return bytes(chunks)
        if not message.get("more_body", False):
            return bytes(chunks)


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """ASGI application. The variable name is the Vercel entrypoint."""

    if scope.get("type") != "http":
        return
    method = str(scope.get("method", ""))
    path = str(scope.get("path", ""))
    body = await _read_body(receive) if method == "POST" else b""
    status, content_type, parts = dispatch(method, path, body)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    for part in parts:
        await send({"type": "http.response.body", "body": part, "more_body": True})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._respond("GET", b"")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            message = _json_bytes({"error": "request body is too large"})
            self._write(413, "application/json; charset=utf-8", iter((message,)))
            return
        body = self.rfile.read(length) if length else b""
        self._respond("POST", body)

    def _respond(self, method: str, body: bytes) -> None:
        status, content_type, parts = dispatch(method, self.path.split("?", 1)[0], body)
        self._write(status, content_type, parts)

    def _write(self, status: int, content_type: str, parts: Iterator[bytes]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for part in parts:
            if not part:
                continue
            self.wfile.write(f"{len(part):X}\r\n".encode("ascii"))
            self.wfile.write(part)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def log_message(self, fmt: str, *args: object) -> None:
        # Request lines only. Never log a body; it can carry nothing secret today,
        # and the next caller should not have to remember that.
        super().log_message(fmt, *args)


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"listening http://{host}:{port}", flush=True)
    server.serve_forever()


def main() -> None:
    host = os.environ.get("REPROOF_DOOR_HOST", "127.0.0.1")
    port = int(os.environ.get("REPROOF_DOOR_PORT", "8765"))
    serve(host, port)


if __name__ == "__main__":
    main()
