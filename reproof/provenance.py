"""Content hashes that bind saved evidence to its inputs and implementation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from reproof.arvo import ArvoTask


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def text_sha256(value: str) -> str:
    return bytes_sha256(value.encode())


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_sha256() -> str:
    digest = hashlib.sha256()
    source_root = Path(__file__).resolve().parent
    for path in sorted(source_root.glob("*.py")):
        relative = path.name.encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def derivation_source_sha256(refresh_script: Path | None = None) -> str:
    """Bind saved-output derivation to package code and the refresh program."""

    script = (
        refresh_script or Path(__file__).resolve().parents[1] / "scripts" / "refresh_eval_cards.py"
    )
    content = script.read_bytes()
    digest = hashlib.sha256()
    digest.update(b"reproof-source-sha256")
    digest.update(bytes.fromhex(source_sha256()))
    label = b"scripts/refresh_eval_cards.py"
    digest.update(len(label).to_bytes(8, "big"))
    digest.update(label)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
    return digest.hexdigest()


def arvo_task_sha256(task: ArvoTask) -> str:
    payload = json.dumps(asdict(task), sort_keys=True, separators=(",", ":")).encode()
    return bytes_sha256(payload)
