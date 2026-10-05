"""Create cached ConTree checkpoints and run disposable ARVO branches."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from contree_sdk import ContreeSync
from contree_sdk.sdk.exceptions import NotFoundError
from contree_sdk.utils.models.file import UploadFileSpec

from reproof.models import SandboxOperation

BASE_IMAGE = "python:3.12-slim"


class CheckpointError(RuntimeError):
    """Report every identifier recovered while preparing a checkpoint."""

    def __init__(
        self,
        message: str,
        *,
        kind: str,
        operation_uuid: str | None,
        checkpoint_uuid: str | None,
        request_id: str | None,
    ) -> None:
        super().__init__(message)
        self.operation_uuid = operation_uuid
        self.operation_uuids = {kind: operation_uuid} if operation_uuid else {}
        self.checkpoint_uuids = {kind: checkpoint_uuid} if checkpoint_uuid else {}
        self.checkpoint_operation_uuids = {kind: operation_uuid} if operation_uuid else {}
        self.request_id = request_id
        self.request_ids = [request_id] if request_id else []


class SandboxPairError(RuntimeError):
    """Preserve every operation identifier captured before a parallel failure."""

    def __init__(
        self,
        message: str,
        *,
        operation_uuids: dict[str, str],
        checkpoint_uuids: dict[str, str],
        checkpoint_operation_uuids: dict[str, str],
        request_ids: list[str],
    ) -> None:
        super().__init__(message)
        self.operation_uuids = operation_uuids
        self.checkpoint_uuids = checkpoint_uuids
        self.checkpoint_operation_uuids = checkpoint_operation_uuids
        self.request_ids = request_ids
        self.operation_uuid = next(iter(operation_uuids.values()), None)
        self.request_id = request_ids[0] if request_ids else None


def _request_id_from_error(error: BaseException) -> str | None:
    request_id = getattr(error, "request_id", None)
    if request_id:
        return str(request_id)
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if headers:
        return headers.get("x-request-id") or headers.get("request-id")
    return None


def default_registry_path() -> Path:
    cache = Path(os.getenv("REPROOF_CACHE_DIR", ".cache/reproof")).expanduser().resolve()
    return cache / "checkpoints.json"


def manifest_digest(slice_dir: Path) -> str:
    manifest = slice_dir / "manifest.json"
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


class CheckpointRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (path or default_registry_path()).resolve()

    def read(self) -> dict[str, dict[str, Any]]:
        if not self.path.is_file():
            return {}
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"checkpoint registry must contain a JSON object: {self.path}")
        return value

    def write(self, value: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True), encoding="utf-8", newline="\n"
        )
        os.replace(temporary, self.path)


class SandboxRunner:
    def __init__(
        self,
        client: ContreeSync | None = None,
        registry: CheckpointRegistry | None = None,
    ) -> None:
        self.client = client or ContreeSync()
        self.registry = registry or CheckpointRegistry()
        self.checkpoint_metadata: dict[str, dict[str, Any]] = {}

    def ensure_checkpoint(self, task_id: int, kind: str, slice_dir: Path) -> Any:
        digest = manifest_digest(slice_dir)
        key = f"{task_id}:{kind}:{digest}"
        registry = self.registry.read()
        cached = registry.get(key)
        if cached:
            try:
                checkpoint = self.client.images.use(cached["checkpoint_uuid"], strict=True)
                self.checkpoint_metadata[str(checkpoint.uuid)] = {
                    "operation_uuid": cached.get("create_operation_uuid"),
                    "wall_seconds": float(cached.get("checkpoint_wall_seconds", 0.0)),
                    "cost_usd": float(cached.get("checkpoint_cost_usd", 0.0)),
                    "cache_hit": True,
                }
                return checkpoint
            except NotFoundError as lookup_error:
                del registry[key]
                try:
                    self.registry.write(registry)
                except Exception as registry_error:
                    raise CheckpointError(
                        "Stale checkpoint registry cleanup failed: "
                        f"{type(registry_error).__name__}: {registry_error}",
                        kind=kind,
                        operation_uuid=str(cached.get("create_operation_uuid") or "") or None,
                        checkpoint_uuid=str(cached.get("checkpoint_uuid") or "") or None,
                        request_id=_request_id_from_error(lookup_error),
                    ) from registry_error
            except Exception as error:
                raise CheckpointError(
                    f"ConTree cached checkpoint lookup failed: {type(error).__name__}: {error}",
                    kind=kind,
                    operation_uuid=str(cached.get("create_operation_uuid") or "") or None,
                    checkpoint_uuid=str(cached.get("checkpoint_uuid") or "") or None,
                    request_id=_request_id_from_error(error),
                ) from error

        manifest = json.loads((slice_dir / "manifest.json").read_text(encoding="utf-8"))
        files = {
            remote_path: UploadFileSpec(
                source=slice_dir / record["relative_path"],
                path=remote_path,
                mode=int(record["mode"]),
            )
            for remote_path, record in manifest["files"].items()
        }
        try:
            base = self.client.images.use(BASE_IMAGE, strict=True)
        except Exception as error:
            raise CheckpointError(
                f"ConTree base image lookup failed: {type(error).__name__}: {error}",
                kind=kind,
                operation_uuid=None,
                checkpoint_uuid=None,
                request_id=_request_id_from_error(error),
            ) from error
        create_operation_uuid: str | None = None
        checkpoint_uuid: str | None = None
        internal = base.client
        original_start = internal._start_operation

        async def capture_create(request: Any) -> Any:
            nonlocal create_operation_uuid
            operation_id = await original_start(request)
            create_operation_uuid = str(operation_id)
            return operation_id

        internal._start_operation = capture_create
        checkpoint_started = time.perf_counter()
        try:
            checkpoint = base.apply_files(files)
            checkpoint_uuid = str(checkpoint.uuid)
            checkpoint_wall_seconds = time.perf_counter() - checkpoint_started
            checkpoint_cost_usd = float(checkpoint.result.cost)
            tag = f"reproof-{task_id}-{kind}-{digest[:12]}"
            checkpoint = checkpoint.tag_as(tag)
        except Exception as error:
            raise CheckpointError(
                f"ConTree checkpoint creation failed: {type(error).__name__}: {error}",
                kind=kind,
                operation_uuid=create_operation_uuid,
                checkpoint_uuid=checkpoint_uuid,
                request_id=_request_id_from_error(error),
            ) from error
        finally:
            internal._start_operation = original_start
        registry[key] = {
            "checkpoint_uuid": str(checkpoint.uuid),
            "tag": tag,
            "manifest_sha256": digest,
            "create_operation_uuid": create_operation_uuid,
            "checkpoint_wall_seconds": round(checkpoint_wall_seconds, 6),
            "checkpoint_cost_usd": checkpoint_cost_usd,
        }
        try:
            self.registry.write(registry)
        except Exception as error:
            raise CheckpointError(
                f"Checkpoint registry persistence failed: {type(error).__name__}: {error}",
                kind=kind,
                operation_uuid=create_operation_uuid,
                checkpoint_uuid=str(checkpoint.uuid),
                request_id=_request_id_from_error(error),
            ) from error
        self.checkpoint_metadata[str(checkpoint.uuid)] = {
            "operation_uuid": create_operation_uuid,
            "wall_seconds": round(checkpoint_wall_seconds, 6),
            "cost_usd": checkpoint_cost_usd,
            "cache_hit": False,
        }
        return checkpoint

    def run_pair(
        self,
        task_id: int,
        vulnerable_checkpoint: Any,
        fixed_checkpoint: Any,
        candidate_input: bytes | None = None,
    ) -> tuple[SandboxOperation, SandboxOperation]:
        checkpoints = {"vul": vulnerable_checkpoint, "fix": fixed_checkpoint}
        operation_ids: dict[str, str] = {}
        originals: dict[int, tuple[Any, Callable[..., Any]]] = {}
        for checkpoint in checkpoints.values():
            internal = checkpoint.client
            if id(internal) in originals:
                continue
            original = internal._start_operation

            async def capture(request: Any, _original: Callable[..., Any] = original) -> Any:
                operation_id = await _original(request)
                operation_ids[str(request.hostname)] = str(operation_id)
                return operation_id

            originals[id(internal)] = (internal, original)
            internal._start_operation = capture

        env = {
            "PATH": "/out:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "ASAN_SYMBOLIZER_PATH": "/out/llvm-symbolizer",
        }
        prepared: dict[str, Any] = {}
        hostnames: dict[str, str] = {}
        try:
            for kind, checkpoint in checkpoints.items():
                hostname = f"reproof-{task_id}-{kind}-{time.time_ns()}"
                hostnames[kind] = hostname
                files = None
                if candidate_input is not None:
                    files = {
                        "/tmp/poc": UploadFileSpec(
                            source=candidate_input,
                            path="/tmp/poc",
                            mode=0o644,
                        )
                    }
                prepared[kind] = checkpoint.run(
                    "/bin/bash",
                    args=["/bin/arvo-contree"],
                    env=env,
                    hostname=hostname,
                    files=files,
                    timeout=600,
                    disposable=True,
                    truncate_output_at=10 * 1024 * 1024,
                )

            def wait_one(kind: str) -> tuple[str, Any, float]:
                started = time.perf_counter()
                try:
                    result = prepared[kind].wait()
                except Exception as error:
                    operation_id = getattr(error, "operation_uuid", None)
                    if operation_id:
                        operation_ids[hostnames[kind]] = str(operation_id)
                    raise
                return kind, result, time.perf_counter() - started

            results: dict[str, SandboxOperation] = {}
            wait_errors: list[Exception] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(wait_one, kind) for kind in ("vul", "fix")]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        kind, result, elapsed = future.result()
                    except Exception as error:
                        wait_errors.append(error)
                        continue
                    stdout = str(result.stdout or "")
                    stderr = str(result.stderr or "")
                    checkpoint_metadata = self.checkpoint_metadata.get(
                        str(checkpoints[kind].uuid), {}
                    )
                    results[kind] = SandboxOperation(
                        task_id=task_id,
                        kind=kind,
                        checkpoint_uuid=str(checkpoints[kind].uuid),
                        checkpoint_operation_uuid=checkpoint_metadata.get("operation_uuid"),
                        checkpoint_wall_seconds=float(checkpoint_metadata.get("wall_seconds", 0.0)),
                        checkpoint_cost_usd=float(checkpoint_metadata.get("cost_usd", 0.0)),
                        operation_uuid=operation_ids.get(hostnames[kind]),
                        exit_code=int(result.exit_code),
                        stdout=stdout,
                        stderr=stderr,
                        wall_seconds=round(elapsed, 6),
                        server_elapsed_seconds=round(result.elapsed.total_seconds(), 6),
                        cost_usd=float(result.result.cost),
                        disposable=True,
                    )
            if wait_errors:
                checkpoint_operations = {
                    kind: str(metadata["operation_uuid"])
                    for kind, checkpoint in checkpoints.items()
                    if (metadata := self.checkpoint_metadata.get(str(checkpoint.uuid), {})).get(
                        "operation_uuid"
                    )
                }
                request_ids = list(
                    dict.fromkeys(
                        request_id
                        for error in wait_errors
                        if (request_id := _request_id_from_error(error)) is not None
                    )
                )
                raise SandboxPairError(
                    "; ".join(f"{type(error).__name__}: {error}" for error in wait_errors),
                    operation_uuids={
                        kind: operation_ids[hostname]
                        for kind, hostname in hostnames.items()
                        if hostname in operation_ids
                    },
                    checkpoint_uuids={
                        kind: str(checkpoint.uuid) for kind, checkpoint in checkpoints.items()
                    },
                    checkpoint_operation_uuids=checkpoint_operations,
                    request_ids=request_ids,
                )
            return results["vul"], results["fix"]
        except SandboxPairError:
            raise
        except Exception as error:
            captured = {
                kind: operation_ids[hostname]
                for kind, hostname in hostnames.items()
                if hostname in operation_ids
            }
            checkpoints_by_kind = {
                kind: str(checkpoint.uuid) for kind, checkpoint in checkpoints.items()
            }
            checkpoint_operations = {
                kind: str(metadata["operation_uuid"])
                for kind, checkpoint in checkpoints.items()
                if (metadata := self.checkpoint_metadata.get(str(checkpoint.uuid), {})).get(
                    "operation_uuid"
                )
            }
            request_id = _request_id_from_error(error)
            raise SandboxPairError(
                f"ConTree parallel run failed: {type(error).__name__}: {error}",
                operation_uuids=captured,
                checkpoint_uuids=checkpoints_by_kind,
                checkpoint_operation_uuids=checkpoint_operations,
                request_ids=[request_id] if request_id is not None else [],
            ) from error
        finally:
            for internal, original in originals.values():
                internal._start_operation = original
