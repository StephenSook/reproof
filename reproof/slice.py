"""Extract a runnable ARVO runtime slice from a stopped Docker container."""

from __future__ import annotations

import hashlib
import io
import json
import os
import posixpath
import shutil
import subprocess
import tarfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from elftools.elf.elffile import ELFFile

NEW_INTERPRETER = "/arvo/ld.so"
LIBRARY_DIRS = (
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/local/lib",
    "/lib64",
    "/lib",
    "/usr/lib64",
    "/usr/lib",
)


@dataclass(frozen=True, slots=True)
class FileMeasurement:
    bytes: int
    sha256: str


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def measure(path: Path) -> FileMeasurement:
    return FileMeasurement(bytes=path.stat().st_size, sha256=sha256(path))


def elf_interpreter(path: Path) -> str:
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_INTERP":
                return str(segment.get_interp_name())
    raise ValueError(f"ELF file has no PT_INTERP segment: {path}")


def elf_needed(path: Path) -> tuple[str, ...]:
    needed: list[str] = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_DYNAMIC":
                continue
            for tag in segment.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(str(tag.needed))
    return tuple(dict.fromkeys(needed))


def patch_interpreter(path: Path, new_interpreter: str = NEW_INTERPRETER) -> tuple[str, str]:
    old_interpreter = elf_interpreter(path)
    old_bytes = old_interpreter.encode() + b"\0"
    new_bytes = new_interpreter.encode() + b"\0"
    if len(new_bytes) > len(old_bytes):
        raise ValueError(
            f"new PT_INTERP is longer than existing field: {new_interpreter} > {old_interpreter}"
        )
    binary = path.read_bytes()
    occurrences = binary.count(old_bytes)
    if occurrences != 1:
        raise ValueError(
            f"expected one PT_INTERP byte sequence in {path}, "
            f"found {occurrences}: {old_interpreter}"
        )
    replacement = new_bytes.ljust(len(old_bytes), b"\0")
    path.write_bytes(binary.replace(old_bytes, replacement, 1))
    if elf_interpreter(path) != new_interpreter:
        raise ValueError(f"PT_INTERP verification failed for {path}")
    return old_interpreter, new_interpreter


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, capture_output=True, text=True)


def _resolve_container_path(container_id: str, source: str) -> str:
    current = PurePosixPath(source)
    for _ in range(16):
        command = ["docker", "cp", f"{container_id}:{current}", "-"]
        result = subprocess.run(command, check=False, capture_output=True)
        if result.returncode != 0:
            error = result.stderr.decode(errors="replace").strip()
            raise FileNotFoundError(
                f"docker cp metadata read failed for {current}: exit {result.returncode}: {error}"
            )
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r|*") as archive:
            member = next(iter(archive), None)
        if member is None:
            raise FileNotFoundError(f"docker cp returned an empty archive for {current}")
        if not (member.issym() or member.islnk()):
            return str(current)
        link = PurePosixPath(member.linkname)
        if link.is_absolute():
            current = link
        else:
            current = PurePosixPath(posixpath.normpath(str(current.parent / link)))
    raise RuntimeError(f"too many symlinks while resolving container path: {source}")


def _copy_from_container(container_id: str, source: str, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    resolved_source = _resolve_container_path(container_id, source)
    result = _run(
        ["docker", "cp", f"{container_id}:{resolved_source}", str(destination)],
        check=False,
    )
    if result.returncode != 0:
        raise FileNotFoundError(
            f"docker cp failed for {source}: exit {result.returncode}: {result.stderr.strip()}"
        )
    return resolved_source


def _copy_library(container_id: str, name: str, destination: Path) -> str:
    errors: list[str] = []
    for directory in LIBRARY_DIRS:
        source = f"{directory}/{name}"
        try:
            return _copy_from_container(container_id, source, destination)
        except FileNotFoundError as error:
            errors.append(str(error))
    raise FileNotFoundError(
        f"could not resolve ELF dependency {name}; tried {', '.join(LIBRARY_DIRS)}; "
        f"last error: {errors[-1] if errors else 'none'}"
    )


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n"
    )
    os.replace(temporary, path)


def validated_cached_manifest(
    destination: Path,
    *,
    task_id: int,
    kind: str,
    image: str,
    fuzz_target: str,
) -> dict[str, Any] | None:
    manifest_path = destination / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("task_id") != task_id
        or manifest.get("kind") != kind
        or manifest.get("image") != image
        or manifest.get("fuzz_target") != fuzz_target
        or manifest.get("docker_image_deleted") is not True
        or "docker_image_delete_error" in manifest
        or not manifest.get("files")
    ):
        return None
    for record in manifest.get("files", {}).values():
        local_path = destination / record["relative_path"]
        if not local_path.is_file():
            return None
        patched = record.get("patched")
        if not isinstance(patched, dict) or asdict(measure(local_path)) != patched:
            return None
    return manifest


def extract_runtime_slice(
    task_id: int,
    kind: str,
    fuzz_target: str,
    slices_root: Path = Path("slices"),
) -> dict[str, Any]:
    if kind not in {"vul", "fix"}:
        raise ValueError(f"invalid ARVO image kind: {kind}")
    tag = f"{task_id}-{kind}"
    image = f"n132/arvo:{tag}"
    destination = slices_root.resolve() / tag
    cached = validated_cached_manifest(
        destination,
        task_id=task_id,
        kind=kind,
        image=image,
        fuzz_target=fuzz_target,
    )
    if cached is not None:
        print(f"Using cached runtime slice {destination}")
        return cached

    inspect = _run(["docker", "image", "inspect", image], check=False)
    if inspect.returncode != 0:
        raise FileNotFoundError(
            f"local Docker image is required before slicing: {image}: {inspect.stderr.strip()}"
        )
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    container = _run(["docker", "create", image]).stdout.strip()
    cleanup_error: str | None = None
    extraction_error: BaseException | None = None
    sources: dict[str, str] = {}
    transformations: dict[str, dict[str, Any]] = {}
    try:
        initial = {
            "/bin/arvo": destination / "bin" / "arvo",
            "/tmp/poc": destination / "tmp" / "poc",
            f"/out/{fuzz_target}": destination / "out" / fuzz_target,
        }
        for remote_path, local_path in initial.items():
            sources[remote_path] = _copy_from_container(container, remote_path, local_path)

        symbolizer = destination / "out" / "llvm-symbolizer"
        symbolizer_errors: list[str] = []
        for candidate in ("/out/llvm-symbolizer", "/usr/local/bin/llvm-symbolizer"):
            try:
                sources["/out/llvm-symbolizer"] = _copy_from_container(
                    container, candidate, symbolizer
                )
                break
            except FileNotFoundError as error:
                symbolizer_errors.append(str(error))
        else:
            raise FileNotFoundError(
                "llvm-symbolizer was not found at either supported ARVO path; "
                + "; ".join(symbolizer_errors)
            )
        initial["/out/llvm-symbolizer"] = symbolizer

        target = initial[f"/out/{fuzz_target}"]
        original_interpreter = elf_interpreter(target)
        loader = destination / "arvo" / "ld.so"
        sources["/arvo/ld.so"] = _copy_from_container(container, original_interpreter, loader)

        pending = list(elf_needed(target) + elf_needed(symbolizer))
        resolved: set[str] = set()
        while pending:
            library = pending.pop(0)
            if library in resolved:
                continue
            local_library = destination / "arvo-lib" / library
            source = _copy_library(container, library, local_library)
            resolved.add(library)
            sources[f"/arvo-lib/{library}"] = source
            pending.extend(name for name in elf_needed(local_library) if name not in resolved)

        for binary in (target, symbolizer):
            remote_path = next(key for key, value in initial.items() if value == binary)
            before = measure(binary)
            old_interpreter, new_interpreter = patch_interpreter(binary)
            after = measure(binary)
            transformations[remote_path] = {
                "kind": "pt_interp",
                "old_interpreter": old_interpreter,
                "new_interpreter": new_interpreter,
                "original": asdict(before),
                "patched": asdict(after),
            }

        wrapper = destination / "bin" / "arvo-contree"
        original_wrapper = initial["/bin/arvo"].read_text(encoding="utf-8")
        target_call = f"/out/{fuzz_target} /tmp/poc"
        target_call_count = original_wrapper.count(target_call)
        if target_call_count < 1:
            raise ValueError("ARVO wrapper did not contain the expected target call")
        wrapper_before = measure(initial["/bin/arvo"])
        wrapper.write_text(
            original_wrapper.replace(target_call, f"LD_LIBRARY_PATH=/arvo-lib {target_call}"),
            encoding="utf-8",
            newline="\n",
        )
        wrapper_after = measure(wrapper)
        sources["/bin/arvo-contree"] = "/bin/arvo"
        transformations["/bin/arvo-contree"] = {
            "kind": "wrapper_ld_library_path",
            "target_call_replacements": target_call_count,
            "original": asdict(wrapper_before),
            "patched": asdict(wrapper_after),
        }
    except BaseException as error:
        extraction_error = error
        raise
    finally:
        removal = _run(["docker", "rm", container], check=False)
        if removal.returncode != 0:
            message = (
                f"docker rm {container} failed with exit {removal.returncode}: "
                f"{removal.stderr.strip()}"
            )
            if extraction_error is not None:
                extraction_error.add_note(message)
            else:
                cleanup_error = message
    if cleanup_error:
        raise RuntimeError(cleanup_error)

    files: dict[str, dict[str, Any]] = {}
    for remote_path, source in sources.items():
        if remote_path == "/bin/arvo-contree":
            local_path = destination / "bin" / "arvo-contree"
        else:
            local_path = destination / remote_path.lstrip("/")
        current = measure(local_path)
        transformation = transformations.get(remote_path)
        files[remote_path] = {
            "source_image_path": source,
            "relative_path": str(local_path.relative_to(destination)).replace("\\", "/"),
            "original": transformation["original"] if transformation else asdict(current),
            "patched": transformation["patched"] if transformation else asdict(current),
            "transformation": transformation["kind"] if transformation else "none",
            "mode": 0o644 if remote_path == "/tmp/poc" else 0o755,
        }

    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "task_id": task_id,
        "kind": kind,
        "image": image,
        "fuzz_target": fuzz_target,
        "created_at": datetime.now(UTC).isoformat(),
        "extraction_commands": ["docker create", "docker cp", "docker rm"],
        "container_run_used": False,
        "files": files,
        "docker_image_deleted": False,
    }
    manifest_path = destination / "manifest.json"
    _atomic_json(manifest_path, manifest)

    deletion = _run(["docker", "image", "rm", image], check=False)
    if deletion.returncode != 0:
        manifest["docker_image_delete_error"] = {
            "exit_code": deletion.returncode,
            "stderr": deletion.stderr.strip(),
        }
        _atomic_json(manifest_path, manifest)
        raise RuntimeError(
            f"slice written but Docker image deletion failed for {image}: "
            f"exit {deletion.returncode}: {deletion.stderr.strip()}"
        )
    manifest["docker_image_deleted"] = True
    _atomic_json(manifest_path, manifest)
    remaining_tag = _run(["docker", "image", "inspect", image], check=False)
    if remaining_tag.returncode == 0:
        raise RuntimeError(f"Docker image tag still exists after deletion: {image}")
    print(f"Removed local Docker image tag {image} after writing {manifest_path}")
    return manifest
