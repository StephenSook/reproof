"""Read public task metadata from the ARVO SQLite table."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ArvoTask:
    local_id: int
    project: str
    fuzz_target: str
    crash_type: str
    crash_output: str
    fix_commit: str | None
    report: str | None
    language: str
    sanitizer: str
    fuzz_engine: str


def default_database_path() -> Path:
    configured = os.getenv("REPROOF_ARVO_DB")
    if configured:
        return Path(configured).expanduser().resolve()
    app_root = Path(__file__).resolve().parents[1]
    candidates = (
        app_root / "data" / "arvo.db",
        app_root.parent / "spike" / "data" / "arvo.db",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(
        "ARVO database not found. Set REPROOF_ARVO_DB or place arvo.db at one of: " + searched
    )


class ArvoRepository:
    def __init__(self, database: Path | None = None) -> None:
        self.database = (database or default_database_path()).resolve()
        if not self.database.is_file():
            raise FileNotFoundError(f"ARVO database not found: {self.database}")

    def get(self, local_id: int) -> ArvoTask:
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                select localId, project, fuzz_target, crash_type, crash_output,
                       fix_commit, report, language, sanitizer, fuzz_engine
                from arvo where localId = ?
                """,
                (local_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"ARVO task not found: {local_id}")
        required = ("fuzz_target", "crash_type", "crash_output", "language")
        missing = [name for name in required if not row[name]]
        if missing:
            raise ValueError(
                f"ARVO task {local_id} is missing required fields: {', '.join(missing)}"
            )
        return ArvoTask(
            local_id=int(row["localId"]),
            project=str(row["project"]),
            fuzz_target=str(row["fuzz_target"]),
            crash_type=str(row["crash_type"]),
            crash_output=str(row["crash_output"]),
            fix_commit=str(row["fix_commit"]) if row["fix_commit"] else None,
            report=str(row["report"]) if row["report"] else None,
            language=str(row["language"]),
            sanitizer=str(row["sanitizer"]),
            fuzz_engine=str(row["fuzz_engine"]),
        )

    def public_rows(self) -> list[tuple[int, str]]:
        with sqlite3.connect(self.database) as connection:
            rows = connection.execute(
                "select localId, project from arvo order by localId"
            ).fetchall()
        return [(int(local_id), str(project)) for local_id, project in rows]
