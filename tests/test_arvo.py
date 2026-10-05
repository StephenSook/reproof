from __future__ import annotations

import sqlite3
from pathlib import Path

from reproof.arvo import ArvoRepository


def test_arvo_repository_reads_task(tmp_path: Path) -> None:
    database = tmp_path / "arvo.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            create table arvo (
                localId integer primary key, project text, fuzz_target text,
                crash_type text, crash_output text, fix_commit text, report text,
                language text, sanitizer text, fuzz_engine text
            )
            """
        )
        connection.execute(
            "insert into arvo values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (7, "demo", "fuzzer", "Heap-overflow", "trace", "abc", None, "c", "asan", "libfuzzer"),
        )
    task = ArvoRepository(database).get(7)
    assert task.project == "demo"
    assert task.fix_commit == "abc"
