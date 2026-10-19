"""Build the pinned public-status fallback preregistration for eval-100."""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reproof.arvo import ArvoRepository
from reproof.crash import parse_crash
from reproof.dup import OsvIndex
from reproof.eval100 import DEFAULT_PREREG, default_eval100_inputs, select_eval100

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "eval" / "public_status_prereg_100.json"


def _raw_osv_records(archive: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(archive) as bundle:
        for name in bundle.namelist():
            raw = json.loads(bundle.read(name))
            if isinstance(raw, dict) and isinstance(raw.get("id"), str):
                records[raw["id"]] = raw
    return records


def _first_github_git_range(raw: dict[str, Any]) -> tuple[str, str]:
    for affected in raw.get("affected") or []:
        for range_record in affected.get("ranges") or []:
            if range_record.get("type") != "GIT":
                continue
            parsed = urlparse(str(range_record.get("repo") or ""))
            if (parsed.hostname or "").lower() != "github.com":
                continue
            parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
            if len(parts) >= 2:
                return parts[0], parts[1]
    return "", ""


def build(prereg_path: Path, out_path: Path) -> dict[str, Any]:
    inputs = default_eval100_inputs()
    selection = select_eval100(prereg_path, inputs=inputs)
    repository = ArvoRepository(inputs.arvo_database)
    index = OsvIndex.from_archive(inputs.osv_archive, inputs.monorail_mapping)
    raw_by_id = _raw_osv_records(inputs.osv_archive)
    paid_ids = set(selection.historical_arvo_ids + selection.selected_new_arvo_ids[:40])
    rows: list[dict[str, Any]] = []
    for task_id in selection.selected_arvo_ids:
        task = repository.get(task_id)
        mapped = index.for_issue(task_id)
        if not mapped:
            raise ValueError(f"selected ARVO task {task_id} has no mapped OSV record")
        record = mapped[0]
        raw = raw_by_id.get(record.id)
        if raw is None:
            raise ValueError(f"mapped OSV record {record.id} is absent from the pinned archive")
        owner, repo = _first_github_git_range(raw)
        measured = parse_crash(task.crash_output)
        cohort = "historical" if task_id in selection.historical_arvo_ids else "draw"
        rows.append(
            {
                "set": cohort,
                "task_id": task_id,
                "project": task.project,
                "crash_type": measured.crash_type or task.crash_type,
                "frames": list(measured.state),
                "owner": owner,
                "repo": repo,
                "project_site": "",
                "fix_commits": list(record.fixed_commits),
                "osv_record_id": record.id,
                "label": (
                    "saved ARVO crash output and pinned OSS-Fuzz OSV record; no new sandbox run"
                ),
                "paid": task_id in paid_ids,
            }
        )
    if len(rows) != 100 or sum(bool(row["paid"]) for row in rows) != 50:
        raise ValueError("public-status eval-100 preregistration must contain 100 tasks, 50 paid")
    new_rows = rows[len(selection.historical_arvo_ids) :]
    missing_github = sum(not row["owner"] for row in new_rows)
    if missing_github != 11:
        raise ValueError(
            f"expected 11 new draw tasks without a GitHub GIT range, found {missing_github}"
        )
    payload = {
        "schema_version": "public-status-prereg-2",
        "registered_on": "2026-10-19",
        "seed": selection.seed,
        "source_eval100_prereg": {
            "path": str(prereg_path.resolve().relative_to(ROOT.resolve())).replace("\\", "/"),
            "sha256": selection.prereg_sha256,
        },
        "input_sha256": selection.expected_input_sha256,
        "task_order": (
            "the historical 10 in their committed order, followed by the 90 metadata-selected "
            "draw tasks in registered draw acceptance order"
        ),
        "paid_scope": "the historical 10 plus the first 40 accepted draw tasks",
        "baseline_scope": "all 100 tasks",
        "task_count": 100,
        "paid_task_count": 50,
        "batch_crawl": False,
        "ledger_starts_at_recorded_credits": 0,
        "tavily_credit_budget": 250,
        "max_tavily_credits_per_started_task": 5,
        "nemotron_call_budget": 200,
        "max_nemotron_calls_per_started_task": 12,
        "tasks": rows,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prereg", type=Path, default=ROOT / DEFAULT_PREREG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    payload = build(args.prereg, args.out)
    print(
        f"wrote {args.out} tasks={payload['task_count']} paid={payload['paid_task_count']} "
        f"credits={payload['tavily_credit_budget']} nemotron={payload['nemotron_call_budget']}"
    )


if __name__ == "__main__":
    main()
