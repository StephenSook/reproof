"""Command-line interface for Reproof."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reproof.door_data import ASSETS_DIR, build_door_assets
from reproof.eval_prepare import run_eval_prepare
from reproof.evaluation import run_eval
from reproof.evaluation100 import DEFAULT_EVAL100_OUTPUT, run_eval100
from reproof.patch_eval import run_patch_eval
from reproof.triage import run_triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reproof")
    commands = parser.add_subparsers(dest="command", required=True)

    triage = commands.add_parser("triage", help="triage one ARVO task")
    triage.add_argument("--arvo", type=int, required=True)
    triage.add_argument("--report", type=Path)
    triage.add_argument("--output", type=Path)

    evaluate = commands.add_parser("eval", help="run the deterministic ARVO evaluation")
    selection = evaluate.add_mutually_exclusive_group()
    selection.add_argument("--n", type=int)
    selection.add_argument("--prereg", type=Path)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--cards-dir", type=Path)
    evaluate.add_argument(
        "--resume",
        action="store_true",
        help="reuse strict per-task cards from an interrupted eval",
    )

    prepare = commands.add_parser("eval-prepare", help="prepare the registered eval-100 images")
    prepare.add_argument("--prereg", type=Path, required=True)
    prepare.add_argument("--ledger", type=Path, required=True)
    prepare.add_argument(
        "--stop-after-prepared",
        type=int,
        help="stop after this many prepared tasks for a bounded smoke run",
    )

    door_data = commands.add_parser(
        "door-data",
        help="build the committed checkpoint manifest and project OSV index",
    )
    door_data.add_argument("--checkpoints", type=Path, required=True)
    door_data.add_argument("--archive", type=Path, required=True)
    door_data.add_argument("--mapping", type=Path, required=True)
    door_data.add_argument("--eval", type=Path, default=Path("eval/results/arvo10.json"))
    door_data.add_argument("--output", type=Path)
    door_data.add_argument("--arvo-db", type=Path)
    door_data.add_argument("--slices", type=Path)
    door_data.add_argument("--cards", type=Path)

    patch = commands.add_parser(
        "patch-eval",
        help="run the registered offline patch evaluation (needs Docker; see eval/PATCH-PREREG.md)",
    )
    patch.add_argument("--resume", action="store_true", help="keep task cards already written")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "triage":
            report_text = args.report.read_text(encoding="utf-8") if args.report else None
            card = run_triage(
                args.arvo,
                report_text=report_text,
                report_source=(f"local report file {args.report}" if args.report else None),
                output_path=args.output,
            )
            print(card.model_dump_json(indent=2))
        elif args.command == "eval-prepare":
            ledger = run_eval_prepare(
                args.prereg,
                args.ledger,
                stop_after_prepared=args.stop_after_prepared,
            )
            print(ledger.model_dump_json(indent=2))
        elif args.command == "door-data":
            summary = build_door_assets(
                checkpoints=args.checkpoints,
                archive=args.archive,
                mapping=args.mapping,
                evaluation=args.eval,
                output=args.output or ASSETS_DIR,
                arvo_db=args.arvo_db,
                slices=args.slices,
                cards=args.cards,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
        elif args.command == "patch-eval":
            patch_report = run_patch_eval(resume=args.resume)
            print(json.dumps(patch_report.get("totals", {}), indent=2, sort_keys=True))
        elif args.prereg is not None:
            eval100_report = run_eval100(
                args.prereg,
                args.output or DEFAULT_EVAL100_OUTPUT,
                cards_dir=args.cards_dir or Path("eval/results/cards100"),
                resume=args.resume,
            )
            print(eval100_report.model_dump_json(indent=2))
        else:
            if args.cards_dir is not None:
                raise ValueError("--cards-dir requires --prereg")
            legacy_report = run_eval(
                args.n if args.n is not None else 10,
                args.output or Path("eval/results/arvo10.json"),
                resume=args.resume,
            )
            print(legacy_report.model_dump_json(indent=2))
    except Exception as error:
        operation_id = getattr(error, "operation_uuid", None)
        operation_ids = getattr(error, "operation_uuids", None)
        checkpoint_ids = getattr(error, "checkpoint_uuids", None)
        checkpoint_operation_ids = getattr(error, "checkpoint_operation_uuids", None)
        request_id = getattr(error, "request_id", None)
        request_ids = getattr(error, "request_ids", None)
        print(
            f"ERROR {type(error).__name__}: {error}; "
            f"operation_uuid={operation_id}; "
            f"operation_uuids={json.dumps(operation_ids, sort_keys=True)}; "
            f"checkpoint_uuids={json.dumps(checkpoint_ids, sort_keys=True)}; "
            f"checkpoint_operation_uuids="
            f"{json.dumps(checkpoint_operation_ids, sort_keys=True)}; "
            f"request_id={request_id}; request_ids={json.dumps(request_ids)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
