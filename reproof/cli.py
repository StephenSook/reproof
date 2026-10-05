"""Command-line interface for Reproof."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reproof.evaluation import run_eval
from reproof.triage import run_triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reproof")
    commands = parser.add_subparsers(dest="command", required=True)

    triage = commands.add_parser("triage", help="triage one ARVO task")
    triage.add_argument("--arvo", type=int, required=True)
    triage.add_argument("--report", type=Path)
    triage.add_argument("--output", type=Path)

    evaluate = commands.add_parser("eval", help="run the deterministic ARVO evaluation")
    evaluate.add_argument("--n", type=int, default=10)
    evaluate.add_argument("--output", type=Path, default=Path("eval/results/arvo10.json"))
    evaluate.add_argument(
        "--resume",
        action="store_true",
        help="reuse strict per-task cards from an interrupted eval",
    )
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
        else:
            report = run_eval(args.n, args.output, resume=args.resume)
            print(report.model_dump_json(indent=2))
    except Exception as error:
        operation_id = getattr(error, "operation_uuid", None)
        operation_ids = getattr(error, "operation_uuids", None)
        request_id = getattr(error, "request_id", None)
        print(
            f"ERROR {type(error).__name__}: {error}; "
            f"operation_uuid={operation_id}; "
            f"operation_uuids={json.dumps(operation_ids, sort_keys=True)}; "
            f"request_id={request_id}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
