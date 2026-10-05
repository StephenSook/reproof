from __future__ import annotations

from pathlib import Path

import pytest

from reproof.arvo import ArvoRepository
from reproof.claims import MODEL, PRICE_SOURCE, extract_claim
from reproof.crash import is_conclusive_crash, looks_clean, parse_crash
from reproof.dup import OsvIndex
from reproof.sandbox import SandboxRunner

TASK_ID = 42530604


@pytest.mark.live
def test_live_token_factory_claim() -> None:
    record = OsvIndex.from_archive().for_issue(TASK_ID)[0]
    claim, call = extract_claim(record.report_text)
    print(
        f"Token Factory request_id={call.request_id} input_tokens={call.input_tokens} "
        f"output_tokens={call.output_tokens} cost_usd={call.cost_usd:.8f}"
    )
    assert call.model == MODEL
    assert call.price_source == PRICE_SOURCE
    assert call.request_id
    assert claim.project


@pytest.mark.live
def test_live_contree_reproduction_pair() -> None:
    task = ArvoRepository().get(TASK_ID)
    vul_dir = Path("slices").resolve() / f"{TASK_ID}-vul"
    fix_dir = Path("slices").resolve() / f"{TASK_ID}-fix"
    assert (vul_dir / "manifest.json").is_file()
    assert (fix_dir / "manifest.json").is_file()
    runner = SandboxRunner()
    vulnerable_checkpoint = runner.ensure_checkpoint(TASK_ID, "vul", vul_dir)
    fixed_checkpoint = runner.ensure_checkpoint(TASK_ID, "fix", fix_dir)
    vulnerable, fixed = runner.run_pair(TASK_ID, vulnerable_checkpoint, fixed_checkpoint)
    print(f"ConTree operations vul={vulnerable.operation_uuid} fix={fixed.operation_uuid}")
    measured = parse_crash(vulnerable.stderr)
    fixed_measured = parse_crash(fixed.stderr)
    assert task.project == "jq"
    assert is_conclusive_crash(vulnerable.exit_code, measured)
    assert looks_clean(fixed.exit_code, fixed.stderr) and not fixed_measured.state
    assert vulnerable.operation_uuid
    assert fixed.operation_uuid
