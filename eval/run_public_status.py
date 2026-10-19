"""Run the pre-registered public-status evaluation.

The batch does not crawl. It stops before a call that would pass the credit or
Nemotron budget. A partial file under the system temp directory lets a stopped
process resume without repeating a finished task. Secrets are not printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reproof.public_match import (
    CONTAINS_FIX,
    DOES_NOT_CONTAIN_FIX,
    FRAME_MIN_LENGTH,
    NOT_CHECKABLE,
    extract_ids,
    host_allowed,
    interpret_compare,
    match_frames,
    resolve_tag,
)
from reproof.public_model import ModelBudget
from reproof.public_status import (
    GitHubError,
    UrllibGitHub,
    _github_get,
    lookup_public_status,
)
from reproof.public_tavily import CreditLedger

ROOT = Path(__file__).resolve().parent.parent
PREREG_PATH = ROOT / "eval" / "public_status_prereg.json"
OUT_PATH = ROOT / "eval" / "results" / "public_status.json"
PROBE_COMMIT = "b86ff49f46a4a37e5a8e75a140cb5fd6e1331384"
PROBE_TAG = "jq-1.7.1"
NVD_PAUSE_S = 6
MAX_ADVISORY_PAGES = 10
MAX_NEMOTRON_CALLS_PER_STARTED_TASK = 12
_SECRET_NAMES = (
    "TAVILY_API_KEY",
    "NEBIUS_API_KEY",
    "NEBIUS_PROJECT_ID",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)


def scrub(text: str) -> str:
    cleaned = text
    for name in _SECRET_NAMES:
        value = os.environ.get(name) or ""
        if len(value) >= 8 and value in cleaned:
            cleaned = cleaned.replace(value, "[redacted]")
    return cleaned


def partial_path(
    prereg_path: Path = PREREG_PATH,
    out_path: Path = OUT_PATH,
) -> Path:
    directory = os.environ.get("TEMP") or os.environ.get("TMP") or "."
    if prereg_path.resolve() == PREREG_PATH.resolve() and out_path.resolve() == OUT_PATH.resolve():
        name = "reproof-public-status-partial.json"
    else:
        identity = f"{prereg_path.resolve()}\0{out_path.resolve()}".encode()
        name = f"reproof-public-status-partial-{hashlib.sha256(identity).hexdigest()[:16]}.json"
    return Path(directory) / name


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SystemExit(f"{label} must be a positive integer")
    return value


def load_prereg(path: Path = PREREG_PATH) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("batch_crawl") is not False:
        raise SystemExit("pre-registration must disable batch crawl")
    _positive_int(payload.get("tavily_credit_budget"), "tavily_credit_budget")
    _positive_int(payload.get("nemotron_call_budget"), "nemotron_call_budget")
    start = payload.get("ledger_starts_at_recorded_credits")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise SystemExit("ledger_starts_at_recorded_credits must be a non-negative integer")
    if "tasks" in payload:
        if payload.get("seed") != 20261019:
            raise SystemExit("eval-100 public-status seed must be 20261019")
        _positive_int(
            payload.get("max_tavily_credits_per_started_task"),
            "max_tavily_credits_per_started_task",
        )
        _positive_int(
            payload.get("max_nemotron_calls_per_started_task"),
            "max_nemotron_calls_per_started_task",
        )
    elif payload.get("seed") != 20261005:
        raise SystemExit("legacy public-status seed must be 20261005")
    return payload


def tasks_from(prereg: dict[str, Any]) -> list[dict[str, Any]]:
    if "tasks" in prereg:
        raw_tasks = prereg["tasks"]
        if not isinstance(raw_tasks, list):
            raise SystemExit("pre-registration tasks must be an array")
        rows = []
        required = {
            "set",
            "task_id",
            "project",
            "crash_type",
            "frames",
            "owner",
            "repo",
            "project_site",
            "fix_commits",
            "osv_record_id",
            "label",
            "paid",
        }
        for raw in raw_tasks:
            if not isinstance(raw, dict) or set(raw) != required:
                raise SystemExit("eval-100 public-status task has an invalid field set")
            if not isinstance(raw["paid"], bool):
                raise SystemExit("eval-100 public-status task paid must be boolean")
            if not isinstance(raw["frames"], list) or not isinstance(raw["fix_commits"], list):
                raise SystemExit("eval-100 public-status frames and fix commits must be arrays")
            rows.append({**raw, "task_id": str(raw["task_id"])})
        expected_tasks = _positive_int(prereg.get("task_count"), "task_count")
        expected_paid = _positive_int(prereg.get("paid_task_count"), "paid_task_count")
        if len(rows) != expected_tasks or sum(bool(row["paid"]) for row in rows) != expected_paid:
            raise SystemExit("eval-100 public-status task counts differ from the preregistration")
        if [bool(row["paid"]) for row in rows] != [True] * expected_paid + [False] * (
            expected_tasks - expected_paid
        ):
            raise SystemExit("eval-100 public-status paid tasks must be the registered prefix")
        task_ids = [row["task_id"] for row in rows]
        if len(set(task_ids)) != len(task_ids):
            raise SystemExit("eval-100 public-status task IDs must be unique")
        return rows

    rows: list[dict[str, Any]] = []
    for row in prereg["set_a_arvo10"]:
        rows.append(
            {
                "set": "A",
                "task_id": str(row["arvo_id"]),
                "project": row["project"],
                "crash_type": row["crash_type"],
                "frames": list(row["frames"]),
                "owner": row["map_owner"],
                "repo": row["map_repo"],
                "project_site": row["project_site"],
                "fix_commits": list(row["fix_commits"]),
                "osv_record_id": row["osv_record_id"],
                "label": row["label"],
                "paid": True,
            }
        )
    for row in prereg["set_b_osv30"]:
        rows.append(
            {
                "set": "B",
                "task_id": row["osv_id"],
                "project": row["project"],
                "crash_type": row["crash_type"],
                "frames": list(row["frames"]),
                "owner": row["owner"],
                "repo": row["repo"],
                "project_site": "",
                "fix_commits": list(row["fix_commits"]),
                "osv_record_id": row["osv_id"],
                "label": row["label"],
                "paid": True,
            }
        )
    if len(rows) != 40 or sum(row["set"] == "A" for row in rows) != 10:
        raise SystemExit(f"expected 10 + 30 tasks, found {len(rows)}")
    return rows


def usable_frames(frames: list[str]) -> list[str]:
    seen: list[str] = []
    for frame in frames:
        cleaned = frame.strip()
        if len(cleaned) < FRAME_MIN_LENGTH or cleaned in seen:
            continue
        seen.append(cleaned)
    return seen


def compact_status(task: dict[str, Any], status: Any) -> dict[str, Any]:
    evidence = []
    for item in status.evidence:
        evidence.append(
            {
                "url": item.url,
                "title": item.title,
                "frames_matched": list(item.frames_matched),
                "cve_ids": list(item.cve_ids),
                "ghsa_ids": list(item.ghsa_ids),
                "patched_versions": list(item.patched_versions),
                "relation": item.relation,
                "upstream_status": item.upstream_status,
                "upstream_version": item.upstream_version,
                "ancestry": item.ancestry,
                "checked_tag": item.checked_tag,
                "checked_commit": item.checked_commit,
                "stale_fields": list(item.stale_fields),
                "match_reason": item.match_reason,
                "model_request_id": item.model_request_id,
                "dispute": item.dispute,
            }
        )
    drafts = [
        {
            "text": line.text,
            "source_url": line.source_url,
            "source_date": line.source_date,
            "confidence": line.confidence,
        }
        for line in status.draft
        if "NAN1000000000" not in line.text
    ]
    return {
        "set": task["set"],
        "task_id": task["task_id"],
        "project": task["project"],
        "osv_record_id": task["osv_record_id"],
        "label": task["label"],
        "ran": True,
        "state": status.state,
        "evidence": evidence,
        "draft": drafts,
        "queries_sent": list(status.queries_sent),
        "query_source": status.query_source,
        "failed_sources": [scrub(item) for item in status.failed_sources],
        "note": scrub(status.note),
        "tavily_request_ids": list(status.tavily_request_ids),
        "tavily_credits": status.tavily_credits,
        "tavily_calls": [
            {
                "operation": call.operation,
                "request_id": call.request_id,
                "credits": call.credits,
                "query": call.query,
            }
            for call in status.tavily_calls
        ],
        "model_calls": len(status.model_calls),
        "model_request_ids": [call.request_id for call in status.model_calls],
        "model_input_tokens": sum(call.input_tokens for call in status.model_calls),
        "model_output_tokens": sum(call.output_tokens for call in status.model_calls),
        "model_cost_usd": round(sum(call.cost_usd for call in status.model_calls), 8),
        "host_rejected": status.host_rejected,
        "snippet_rejected": status.snippet_rejected,
        "frame_rejected": status.frame_rejected,
        "quote_rejected": status.quote_rejected,
        "unrelated_rejected": status.unrelated_rejected,
        "source_file_rejected": status.source_file_rejected,
        "latency_seconds": status.latency_seconds,
    }


def not_run(task: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "set": task["set"],
        "task_id": task["task_id"],
        "project": task["project"],
        "osv_record_id": task["osv_record_id"],
        "label": task["label"],
        "ran": False,
        "not_run_reason": reason,
        "state": "",
        "evidence": [],
        "draft": [],
        "queries_sent": [],
        "failed_sources": [],
        "note": reason,
        "tavily_request_ids": [],
        "tavily_credits": 0,
        "tavily_calls": [],
        "model_calls": 0,
        "model_request_ids": [],
        "host_rejected": 0,
        "snippet_rejected": 0,
        "frame_rejected": 0,
        "quote_rejected": 0,
        "unrelated_rejected": 0,
        "source_file_rejected": 0,
        "latency_seconds": 0,
    }


def ancestry_of(
    transport: UrllibGitHub,
    owner: str,
    repo: str,
    versions: list[str],
    commits: list[str],
    tag_cache: dict[tuple[str, str], tuple[str, ...] | str],
) -> dict[str, Any]:
    if not commits:
        return {
            "ancestry": "NO_FIX_COMMIT",
            "checked_tag": "",
            "checked_commit": "",
            "stale_fields": [],
        }
    if not versions:
        return {
            "ancestry": NOT_CHECKABLE,
            "checked_tag": "",
            "checked_commit": "",
            "stale_fields": [],
        }
    key = (owner, repo)
    if key not in tag_cache:
        try:
            tag_cache[key] = transport.list_tags(owner, repo)
        except GitHubError as exc:
            tag_cache[key] = exc.reason
    cached = tag_cache[key]
    if isinstance(cached, str):
        return {
            "ancestry": NOT_CHECKABLE,
            "checked_tag": "",
            "checked_commit": "",
            "stale_fields": [],
            "error": f"git tags failed: {cached}",
        }
    decided = NOT_CHECKABLE
    tag_out = ""
    commit_out = ""
    version_out = versions[0]
    stale: list[str] = []
    saw_contains = False
    errors: list[str] = []
    for version in versions:
        tag, reason = resolve_tag(version, cached)
        if not tag:
            errors.append(f"git tag {version}: {reason}")
            continue
        outcomes: list[str] = []
        chosen = ""
        for commit in commits:
            result = transport.compare(owner, repo, tag, commit)
            if result.error:
                errors.append(f"git compare {tag}: {result.error}")
                outcomes = []
                break
            outcomes.append(interpret_compare(result.status, result.ahead_by, result.behind_by))
            chosen = commit
        if not outcomes:
            continue
        if DOES_NOT_CONTAIN_FIX in outcomes:
            field = f"patched_version:{version}"
            if field not in stale:
                stale.append(field)
            if decided != DOES_NOT_CONTAIN_FIX:
                decided = DOES_NOT_CONTAIN_FIX
                tag_out = tag
                commit_out = chosen
                version_out = version
            continue
        contains = all(item == CONTAINS_FIX for item in outcomes)
        if contains and decided != DOES_NOT_CONTAIN_FIX and not saw_contains:
            saw_contains = True
            decided = CONTAINS_FIX
            tag_out = tag
            commit_out = chosen
            version_out = version
    return {
        "ancestry": decided,
        "checked_tag": tag_out,
        "checked_commit": commit_out,
        "checked_version": version_out,
        "stale_fields": stale,
        "errors": errors,
    }


def github_advisories(
    owner: str,
    repo: str,
    cache: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    key = (owner, repo)
    if key in cache:
        return cache[key]
    pages: list[dict[str, Any]] = []
    error = ""
    truncated = False
    for page in range(1, MAX_ADVISORY_PAGES + 1):
        url = (
            "https://api.github.com/repos/"
            f"{owner}/{repo}/security-advisories?per_page=100&page={page}&state=published"
        )
        try:
            payload = _github_get(url)
        except GitHubError as exc:
            error = exc.reason
            break
        if not isinstance(payload, list):
            error = "advisory_shape"
            break
        for item in payload:
            if isinstance(item, dict):
                pages.append(item)
        if len(payload) < 100:
            break
        if page == MAX_ADVISORY_PAGES:
            truncated = True
    found = {"advisories": pages, "error": error, "truncated": truncated}
    cache[key] = found
    return found


def nvd_search(frame: str, cache: dict[str, dict[str, Any]], clock: list[float]) -> dict[str, Any]:
    if frame in cache:
        cached = dict(cache[frame])
        cached["cached"] = True
        return cached
    wait = NVD_PAUSE_S - (time.monotonic() - clock[0])
    if clock[0] and wait > 0:
        time.sleep(wait)
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&keywordSearch="
        + urllib.parse.quote(frame)
    )
    request = urllib.request.Request(url, headers={"User-Agent": "reproof"})
    clock[0] = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        found = {"payload": payload, "error": "", "cached": False}
    except urllib.error.HTTPError as exc:
        found = {"payload": None, "error": f"http_{exc.code}", "cached": False}
    except urllib.error.URLError:
        found = {"payload": None, "error": "transport", "cached": False}
    except json.JSONDecodeError:
        found = {"payload": None, "error": "not_json", "cached": False}
    cache[frame] = found
    return found


def baseline_task(
    task: dict[str, Any],
    transport: UrllibGitHub,
    advisories: dict[tuple[str, str], dict[str, Any]],
    nvd_cache: dict[str, dict[str, Any]],
    tag_cache: dict[tuple[str, str], tuple[str, ...] | str],
    nvd_clock: list[float],
    nvd_blocked: list[str],
) -> dict[str, Any]:
    started = time.perf_counter()
    frames = usable_frames(task["frames"])
    failed: list[str] = []
    hits: list[dict[str, Any]] = []
    rejected = {"host": 0, "frame": 0}
    if not frames:
        failed.append("baseline not checkable: missing frame")
    else:
        has_repository = bool(task["owner"] and task["repo"])
        if not has_repository:
            failed.append("GitHub baseline not checkable: missing repository")
        else:
            listing = github_advisories(task["owner"], task["repo"], advisories)
            if listing["error"]:
                failed.append(
                    f"GET /repos/{task['owner']}/{task['repo']}/security-advisories: "
                    f"{listing['error']}"
                )
            if listing["truncated"]:
                failed.append("repository advisory list truncated at 10 pages")
            for item in listing["advisories"]:
                text = f"{item.get('summary', '')}\n{item.get('description', '')}"
                url = str(item.get("html_url") or "")
                decision = host_allowed(
                    url,
                    owner=task["owner"],
                    repo=task["repo"],
                    project=task["project"],
                    text=text,
                )
                if not decision.allowed:
                    rejected["host"] += 1
                    continue
                gate = match_frames(text, frames, task["crash_type"])
                if not gate.passes:
                    rejected["frame"] += 1
                    continue
                ids = extract_ids(text)
                versions = list(ids.patched_versions)
                ancestry = ancestry_of(
                    transport,
                    task["owner"],
                    task["repo"],
                    versions,
                    task["fix_commits"],
                    tag_cache,
                )
                hits.append(
                    {
                        "source": "github_repo_advisories",
                        "url": url,
                        "ghsa_id": item.get("ghsa_id") or "",
                        "cve_id": item.get("cve_id") or "",
                        "frames_matched": list(gate.frames_matched),
                        "match_reason": gate.reason,
                        "patched_versions": versions,
                        **ancestry,
                    }
                )

        if nvd_blocked[0]:
            failed.append(f"NVD skipped after {nvd_blocked[0]}")
        else:
            searched = nvd_search(frames[0], nvd_cache, nvd_clock)
            if searched["error"]:
                failed.append(f"NVD keywordSearch {frames[0]}: {searched['error']}")
                if searched["error"] in {"http_403", "http_429"}:
                    nvd_blocked[0] = searched["error"]
            else:
                vulns = (searched["payload"] or {}).get("vulnerabilities") or []
                for vuln in vulns:
                    cve = vuln.get("cve") or {}
                    descriptions = cve.get("descriptions") or []
                    text = "\n".join(
                        str(item.get("value") or "")
                        for item in descriptions
                        if item.get("lang") == "en"
                    )
                    cve_id = str(cve.get("id") or "")
                    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""
                    decision = host_allowed(
                        url,
                        owner=task["owner"],
                        repo=task["repo"],
                        project=task["project"],
                        text=text,
                    )
                    if not decision.allowed:
                        rejected["host"] += 1
                        continue
                    gate = match_frames(text, frames, task["crash_type"])
                    if not gate.passes:
                        rejected["frame"] += 1
                        continue
                    ids = extract_ids(text)
                    if has_repository:
                        ancestry = ancestry_of(
                            transport,
                            task["owner"],
                            task["repo"],
                            list(ids.patched_versions),
                            task["fix_commits"],
                            tag_cache,
                        )
                    else:
                        ancestry = {
                            "ancestry": NOT_CHECKABLE,
                            "checked_tag": "",
                            "checked_commit": "",
                            "checked_version": (
                                ids.patched_versions[0] if ids.patched_versions else ""
                            ),
                            "stale_fields": [],
                            "errors": ["GitHub ancestry not checkable: missing repository"],
                        }
                    hits.append(
                        {
                            "source": "nvd_keyword",
                            "url": url,
                            "cve_id": cve_id,
                            "frames_matched": list(gate.frames_matched),
                            "match_reason": gate.reason,
                            "patched_versions": list(ids.patched_versions),
                            "cached_request": searched["cached"],
                            **ancestry,
                        }
                    )
    return {
        "set": task["set"],
        "task_id": task["task_id"],
        "project": task["project"],
        "references": hits,
        "host_rejected": rejected["host"],
        "frame_rejected": rejected["frame"],
        "failed_sources": failed,
        "latency_seconds": round(time.perf_counter() - started, 6),
    }


def claim_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    precise = 0
    prevented = 0
    not_checkable = 0
    for item in items:
        claimed = bool(
            item.get("patched_versions")
            or item.get("upstream_version")
            or item.get("upstream_status") == "FIXED"
        )
        if not claimed:
            continue
        ancestry = item.get("ancestry")
        if ancestry == CONTAINS_FIX:
            precise += 1
        elif ancestry == DOES_NOT_CONTAIN_FIX:
            prevented += 1
        else:
            not_checkable += 1
    return {"precise": precise, "prevented": prevented, "not_checkable": not_checkable}


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    ran = [row for row in records if row.get("ran")]
    evidence = [item for row in ran for item in row.get("evidence", [])]
    claims = claim_counts(evidence)
    by_set: dict[str, Any] = {}
    for name in dict.fromkeys(str(row["set"]) for row in records):
        chosen = [row for row in records if row["set"] == name]
        chosen_ran = [row for row in chosen if row.get("ran")]
        by_set[name] = {
            "tasks": len(chosen),
            "ran": len(chosen_ran),
            "not_run": sum(not row.get("ran") for row in chosen),
            "with_verified_reference": sum(bool(row.get("evidence")) for row in chosen_ran),
            "no_public_findings": sum(
                row.get("state") == "NO_PUBLIC_FINDINGS" for row in chosen_ran
            ),
            "states": {
                state: sum(row.get("state") == state for row in chosen_ran)
                for state in (
                    "PUBLICLY_KNOWN_FIXED",
                    "PUBLICLY_KNOWN_OPEN",
                    "RELATED_VARIANTS_ONLY",
                    "SOURCE_DISPUTE",
                    "NO_PUBLIC_FINDINGS",
                    "LOOKUP_UNAVAILABLE",
                )
            },
            "unrelated_rejected": sum(row.get("unrelated_rejected", 0) for row in chosen_ran),
            "frame_rejected": sum(row.get("frame_rejected", 0) for row in chosen_ran),
            "host_rejected": sum(row.get("host_rejected", 0) for row in chosen_ran),
            "snippet_rejected": sum(row.get("snippet_rejected", 0) for row in chosen_ran),
            "tavily_credits": sum(row.get("tavily_credits", 0) for row in chosen_ran),
            "model_calls": sum(row.get("model_calls", 0) for row in chosen_ran),
            "latency_seconds": round(sum(row.get("latency_seconds", 0) for row in chosen_ran), 6),
        }
    return {"by_set": by_set, "fixed_in_claims": claims, "evidence_pages": len(evidence)}


def save_partial(payload: dict[str, Any], path: Path | None = None) -> None:
    path = path or partial_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(path)


def _assert_within_budget(ledger: CreditLedger, budget: ModelBudget) -> None:
    if ledger.used + ledger.unanswered > ledger.limit:
        raise RuntimeError("Tavily accounting exceeded the preregistered credit cap")
    if budget.used > budget.limit:
        raise RuntimeError("Nemotron accounting exceeded the preregistered call cap")


def _utc_date() -> str:
    return datetime.now(UTC).date().isoformat()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prereg", type=Path, default=PREREG_PATH)
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    prereg_path = args.prereg.resolve()
    out_path = args.out.resolve()
    if prereg_path != PREREG_PATH.resolve() and out_path == OUT_PATH.resolve():
        raise SystemExit(
            "refusing a non-default pre-registration with the legacy public-status output"
        )
    prereg = load_prereg(prereg_path)
    rows = tasks_from(prereg)
    if args.dry_run:
        paid = sum(bool(row.get("paid", True)) for row in rows)
        print(
            f"tasks {len(rows)} paid {paid} seed {prereg['seed']}"
            f" credits {prereg['tavily_credit_budget']}"
            f" nemotron {prereg['nemotron_call_budget']}"
            f" crawl {prereg['batch_crawl']}"
        )
        return
    for name in ("TAVILY_API_KEY", "NEBIUS_API_KEY"):
        if len(os.environ.get(name) or "") < 8:
            raise SystemExit(f"missing {name}")
    digest = hashlib.sha256(prereg_path.read_bytes()).hexdigest()
    credit_limit = int(prereg["tavily_credit_budget"])
    model_limit = int(prereg["nemotron_call_budget"])
    ledger_start = int(prereg["ledger_starts_at_recorded_credits"])
    task_credit_max = int(prereg.get("max_tavily_credits_per_started_task", 5))
    task_model_max = int(
        prereg.get(
            "max_nemotron_calls_per_started_task",
            MAX_NEMOTRON_CALLS_PER_STARTED_TASK,
        )
    )
    transport = UrllibGitHub()
    path = partial_path(prereg_path, out_path)
    if path.is_file():
        state = json.loads(path.read_text(encoding="utf-8"))
        print(f"resume tasks {len(state.get('tasks', []))}")
    else:
        probe = transport.compare("jqlang", "jq", PROBE_TAG, PROBE_COMMIT)
        print(
            "probe"
            f" status={probe.status} ahead_by={probe.ahead_by}"
            f" behind_by={probe.behind_by} error={probe.error or 'none'}"
        )
        state = {
            "prereg_sha256": digest,
            "retrieved_on": _utc_date(),
            "ledger_start_credits": ledger_start,
            "ancestry_probe": {
                "owner": "jqlang",
                "repo": "jq",
                "tag": PROBE_TAG,
                "commit": PROBE_COMMIT,
                "status": probe.status,
                "ahead_by": probe.ahead_by,
                "behind_by": probe.behind_by,
                "error": probe.error,
            },
            "tasks": [],
            "baseline": [],
            "ledger_used": ledger_start,
            "ledger_unanswered": 0,
            "ledger_usage_missing": False,
            "nemotron_used": 0,
            "nemotron_reserved": 0,
            "interrupted": [],
            "in_progress": None,
        }
        save_partial(state, path)
    if state.get("prereg_sha256") != digest:
        raise SystemExit("partial file was built from a different pre-registration")
    if not isinstance(state.get("retrieved_on"), str) or not state["retrieved_on"]:
        state["retrieved_on"] = _utc_date()
        save_partial(state, path)
    in_progress = state.get("in_progress")
    if in_progress is not None:
        expected_hold = {
            "task_id": str(in_progress.get("task_id")) if isinstance(in_progress, dict) else "",
            "tavily_credits": task_credit_max,
            "nemotron_calls": task_model_max,
        }
        if not isinstance(in_progress, dict) or in_progress != expected_hold:
            raise SystemExit("partial file has an invalid in-progress budget reservation")
        task_by_id = {str(row["task_id"]): row for row in rows}
        interrupted_task = task_by_id.get(expected_hold["task_id"])
        if interrupted_task is None or any(
            str(row.get("task_id")) == expected_hold["task_id"] for row in state["tasks"]
        ):
            raise SystemExit("partial file has an invalid in-progress task")
        state["ledger_unanswered"] = int(state.get("ledger_unanswered", 0)) + task_credit_max
        state["nemotron_used"] = int(state.get("nemotron_used", 0)) + task_model_max
        state["nemotron_reserved"] = int(state.get("nemotron_reserved", 0)) + task_model_max
        state.setdefault("interrupted", []).append(expected_hold)
        state["tasks"].append(
            not_run(
                interrupted_task,
                "not retried: prior process stopped after reserving paid-call budget",
            )
        )
        state["in_progress"] = None
        save_partial(state, path)
    done = {row["task_id"] for row in state["tasks"]}
    ledger = CreditLedger(
        limit=credit_limit,
        used=int(state["ledger_used"]),
        unanswered=int(state.get("ledger_unanswered", 0)),
        usage_missing=bool(state.get("ledger_usage_missing", False)),
    )
    budget = ModelBudget(limit=model_limit, used=int(state["nemotron_used"]))
    try:
        _assert_within_budget(ledger, budget)
    except RuntimeError as error:
        raise SystemExit("partial file exceeds the registered public-status budget") from error
    for task in rows:
        if task["task_id"] in done:
            continue
        if not task.get("paid", True):
            record = not_run(task, "not run: outside the preregistered paid subset")
        elif not usable_frames(task["frames"]):
            status = lookup_public_status(
                project=task["project"],
                crash_type=task["crash_type"],
                frames=task["frames"],
                owner=task["owner"],
                repo=task["repo"],
                fix_commits=task["fix_commits"],
                project_site=task["project_site"],
                ledger=ledger,
                model_budget=budget,
                transport=transport,
                retrieved_on=str(state["retrieved_on"]),
                forbidden=("NAN1000000000",),
                crawl_fallback=False,
            )
            record = compact_status(task, status)
        elif ledger.usage_missing:
            record = not_run(
                task,
                "stopped before this task: an earlier Tavily response had no usage.credits",
            )
        elif ledger.used + ledger.unanswered + task_credit_max > ledger.limit:
            record = not_run(task, "stopped before this task: Tavily credit cap")
        elif budget.used + task_model_max > budget.limit:
            record = not_run(task, "stopped before this task: Nemotron call cap")
        else:
            state["in_progress"] = {
                "task_id": str(task["task_id"]),
                "tavily_credits": task_credit_max,
                "nemotron_calls": task_model_max,
            }
            save_partial(state, path)
            try:
                status = lookup_public_status(
                    project=task["project"],
                    crash_type=task["crash_type"],
                    frames=task["frames"],
                    owner=task["owner"],
                    repo=task["repo"],
                    fix_commits=task["fix_commits"],
                    project_site=task["project_site"],
                    ledger=ledger,
                    model_budget=budget,
                    transport=transport,
                    retrieved_on=str(state["retrieved_on"]),
                    forbidden=("NAN1000000000",),
                    crawl_fallback=False,
                )
                record = compact_status(task, status)
            except Exception as exc:
                record = not_run(task, "lookup failed: " + scrub(f"{type(exc).__name__}: {exc}"))
                record["ran"] = False
        _assert_within_budget(ledger, budget)
        state["tasks"].append(record)
        state["ledger_used"] = ledger.used
        state["ledger_unanswered"] = ledger.unanswered
        state["ledger_usage_missing"] = ledger.usage_missing
        state["nemotron_used"] = budget.used
        state["in_progress"] = None
        save_partial(state, path)
        print(
            f"{task['set']} {task['task_id']} {record.get('state') or 'NOT_RUN'}"
            f" credits={ledger.used} nemotron={budget.used} refs={len(record.get('evidence', []))}"
        )
    done_base = {row["task_id"] for row in state["baseline"]}
    advisories: dict[tuple[str, str], dict[str, Any]] = {}
    nvd_cache: dict[str, dict[str, Any]] = {}
    tag_cache: dict[tuple[str, str], tuple[str, ...] | str] = {}
    nvd_clock = [0.0]
    nvd_blocked = [""]
    for task in rows:
        if task["task_id"] in done_base:
            continue
        record = baseline_task(
            task, transport, advisories, nvd_cache, tag_cache, nvd_clock, nvd_blocked
        )
        state["baseline"].append(record)
        save_partial(state, path)
        print(
            f"baseline {task['set']} {task['task_id']}"
            f" refs={len(record['references'])} failed={len(record['failed_sources'])}"
        )
    base_hits = [item for row in state["baseline"] for item in row["references"]]
    payload = {
        "schema": "public-status-eval-1",
        "registered_on": prereg["registered_on"],
        "retrieved_on": state["retrieved_on"],
        "prereg_sha256": digest,
        "ledger_start_credits": ledger_start,
        "batch_crawl": False,
        "tavily_credit_cap": credit_limit,
        "nemotron_call_cap": model_limit,
        "ancestry_probe": state["ancestry_probe"],
        "tavily_credits_used_including_recorded": ledger.used,
        "tavily_unanswered_credits": ledger.unanswered,
        "tavily_usage_missing": ledger.usage_missing,
        "tavily_credits_this_run": ledger.used - ledger_start,
        "nemotron_calls": budget.used,
        "nemotron_reserved_after_interruption": int(state.get("nemotron_reserved", 0)),
        "interrupted_reservations": state.get("interrupted", []),
        "tasks": state["tasks"],
        "baseline": state["baseline"],
        "tavily_summary": summarize(state["tasks"]),
        "baseline_fixed_in_claims": claim_counts(base_hits),
        "baseline_verified_references": len(base_hits),
        "baseline_frame_rejected": sum(row["frame_rejected"] for row in state["baseline"]),
        "baseline_host_rejected": sum(row["host_rejected"] for row in state["baseline"]),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = out_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(out_path)
    print("wrote", out_path)
    print(json.dumps(payload["tavily_summary"], indent=2))
    print("baseline_refs", payload["baseline_verified_references"])
    print("baseline_fixed_in", json.dumps(payload["baseline_fixed_in_claims"]))
    print("credits_this_run", payload["tavily_credits_this_run"], "nemotron", budget.used)


if __name__ == "__main__":
    main()
