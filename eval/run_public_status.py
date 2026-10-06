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
from reproof.public_tavily import RECORDED_CALL_CREDITS, CreditLedger

ROOT = Path(__file__).resolve().parent.parent
PREREG_PATH = ROOT / "eval" / "public_status_prereg.json"
OUT_PATH = ROOT / "eval" / "results" / "public_status.json"
PROBE_COMMIT = "b86ff49f46a4a37e5a8e75a140cb5fd6e1331384"
PROBE_TAG = "jq-1.7.1"
NVD_PAUSE_S = 6
MAX_ADVISORY_PAGES = 10
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


def partial_path() -> Path:
    directory = os.environ.get("TEMP") or os.environ.get("TMP") or "."
    return Path(directory) / "reproof-public-status-partial.json"


def load_prereg() -> dict[str, Any]:
    payload = json.loads(PREREG_PATH.read_text(encoding="utf-8"))
    if payload.get("seed") != 20261005 or payload.get("batch_crawl") is not False:
        raise SystemExit("pre-registration file does not match the registered seed or crawl rule")
    return payload


def tasks_from(prereg: dict[str, Any]) -> list[dict[str, Any]]:
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
    if not frames or not task["owner"] or not task["repo"]:
        failed.append("baseline not checkable: missing frame or repository")
    else:
        listing = github_advisories(task["owner"], task["repo"], advisories)
        if listing["error"]:
            failed.append(
                f"GET /repos/{task['owner']}/{task['repo']}/security-advisories: {listing['error']}"
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
                transport, task["owner"], task["repo"], versions, task["fix_commits"], tag_cache
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
                    ancestry = ancestry_of(
                        transport,
                        task["owner"],
                        task["repo"],
                        list(ids.patched_versions),
                        task["fix_commits"],
                        tag_cache,
                    )
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
    for name in ("A", "B"):
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


def save_partial(payload: dict[str, Any]) -> None:
    path = partial_path()
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    prereg = load_prereg()
    rows = tasks_from(prereg)
    if args.dry_run:
        jq = next(row for row in rows if row["task_id"] == "42531223")
        print(f"tasks {len(rows)} jq_top {jq['frames'][0]} crawl {prereg['batch_crawl']}")
        return
    for name in ("TAVILY_API_KEY", "NEBIUS_API_KEY"):
        if len(os.environ.get(name) or "") < 8:
            raise SystemExit(f"missing {name}")
    digest = hashlib.sha256(PREREG_PATH.read_bytes()).hexdigest()
    transport = UrllibGitHub()
    path = partial_path()
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
            "ledger_start_credits": RECORDED_CALL_CREDITS,
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
            "ledger_used": RECORDED_CALL_CREDITS,
            "nemotron_used": 0,
        }
        save_partial(state)
    if state.get("prereg_sha256") != digest:
        raise SystemExit("partial file was built from a different pre-registration")
    done = {row["task_id"] for row in state["tasks"]}
    ledger = CreditLedger(used=int(state["ledger_used"]))
    budget = ModelBudget(used=int(state["nemotron_used"]))
    for task in rows:
        if task["task_id"] in done:
            continue
        if ledger.usage_missing or ledger.used >= ledger.limit or budget.used >= budget.limit:
            reason = "stopped before this task: credit or Nemotron budget"
            if ledger.usage_missing:
                reason = "stopped before this task: an earlier Tavily response had no usage.credits"
            record = not_run(task, reason)
        else:
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
                    retrieved_on="2026-10-05",
                    forbidden=("NAN1000000000",),
                    crawl_fallback=False,
                )
                record = compact_status(task, status)
            except Exception as exc:
                record = not_run(task, "lookup failed: " + scrub(f"{type(exc).__name__}: {exc}"))
                record["ran"] = False
        state["tasks"].append(record)
        state["ledger_used"] = ledger.used
        state["nemotron_used"] = budget.used
        save_partial(state)
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
        save_partial(state)
        print(
            f"baseline {task['set']} {task['task_id']}"
            f" refs={len(record['references'])} failed={len(record['failed_sources'])}"
        )
    base_hits = [item for row in state["baseline"] for item in row["references"]]
    payload = {
        "schema": "public-status-eval-1",
        "registered_on": "2026-10-05",
        "prereg_sha256": digest,
        "ledger_start_credits": RECORDED_CALL_CREDITS,
        "batch_crawl": False,
        "ancestry_probe": state["ancestry_probe"],
        "tavily_credits_used_including_recorded": ledger.used,
        "tavily_credits_this_run": ledger.used - RECORDED_CALL_CREDITS,
        "nemotron_calls": budget.used,
        "tasks": state["tasks"],
        "baseline": state["baseline"],
        "tavily_summary": summarize(state["tasks"]),
        "baseline_fixed_in_claims": claim_counts(base_hits),
        "baseline_verified_references": len(base_hits),
        "baseline_frame_rejected": sum(row["frame_rejected"] for row in state["baseline"]),
        "baseline_host_rejected": sum(row["host_rejected"] for row in state["baseline"]),
    }
    temporary = OUT_PATH.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(OUT_PATH)
    print("wrote", OUT_PATH)
    print(json.dumps(payload["tavily_summary"], indent=2))
    print("baseline_refs", payload["baseline_verified_references"])
    print("baseline_fixed_in", json.dumps(payload["baseline_fixed_in_claims"]))
    print("credits_this_run", payload["tavily_credits_this_run"], "nemotron", budget.used)


if __name__ == "__main__":
    main()
