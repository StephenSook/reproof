"""Re-score own-repo GitHub advisories already stored in the public-status result.

Reads the advisory API and runs the existing ancestry check. No Tavily call.
No Nemotron call. Does not modify eval/results/public_status.json.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import reproof.public_status as public_status
from reproof.public_match import (
    CONTAINS_FIX,
    DOES_NOT_CONTAIN_FIX,
    NOT_CHECKABLE,
    extract_ids,
)
from reproof.public_model import GuardedPage
from reproof.public_status import (
    AdvisoryRecord,
    CompareResult,
    GitHubError,
    UrllibGitHub,
    _Ancestry,
    assess_ancestry,
    task_advisory,
)

ROOT = Path(__file__).resolve().parent.parent
SOURCE_PATH = ROOT / "eval" / "results" / "public_status.json"
PREREG_PATH = ROOT / "eval" / "public_status_prereg.json"
OUT_PATH = ROOT / "eval" / "results" / "advisory_rescore.json"
_RATE_LIMIT = frozenset({"http_403"})


class LoggedGitHubGet:
    """Record each GitHub URL. On the first 403, wait once and retry once."""

    def __init__(self, original: Any) -> None:
        self._original = original
        self.urls: list[str] = []
        self._retried = False
        self.blocked = False

    def __call__(self, url: str) -> Any:
        if self.blocked:
            raise GitHubError("rate_limit_stop")
        self.urls.append(url)
        try:
            return self._original(url)
        except GitHubError as exc:
            if exc.reason not in _RATE_LIMIT or self._retried:
                if exc.reason in _RATE_LIMIT:
                    self.blocked = True
                raise
            self._retried = True
            time.sleep(60)
            self.urls.append(url)
            try:
                return self._original(url)
            except GitHubError as again:
                if again.reason in _RATE_LIMIT:
                    self.blocked = True
                raise


class RecordingGitHub:
    """UrllibGitHub with one cache for tags, advisories, and compares."""

    def __init__(self, inner: UrllibGitHub) -> None:
        self._inner = inner
        self._tags: dict[tuple[str, str], tuple[str, ...]] = {}
        self._advisories: dict[tuple[str, str, str], AdvisoryRecord] = {}
        self._compares: dict[tuple[str, str, str, str], CompareResult] = {}
        self.last_compares: list[tuple[str, str, CompareResult]] = []

    def list_tags(self, owner: str, repo: str) -> tuple[str, ...]:
        key = (owner, repo)
        if key not in self._tags:
            self._tags[key] = self._inner.list_tags(owner, repo)
        return self._tags[key]

    def compare(self, owner: str, repo: str, base: str, head: str) -> CompareResult:
        key = (owner, repo, base, head)
        if key not in self._compares:
            self._compares[key] = self._inner.compare(owner, repo, base, head)
        result = self._compares[key]
        self.last_compares.append((base, head, result))
        return result

    def read_advisory(self, owner: str, repo: str, ghsa_id: str) -> AdvisoryRecord:
        key = (owner, repo, ghsa_id)
        if key not in self._advisories:
            self._advisories[key] = self._inner.read_advisory(owner, repo, ghsa_id)
        return self._advisories[key]


def _repos(prereg: dict[str, Any]) -> dict[str, tuple[str, str, tuple[str, ...]]]:
    found: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    for row in prereg["set_a_arvo10"]:
        commits = tuple(str(item) for item in row["fix_commits"])
        found[str(row["arvo_id"])] = (str(row["map_owner"]), str(row["map_repo"]), commits)
    for row in prereg["set_b_osv30"]:
        commits = tuple(str(item) for item in row["fix_commits"])
        found[str(row["osv_id"])] = (str(row["owner"]), str(row["repo"]), commits)
    return found


def _pages(document: dict[str, Any]) -> list[tuple[str, str, str]]:
    pages: list[tuple[str, str, str]] = []
    for task in document["tasks"]:
        for item in task.get("evidence") or []:
            url = item.get("url")
            if isinstance(url, str):
                pages.append((str(task["task_id"]), "evidence", url))
    for task in document["baseline"]:
        for item in task.get("references") or []:
            url = item.get("url")
            if isinstance(url, str):
                pages.append((str(task["task_id"]), "baseline", url))
    return pages


def _blank(task_id: str, role: str, url: str, ghsa_id: str, error: str) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "role": role,
        "url": url,
        "ghsa_id": ghsa_id,
        "patched_versions": [],
        "usable_versions": [],
        "tag": "",
        "compare_status": "",
        "ahead_by": None,
        "behind_by": None,
        "ancestry": NOT_CHECKABLE,
        "state": NOT_CHECKABLE,
        "stale_fields": [],
        "error": error,
    }


def _state(ancestry: str) -> str:
    if ancestry == CONTAINS_FIX:
        return "PUBLICLY_KNOWN_FIXED"
    if ancestry == DOES_NOT_CONTAIN_FIX:
        return DOES_NOT_CONTAIN_FIX
    return NOT_CHECKABLE


def _guard() -> GuardedPage:
    return GuardedPage(
        accepted=True,
        relation="SAME_BUG",
        upstream_status="UNKNOWN",
        upstream_version="",
        upstream_commit="",
        supporting_quotes=(),
        dispute=False,
        dispute_quotes=(),
        rejection="",
        model_calls=(),
    )


def _chosen(
    ancestry: _Ancestry, compares: list[tuple[str, str, CompareResult]]
) -> tuple[str, str, CompareResult] | None:
    for base, head, result in compares:
        if ancestry.tag and ancestry.commit and base == ancestry.tag and head == ancestry.commit:
            return base, head, result
    if len(compares) == 1:
        return compares[0]
    return None


def _score(
    transport: RecordingGitHub,
    task_id: str,
    role: str,
    url: str,
    owner: str,
    repo: str,
    commits: tuple[str, ...],
    ghsa_id: str,
) -> dict[str, Any]:
    record = transport.read_advisory(owner, repo, ghsa_id)
    if record.error:
        row = _blank(task_id, role, url, record.ghsa_id or ghsa_id, record.error)
        return row
    failed: list[str] = []
    transport.last_compares.clear()
    ancestry = assess_ancestry(
        "",
        extract_ids(""),
        _guard(),
        commits,
        owner=owner,
        repo=repo,
        transport=transport,
        failed=failed,
        extra_versions=tuple(record.patched_versions),
    )
    chosen = _chosen(ancestry, transport.last_compares)
    error = record.error
    if failed:
        error = "; ".join(failed)
    if chosen is not None and chosen[2].error and not error:
        error = chosen[2].error
    row = _blank(task_id, role, url, record.ghsa_id or ghsa_id, error)
    row["patched_versions"] = list(record.raw_patched_versions)
    row["usable_versions"] = list(record.patched_versions)
    row["ancestry"] = ancestry.ancestry
    row["state"] = _state(ancestry.ancestry)
    row["stale_fields"] = list(ancestry.stale)
    row["tag"] = ancestry.tag
    if chosen is not None:
        row["tag"] = ancestry.tag or chosen[0]
        row["compare_status"] = chosen[2].status
        row["ahead_by"] = chosen[2].ahead_by
        row["behind_by"] = chosen[2].behind_by
    return row


def main() -> int:
    source_bytes = SOURCE_PATH.read_bytes()
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    document = json.loads(source_bytes.decode("utf-8"))
    prereg = json.loads(PREREG_PATH.read_text(encoding="utf-8"))
    repos = _repos(prereg)
    logged = LoggedGitHubGet(public_status._github_get)
    public_status._github_get = logged
    transport = RecordingGitHub(UrllibGitHub())
    rows: list[dict[str, Any]] = []
    try:
        for task_id, role, url in _pages(document):
            located_repo = repos.get(task_id)
            if located_repo is None:
                continue
            owner, repo, commits = located_repo
            located = task_advisory(url, owner, repo)
            if located is None:
                continue
            _owner, _repo, ghsa_id = located
            if logged.blocked:
                rows.append(_blank(task_id, role, url, ghsa_id, "rate_limit_stop"))
                continue
            rows.append(_score(transport, task_id, role, url, owner, repo, commits, ghsa_id))
    finally:
        public_status._github_get = logged._original
    if hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest() != source_sha:
        raise RuntimeError("public_status.json changed during the rescore")
    payload = {
        "schema": "advisory-rescore-1",
        "source": "eval/results/public_status.json",
        "source_sha256": source_sha,
        "tavily_calls": 0,
        "nemotron_calls": 0,
        "github_api_urls": list(logged.urls),
        "rows": rows,
    }
    with OUT_PATH.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
