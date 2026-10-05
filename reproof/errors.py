"""Errors that preserve remote evidence across downstream failures."""

from __future__ import annotations


class EvidenceContextError(RuntimeError):
    """Report a failure without discarding recovered remote identifiers."""

    def __init__(
        self,
        message: str,
        *,
        request_ids: list[str],
        operation_uuids: dict[str, str],
        checkpoint_uuids: dict[str, str],
        checkpoint_operation_uuids: dict[str, str],
    ) -> None:
        super().__init__(message)
        self.request_ids = list(dict.fromkeys(request_ids))
        self.request_id = self.request_ids[0] if self.request_ids else None
        self.operation_uuids = operation_uuids
        self.operation_uuid = next(iter(operation_uuids.values()), None)
        self.checkpoint_uuids = checkpoint_uuids
        self.checkpoint_operation_uuids = checkpoint_operation_uuids


class EvidencePersistenceError(EvidenceContextError):
    """Report local write failure without discarding recovered remote identifiers."""


class TriageExecutionError(EvidenceContextError):
    """Report post-model triage failure with every identifier recovered so far."""
