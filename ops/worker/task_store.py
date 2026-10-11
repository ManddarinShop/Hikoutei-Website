"""Redis v2 storage-key namespace foundation."""

import re

PREFIX = "ops:v2:"
CURSOR_KEY = PREFIX + "cursor:qa-history"
QUEUE_KEY = PREFIX + "queue"
QUEUE_REGISTRY_KEY = PREFIX + "queue:registrations"
DEFAULT_LEASE_SECONDS = 300
MAX_LEASE_SECONDS = 86400


def occurrence_key(occurrence_id: str) -> str:
    """Name one immutable evidence record in the v2 namespace."""
    if not isinstance(occurrence_id, str) or not re.fullmatch(r"occ_[0-9a-f]{64}", occurrence_id):
        raise TaskStoreError("invalid_occurrence_id")
    return PREFIX + "occurrence:" + occurrence_id


def task_key(task_id: str) -> str:
    """Name one durable incident lifecycle document in the v2 namespace."""
    if not isinstance(task_id, str) or not re.fullmatch(r"inc_[0-9a-f]{64}", task_id):
        raise TaskStoreError("invalid_task_id")
    return PREFIX + "task:" + task_id


def observations_key(task_id: str) -> str:
    """Name the occurrence index retained for one incident task."""
    task_key(task_id)
    return PREFIX + "observations:" + task_id


def execution_key(task_id: str) -> str:
    """Name the bounded durable execution budget for one incident."""
    if not isinstance(task_id, str) or not re.fullmatch(r"inc_[0-9a-f]{64}", task_id):
        raise TaskStoreError("invalid_task_id")
    return PREFIX + "execution:" + task_id


class TaskStoreError(RuntimeError):
    """Stable storage failure without echoing Redis payloads or error values."""

    domain = "ops.v2.store"

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{self.domain}:{code}")
