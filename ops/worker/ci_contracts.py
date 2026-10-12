"""Strict typed boundaries for read-only GitHub Actions evidence."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal, TypeAlias, TypedDict, cast
from urllib.parse import urlsplit

from task_contracts import (
    IncidentIdentity,
    MAX_SAFE_COUNTER,
    SOURCE_REPOSITORIES,
    is_int,
    stable_json,
)

CI_CURSOR_PREFIX = "ops:v2:cursor:ci:"
CI_PAGE_SIZE = 100
MAX_CI_PAGE = 10_000
MAX_CI_ATTEMPTS = 100
MAX_CI_JOBS = 10_000
MAX_CI_STEPS = 500
MAX_CI_DIAGNOSTICS = 32
MAX_DIAGNOSTIC_TEXT = 32_768
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)\s+")
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)(?P<key>[\"']?[A-Za-z0-9_.-]*(?:token|password|secret|api[_-]?key|authorization|credentials?|private[_-]?key)[A-Za-z0-9_.-]*[\"']?)(?P<separator>\s*[:=]\s*)(?P<value>\[redacted\]|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)"""
)
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|$)",
    re.IGNORECASE | re.DOTALL,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_CREDENTIAL = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_JSON_STRING_TOKEN = re.compile(r'(?<!\\)"(?:\\[^\r\n]|[^"\\\r\n])*(?:"|\\?(?=$|[\r\n]))')
_URL = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*:(?:/|\\/){2}[^\s\"'<>]+", re.IGNORECASE)

CI_STATUS_VALUES = ("queued", "in_progress", "completed", "requested", "waiting", "pending")
CI_CONCLUSION_VALUES = (
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure",
)
CI_FAILURE_CONCLUSIONS = frozenset(("failure", "timed_out", "action_required", "startup_failure"))
JOB_STATUS_VALUES = ("queued", "in_progress", "completed")
STEP_STATUS_VALUES = ("queued", "in_progress", "completed")


class MissingCICursor(TypedDict):
    status: Literal["missing"]


class StoredCICursor(TypedDict):
    status: Literal["stored"]
    raw: str
    value: CICursor


CICursorSnapshot: TypeAlias = MissingCICursor | StoredCICursor


class CICursor(TypedDict):
    schema_version: Literal[2]
    source_repo: str
    pass_id: int
    next_page: int
    previous_page_ids: list[int]


class ValidCICursor(TypedDict):
    status: Literal["valid"]
    value: CICursor


class InvalidCICursor(TypedDict):
    status: Literal["invalid"]
    code: str


CICursorValidation: TypeAlias = ValidCICursor | InvalidCICursor


CIConclusion: TypeAlias = Literal[
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure",
]


class RunBase(TypedDict):
    source_repo: str
    run_id: int
    run_attempt: int
    workflow_id: int
    workflow_path: str
    head_sha: str
    head_ref: str


class CompletedRunAttempt(RunBase):
    status: Literal["completed"]
    conclusion: CIConclusion


class NonCompletedRunAttempt(RunBase):
    status: Literal["queued", "in_progress", "requested", "waiting", "pending"]
    conclusion: None


CIRunAttempt: TypeAlias = CompletedRunAttempt | NonCompletedRunAttempt


class CIStep(TypedDict):
    name: str
    status: Literal["queued", "in_progress", "completed"]
    conclusion: CIConclusion | None


class CIJob(TypedDict):
    id: int
    run_id: int
    run_attempt: int
    name: str
    status: Literal["queued", "in_progress", "completed"]
    conclusion: CIConclusion | None
    steps: list[CIStep]


class CIDiagnostic(TypedDict):
    job_id: int
    sha256: str
    text: str
    truncated: bool


class CIAttemptObservation(TypedDict):
    schema_version: Literal[2]
    occurrence_id: str
    source_repo: str
    kind: Literal["ci_attempt"]
    run: CompletedRunAttempt
    jobs: list[CIJob]


class CIFailureOccurrence(TypedDict):
    schema_version: Literal[2]
    occurrence_id: str
    source_repo: str
    kind: Literal["ci_failure"]
    run: CompletedRunAttempt
    jobs: list[CIJob]
    diagnostics: list[CIDiagnostic]
    mode: Literal["local", "sync", "unknown"]
    incident_id: str


class CIMonitorOccurrence(TypedDict):
    schema_version: Literal[2]
    occurrence_id: str
    source_repo: str
    kind: Literal["ci_monitor"]
    pass_id: int
    page: int
    code: str
    incident_id: str


class CIPageOccurrence(TypedDict):
    schema_version: Literal[2]
    occurrence_id: str
    source_repo: str
    kind: Literal["ci_page"]
    pass_id: int
    page: int
    payload_sha256: str
    run_ids: list[int]


CIEvent: TypeAlias = CIAttemptObservation | CIFailureOccurrence | CIMonitorOccurrence | CIPageOccurrence


class ValidCIEvent(TypedDict):
    status: Literal["valid"]
    value: CIEvent


class InvalidCIEvent(TypedDict):
    status: Literal["invalid"]
    code: str


CIEventValidation: TypeAlias = ValidCIEvent | InvalidCIEvent


def ci_cursor_key(source_repo: str) -> str:
    """Return the independent v2 cursor key for one fixed repository."""
    if source_repo not in SOURCE_REPOSITORIES:
        raise ValueError("unknown_source_repository")
    return CI_CURSOR_PREFIX + source_repo.replace("/", ":")


def initial_ci_cursor(source_repo: str) -> CICursor:
    """Start an unfiltered run-history sweep at page one."""
    if source_repo not in SOURCE_REPOSITORIES:
        raise ValueError("unknown_source_repository")
    return {
        "schema_version": 2,
        "source_repo": source_repo,
        "pass_id": 0,
        "next_page": 1,
        "previous_page_ids": [],
    }


def validate_ci_cursor(value: object, source_repo: str) -> CICursorValidation:
    """Promote the persisted JSON cursor only after exact shape and bound checks."""
    if source_repo not in SOURCE_REPOSITORIES:
        return {"status": "invalid", "code": "unknown_source_repository"}
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "source_repo", "pass_id", "next_page", "previous_page_ids",
    }:
        return {"status": "invalid", "code": "ci_cursor_shape"}
    if (
        not isinstance(value.get("schema_version"), int) or isinstance(value.get("schema_version"), bool)
        or value["schema_version"] != 2 or value.get("source_repo") != source_repo
    ):
        return {"status": "invalid", "code": "ci_cursor_identity"}
    if not is_int(value.get("pass_id")) or value["pass_id"] > MAX_SAFE_COUNTER:
        return {"status": "invalid", "code": "ci_cursor_pass"}
    if not is_int(value.get("next_page"), minimum=1) or value["next_page"] > MAX_CI_PAGE:
        return {"status": "invalid", "code": "ci_cursor_page"}
    ids = value.get("previous_page_ids")
    if not isinstance(ids, list) or len(ids) > CI_PAGE_SIZE:
        return {"status": "invalid", "code": "ci_cursor_previous_ids"}
    if any(not is_int(run_id, minimum=1) for run_id in ids) or len(set(ids)) != len(ids):
        return {"status": "invalid", "code": "ci_cursor_previous_ids"}
    if (value["next_page"] == 1) != (not ids):
        return {"status": "invalid", "code": "ci_cursor_previous_ids"}
    return {"status": "valid", "value": cast(CICursor, value)}


def _safe_text(value: object, *, max_length: int = 512) -> bool:
    if (
        not isinstance(value, str) or not 0 < len(value) <= max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _valid_ref(value: object) -> bool:
    if not _safe_text(value, max_length=255) or value == "@" or value.startswith("/"):
        return False
    if value.endswith(("/", ".")) or ".." in value or "//" in value or "@{" in value:
        return False
    if any(character.isspace() or character in ("~", "^", ":", "?", "*", "[", "\\") for character in value):
        return False
    components = value.split("/")
    return all(component and not component.startswith(".") and not component.lower().endswith(".lock") for component in components)


def _valid_https_url(value: object, host: str, path: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https" and parts.hostname == host and port is None
        and parts.username is None and parts.password is None
        and parts.path == path and not parts.query and not parts.fragment
    )


def _valid_run_path(value: object) -> str | None:
    if not _safe_text(value, max_length=512) or not value.startswith(".github/workflows/"):
        return None
    filename, separator, ref = value.partition("@")
    if not re.fullmatch(r"\.github/workflows/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.ya?ml", filename):
        return None
    if separator and not _safe_text(ref, max_length=255):
        return None
    return filename


def _repository_matches(value: object, source_repo: str) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict):
        return False
    full_name = value.get("full_name")
    if full_name is not None:
        return full_name == source_repo
    owner = value.get("owner")
    name = value.get("name")
    return isinstance(owner, dict) and owner.get("login") == source_repo.split("/", 1)[0] and name == source_repo.split("/", 1)[1]


def normalize_run(
    value: object,
    source_repo: str,
    *,
    expected_run_id: int | None = None,
    expected_attempt: int | None = None,
) -> CIRunAttempt | None:
    """Validate one untrusted workflow-run row, including repository and run URLs."""
    if source_repo not in SOURCE_REPOSITORIES or not isinstance(value, dict):
        return None
    run_id = value.get("id")
    attempt = value.get("run_attempt")
    workflow_id = value.get("workflow_id")
    if not is_int(run_id, minimum=1) or not is_int(attempt, minimum=1) or not is_int(workflow_id, minimum=1):
        return None
    if attempt > MAX_CI_ATTEMPTS or (expected_run_id is not None and run_id != expected_run_id):
        return None
    if expected_attempt is not None and attempt != expected_attempt:
        return None
    api_path = f"/repos/{source_repo}/actions/runs/{run_id}"
    html_path = f"/{source_repo}/actions/runs/{run_id}"
    api_url = value.get("url")
    html_url = value.get("html_url")
    for url, host, base in ((api_url, "api.github.com", api_path), (html_url, "github.com", html_path)):
        if not isinstance(url, str):
            return None
        suffix = f"/attempts/{attempt}"
        if not (_valid_https_url(url, host, base) or _valid_https_url(url, host, base + suffix)):
            return None
    if not _repository_matches(value.get("repository"), source_repo):
        return None
    workflow_path = _valid_run_path(value.get("path"))
    head_sha = value.get("head_sha")
    head_ref = value.get("head_branch")
    status = value.get("status")
    conclusion = value.get("conclusion")
    if (
        workflow_path is None or not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None
        or not _valid_ref(head_ref) or status not in CI_STATUS_VALUES
    ):
        return None
    if status == "completed":
        if conclusion not in CI_CONCLUSION_VALUES:
            return None
        result: CIRunAttempt = {
            "source_repo": source_repo, "run_id": run_id, "run_attempt": attempt,
            "workflow_id": workflow_id, "workflow_path": workflow_path,
            "head_sha": head_sha, "head_ref": head_ref,
            "status": "completed", "conclusion": cast(CIConclusion, conclusion),
        }
    else:
        if conclusion is not None:
            return None
        result = {
            "source_repo": source_repo, "run_id": run_id, "run_attempt": attempt,
            "workflow_id": workflow_id, "workflow_path": workflow_path,
            "head_sha": head_sha, "head_ref": head_ref,
            "status": cast(Any, status), "conclusion": None,
        }
    return result


def _validate_run(value: object, source_repo: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "source_repo", "run_id", "run_attempt", "workflow_id", "workflow_path",
        "head_sha", "head_ref", "status", "conclusion",
    }:
        return False
    if value.get("source_repo") != source_repo:
        return False
    if not is_int(value.get("run_id"), minimum=1) or not is_int(value.get("run_attempt"), minimum=1):
        return False
    if value["run_attempt"] > MAX_CI_ATTEMPTS or not is_int(value.get("workflow_id"), minimum=1):
        return False
    workflow_path = _valid_run_path(value.get("workflow_path"))
    if workflow_path is None or workflow_path != value.get("workflow_path"):
        return False
    if not isinstance(value.get("head_sha"), str) or _SHA.fullmatch(value["head_sha"]) is None:
        return False
    if not _valid_ref(value.get("head_ref")):
        return False
    if value.get("status") == "completed":
        return value.get("conclusion") in CI_CONCLUSION_VALUES
    return value.get("status") in CI_STATUS_VALUES and value.get("status") != "completed" and value.get("conclusion") is None


def _valid_job_url(value: object, path: str, host: str) -> bool:
    return value is None or _valid_https_url(value, host, path)


def normalize_job(value: object, run: CIRunAttempt) -> CIJob | None:
    """Validate one job and every step against its requested run and attempt."""
    if not isinstance(value, dict):
        return None
    job_id = value.get("id")
    if (
        not is_int(job_id, minimum=1) or value.get("run_id") != run["run_id"]
        or not is_int(value.get("run_id"), minimum=1)
        or value.get("run_attempt") != run["run_attempt"]
        or not is_int(value.get("run_attempt"), minimum=1)
    ):
        return None
    run_path = f"/repos/{run['source_repo']}/actions/runs/{run['run_id']}"
    attempt_path = f"{run_path}/attempts/{run['run_attempt']}"
    if not any(
        _valid_https_url(value.get("run_url"), "api.github.com", path)
        for path in (run_path, attempt_path)
    ):
        return None
    job_path = f"/repos/{run['source_repo']}/actions/jobs/{job_id}"
    html_job_path = f"/{run['source_repo']}/actions/runs/{run['run_id']}/job/{job_id}"
    if not _valid_job_url(value.get("url"), job_path, "api.github.com"):
        return None
    if not _valid_job_url(value.get("html_url"), html_job_path, "github.com"):
        return None
    name = value.get("name")
    status = value.get("status")
    conclusion = value.get("conclusion")
    if not _safe_text(name, max_length=512) or status not in JOB_STATUS_VALUES:
        return None
    if (status == "completed" and conclusion not in CI_CONCLUSION_VALUES) or (status != "completed" and conclusion is not None):
        return None
    raw_steps = value.get("steps")
    if not isinstance(raw_steps, list) or len(raw_steps) > MAX_CI_STEPS:
        return None
    steps: list[CIStep] = []
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            return None
        step_name = raw_step.get("name")
        step_status = raw_step.get("status")
        step_conclusion = raw_step.get("conclusion")
        if not _safe_text(step_name, max_length=512) or step_status not in STEP_STATUS_VALUES:
            return None
        if (step_status == "completed" and step_conclusion not in CI_CONCLUSION_VALUES) or (
            step_status != "completed" and step_conclusion is not None
        ):
            return None
        steps.append({"name": step_name, "status": step_status, "conclusion": step_conclusion})
    return {
        "id": job_id, "run_id": run["run_id"], "run_attempt": run["run_attempt"],
        "name": name, "status": status, "conclusion": conclusion, "steps": steps,
    }


def _validate_job(value: object, run: CIRunAttempt) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "id", "run_id", "run_attempt", "name", "status", "conclusion", "steps",
    }:
        return False
    # Reuse the API promoter with fixed canonical URLs; it still checks nested state.
    raw = {
        **value,
        "run_url": f"https://api.github.com/repos/{run['source_repo']}/actions/runs/{run['run_id']}",
    }
    return normalize_job(raw, run) == value
