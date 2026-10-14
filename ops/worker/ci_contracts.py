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
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;\"']+")
_CREDENTIAL = re.compile(
    r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_JSON_STRING_TOKEN = re.compile(r'(?<!\\)"(?:\\[^\r\n]|[^"\\\r\n])*(?:"|\\?(?=$|[\r\n]))')
_JSON_KEY_SEPARATOR = re.compile(r"\s*:")
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


def make_ci_attempt_occurrence_id(source_repo: str, run_id: int, attempt: int) -> str:
    """Identify immutable evidence by repository, run and attempt—not mutable timestamps."""
    if source_repo not in SOURCE_REPOSITORIES or not is_int(run_id, minimum=1) or not is_int(attempt, minimum=1):
        raise ValueError("invalid_ci_attempt_identity")
    if attempt > MAX_CI_ATTEMPTS:
        raise ValueError("ci_attempt_limit")
    payload = stable_json(["ci-attempt", source_repo, run_id, attempt])
    return "occ_" + hashlib.sha256(payload.encode()).hexdigest()


def make_ci_monitor_occurrence_id(source_repo: str, pass_id: int, page: int, code: str) -> str:
    """Deduplicate the same safe monitoring signal while a page remains pending."""
    if (
        source_repo not in SOURCE_REPOSITORIES or not is_int(pass_id)
        or pass_id > MAX_SAFE_COUNTER or not is_int(page, minimum=1)
    ):
        raise ValueError("invalid_ci_monitor_identity")
    if page > MAX_CI_PAGE or not isinstance(code, str) or _CODE.fullmatch(code) is None:
        raise ValueError("invalid_ci_monitor_code")
    payload = stable_json(["ci-monitor", source_repo, pass_id, page, code])
    return "occ_" + hashlib.sha256(payload.encode()).hexdigest()


def make_ci_page_occurrence_id(source_repo: str, pass_id: int, page: int, payload_sha256: str) -> str:
    """Checkpoint one validated page payload in one full-history sweep."""
    if (
        source_repo not in SOURCE_REPOSITORIES or not is_int(pass_id)
        or pass_id > MAX_SAFE_COUNTER or not is_int(page, minimum=1) or page > MAX_CI_PAGE
        or not isinstance(payload_sha256, str) or _SHA256.fullmatch(payload_sha256) is None
    ):
        raise ValueError("invalid_ci_page_identity")
    payload = stable_json(["ci-page", source_repo, pass_id, page, payload_sha256])
    return "occ_" + hashlib.sha256(payload.encode()).hexdigest()


def ci_monitor_identity(source_repo: str, code: str) -> IncidentIdentity:
    """Group only by stable safe monitor code; never include response text or secrets."""
    if source_repo not in SOURCE_REPOSITORIES or not isinstance(code, str) or _CODE.fullmatch(code) is None:
        raise ValueError("invalid_ci_monitor_code")
    identity: dict[str, object] = {
        "source_repo": source_repo,
        "category": "ci_monitoring",
        "component": "github_actions",
        "mode": "unknown",
        "error_family": code,
    }
    incident_id = "inc_" + hashlib.sha256(stable_json(identity).encode()).hexdigest()
    return cast(IncidentIdentity, {"id": incident_id, **identity})


def _strip_envelope(text: str) -> str:
    clean = _ANSI.sub("", text)
    return "\n".join(_TIMESTAMP.sub("", line, count=1) for line in clean.splitlines())


def _redact_secret_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    replacement = f"{value[0]}[redacted]{value[0]}" if value[0] in ("\"", "'") else "[redacted]"
    return match.group("key") + match.group("separator") + replacement


def _redact_credentials(text: str, token: str) -> str:
    """Apply the existing credential filters to raw or decoded diagnostic text."""
    clean = _PEM_PRIVATE_KEY.sub("[redacted-private-key]", text)
    if token:
        clean = clean.replace(token, "[redacted]")
    clean = _BEARER.sub("Bearer [redacted]", clean)
    clean = _SECRET_ASSIGNMENT.sub(_redact_secret_assignment, clean)
    return _CREDENTIAL.sub("[redacted]", clean)


def _redact_json_uri_token(match: re.Match[str], token: str) -> str:
    """Redact decoded credentials and URIs; fail closed on unreadable fragments."""
    raw_token = match.group(0)
    try:
        value = json.loads(raw_token)
    except ValueError:
        # Keep the marker unquoted so malformed producer JSON stays malformed.
        return "[redacted-json-string]"
    if not isinstance(value, str):
        return raw_token
    if (
        _JSON_KEY_SEPARATOR.match(match.string, match.end()) is not None
        and _SECRET_ASSIGNMENT.fullmatch(json.dumps(value) + ":0") is not None
    ):
        return json.dumps(value)
    redacted = _redact_credentials(value, token)
    redacted = _URL.sub("[redacted-url]", redacted)
    return json.dumps(redacted) if redacted != value else raw_token


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON objects instead of accepting duplicate last-key-wins data."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def sanitize_diagnostic(text: str, token: str = "") -> str:
    """Redact credentials and URLs before diagnostic text is hashed or retained."""
    clean = _redact_credentials(_strip_envelope(text), token)
    clean = _JSON_STRING_TOKEN.sub(lambda match: _redact_json_uri_token(match, token), clean)
    clean = _redact_credentials(clean, token)
    return _URL.sub("[redacted-url]", clean)


def _scenario(value: object, run_id: int) -> dict[str, object] | None:
    if not isinstance(value, dict) or set(value) != {
        "status", "runId", "tab", "elapsedMs", "apiCalls", "throttled429", "steps",
    }:
        return None
    status = value.get("status")
    if status not in ("passed", "failed", "misconfigured"):
        return None
    if not _safe_text(value.get("runId"), max_length=128) or value["runId"] != str(run_id):
        return None
    tab = value.get("tab")
    if tab is not None and not _safe_text(tab, max_length=255):
        return None
    for field in ("elapsedMs", "apiCalls", "throttled429"):
        if not is_int(value.get(field)) or value[field] > MAX_SAFE_COUNTER:
            return None
    steps = value.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        return None
    normalized: list[dict[str, str]] = []
    for step in steps:
        if not isinstance(step, dict) or set(step) not in (
            {"name", "status"}, {"name", "status", "detail"},
        ):
            return None
        if not _safe_text(step.get("name"), max_length=128) or step.get("status") not in ("ok", "failed", "skipped"):
            return None
        detail = step.get("detail")
        if "detail" in step and not _safe_text(detail, max_length=512):
            return None
        normalized.append({"name": step["name"], "status": step["status"], **({"detail": detail} if "detail" in step else {})})
    return {
        "status": status, "runId": value["runId"], "tab": tab,
        "elapsedMs": value["elapsedMs"], "apiCalls": value["apiCalls"],
        "throttled429": value["throttled429"], "steps": normalized,
    }


def scenario_verdicts(diagnostics: list[CIDiagnostic], run_id: int) -> list[dict[str, object]]:
    """Find only complete, strictly validated, run-bound scenario verdict objects."""
    found: list[dict[str, object]] = []
    for diagnostic in diagnostics:
        for line in diagnostic["text"].splitlines():
            candidate = line.strip()
            if not candidate.startswith("{"):
                continue
            try:
                normalized = _scenario(json.loads(candidate, object_pairs_hook=_json_object), run_id)
            except (TypeError, ValueError, RecursionError):
                normalized = None
            if normalized is not None:
                found.append(normalized)
    return found


def scenario_mode(diagnostics: list[CIDiagnostic], run_id: int) -> Literal["local", "sync", "unknown"]:
    """Infer mode only from an unambiguous run-bound scenario boot step."""
    modes: set[str] = set()
    for verdict in scenario_verdicts(diagnostics, run_id):
        if verdict["status"] == "misconfigured":
            continue
        for step in verdict["steps"]:
            if step["status"] == "ok" and step["name"] in ("sync-boot", "local-boot"):
                modes.add("sync" if step["name"] == "sync-boot" else "local")
    if len(modes) != 1:
        return "unknown"
    return cast(Literal["local", "sync"], next(iter(modes)))


def _known_failure_family(run_id: int, diagnostics: list[CIDiagnostic]) -> str | None:
    for verdict in scenario_verdicts(diagnostics, run_id):
        steps = verdict["steps"]
        if (
            verdict["status"] == "failed"
            and any(step["name"] == "sync-boot" and step["status"] == "ok" for step in steps)
            and any(
                step["name"] == "ingest-poll" and step["status"] == "failed"
                and step.get("detail") == "ingest-timeout"
                for step in steps
            )
        ):
            return "scenario_ingest_timeout"
    if any(
        line.strip() == "rm: cannot remove '/tmp/live-verify/run/summary.json': Permission denied"
        for diagnostic in diagnostics for line in diagnostic["text"].splitlines()
    ):
        return "artifact_permission_denied"
    return None


def ci_failure_identity(
    source_repo: str,
    run: CompletedRunAttempt,
    jobs: list[CIJob],
    diagnostics: list[CIDiagnostic],
    mode: Literal["local", "sync", "unknown"],
) -> IncidentIdentity:
    """Group explicit known evidence; preserve all unknown text/numbers by digest."""
    if source_repo not in SOURCE_REPOSITORIES or run["source_repo"] != source_repo:
        raise ValueError("ci_failure_source_mismatch")
    if mode != scenario_mode(diagnostics, run["run_id"]):
        raise ValueError("ci_failure_mode_mismatch")
    known = _known_failure_family(run["run_id"], diagnostics)
    if known is None:
        signature = {
            "failed_jobs": [
                {"name": job["name"], "conclusion": job["conclusion"], "steps": [
                    {"name": step["name"], "conclusion": step["conclusion"]}
                    for step in job["steps"] if step["conclusion"] not in (None, "success", "skipped", "neutral")
                ]}
                for job in jobs if job["conclusion"] in CI_FAILURE_CONCLUSIONS
            ],
            "diagnostics": [diagnostic["sha256"] for diagnostic in diagnostics],
        }
        family = "unclassified:" + hashlib.sha256(stable_json(signature).encode()).hexdigest()
        component = "workflow_run"
    else:
        family = known
        component = "human_lane" if known == "scenario_ingest_timeout" else "artifact_cleanup"
    identity: dict[str, object] = {
        "source_repo": source_repo,
        "category": "ci_failure",
        "component": component,
        "mode": mode,
        "error_family": family,
    }
    incident_id = "inc_" + hashlib.sha256(stable_json(identity).encode()).hexdigest()
    return cast(IncidentIdentity, {"id": incident_id, **identity})


def make_ci_attempt_event(run: CompletedRunAttempt, jobs: list[CIJob]) -> CIAttemptObservation:
    """Build immutable non-failure evidence after every requested jobs page validates."""
    return {
        "schema_version": 2,
        "occurrence_id": make_ci_attempt_occurrence_id(run["source_repo"], run["run_id"], run["run_attempt"]),
        "source_repo": run["source_repo"], "kind": "ci_attempt", "run": run, "jobs": jobs,
    }


def make_ci_failure_event(
    run: CompletedRunAttempt,
    jobs: list[CIJob],
    diagnostics: list[CIDiagnostic],
) -> tuple[CIFailureOccurrence, IncidentIdentity]:
    """Bind one immutable failed run attempt to safely classified diagnostic evidence."""
    mode = scenario_mode(diagnostics, run["run_id"])
    identity = ci_failure_identity(run["source_repo"], run, jobs, diagnostics, mode)
    event: CIFailureOccurrence = {
        "schema_version": 2,
        "occurrence_id": make_ci_attempt_occurrence_id(run["source_repo"], run["run_id"], run["run_attempt"]),
        "source_repo": run["source_repo"], "kind": "ci_failure", "run": run,
        "jobs": jobs, "diagnostics": diagnostics, "mode": mode, "incident_id": identity["id"],
    }
    return event, identity


def make_ci_monitor_event(source_repo: str, pass_id: int, page: int, code: str) -> tuple[CIMonitorOccurrence, IncidentIdentity]:
    """Create a safe durable monitor occurrence without embedding provider payloads."""
    identity = ci_monitor_identity(source_repo, code)
    event: CIMonitorOccurrence = {
        "schema_version": 2,
        "occurrence_id": make_ci_monitor_occurrence_id(source_repo, pass_id, page, code),
        "source_repo": source_repo, "kind": "ci_monitor", "pass_id": pass_id,
        "page": page, "code": code, "incident_id": identity["id"],
    }
    return event, identity


def make_ci_page_event(
    source_repo: str, pass_id: int, page: int, payload_sha256: str, run_ids: list[int],
) -> CIPageOccurrence:
    """Create a payload-specific page checkpoint without retaining raw GitHub JSON."""
    return {
        "schema_version": 2,
        "occurrence_id": make_ci_page_occurrence_id(source_repo, pass_id, page, payload_sha256),
        "source_repo": source_repo, "kind": "ci_page", "pass_id": pass_id,
        "page": page, "payload_sha256": payload_sha256, "run_ids": run_ids,
    }


def _valid_jobs(value: object, run: CompletedRunAttempt) -> bool:
    if not isinstance(value, list) or len(value) > MAX_CI_JOBS:
        return False
    ids: set[int] = set()
    for job in value:
        if not _validate_job(job, run) or job["id"] in ids:
            return False
        ids.add(job["id"])
    return True


def validate_ci_event(value: object) -> CIEventValidation:
    """Validate a stored CI event independently from the file-specific QA contract."""
    if not isinstance(value, dict):
        return {"status": "invalid", "code": "ci_event_not_object"}
    kind = value.get("kind")
    common = {"schema_version", "occurrence_id", "source_repo", "kind"}
    repo = value.get("source_repo")
    occurrence_id = value.get("occurrence_id")
    version = value.get("schema_version")
    if (
        not isinstance(version, int) or isinstance(version, bool) or version != 2
        or repo not in SOURCE_REPOSITORIES
    ):
        return {"status": "invalid", "code": "ci_event_identity"}
    if not isinstance(occurrence_id, str) or re.fullmatch(r"occ_[0-9a-f]{64}", occurrence_id) is None:
        return {"status": "invalid", "code": "ci_event_occurrence"}
    if kind in ("ci_attempt", "ci_failure"):
        expected = common | {"run", "jobs"}
        if kind == "ci_failure":
            expected |= {"diagnostics", "mode", "incident_id"}
        if set(value) != expected:
            return {"status": "invalid", "code": "ci_attempt_shape"}
        run = value.get("run")
        if not _validate_run(run, repo) or run.get("status") != "completed":
            return {"status": "invalid", "code": "ci_attempt_run"}
        try:
            expected_id = make_ci_attempt_occurrence_id(repo, run["run_id"], run["run_attempt"])
        except ValueError:
            return {"status": "invalid", "code": "ci_attempt_identity"}
        if occurrence_id != expected_id or not _valid_jobs(value.get("jobs"), cast(CompletedRunAttempt, run)):
            return {"status": "invalid", "code": "ci_attempt_identity"}
        jobs = cast(list[CIJob], value["jobs"])
        if kind == "ci_attempt":
            if run["conclusion"] in CI_FAILURE_CONCLUSIONS:
                return {"status": "invalid", "code": "ci_failure_misclassified"}
        else:
            diagnostics = value.get("diagnostics")
            if not isinstance(diagnostics, list) or len(diagnostics) > MAX_CI_DIAGNOSTICS:
                return {"status": "invalid", "code": "ci_diagnostics_shape"}
            for diagnostic in diagnostics:
                if not isinstance(diagnostic, dict) or set(diagnostic) != {"job_id", "sha256", "text", "truncated"}:
                    return {"status": "invalid", "code": "ci_diagnostic_shape"}
                if (
                    not is_int(diagnostic.get("job_id"), minimum=1)
                    or not isinstance(diagnostic.get("sha256"), str)
                    or _SHA256.fullmatch(diagnostic["sha256"]) is None
                    or not isinstance(diagnostic.get("text"), str)
                    or len(diagnostic["text"]) > MAX_DIAGNOSTIC_TEXT
                    or not isinstance(diagnostic.get("truncated"), bool)
                ):
                    return {"status": "invalid", "code": "ci_diagnostic_fields"}
                try:
                    diagnostic_bytes = diagnostic["text"].encode("utf-8")
                except UnicodeEncodeError:
                    return {"status": "invalid", "code": "ci_diagnostic_fields"}
                if (
                    sanitize_diagnostic(diagnostic["text"]) != diagnostic["text"]
                    or (not diagnostic["truncated"] and hashlib.sha256(diagnostic_bytes).hexdigest() != diagnostic["sha256"])
                ):
                    return {"status": "invalid", "code": "ci_diagnostic_fields"}
                if diagnostic["job_id"] not in {job["id"] for job in jobs if job["conclusion"] in CI_FAILURE_CONCLUSIONS}:
                    return {"status": "invalid", "code": "ci_diagnostic_job"}
            diagnostic_jobs = [diagnostic["job_id"] for diagnostic in diagnostics]
            failed_job_ids = [job["id"] for job in jobs if job["conclusion"] in CI_FAILURE_CONCLUSIONS]
            if (
                len(diagnostic_jobs) != len(set(diagnostic_jobs))
                or set(diagnostic_jobs) != set(failed_job_ids)
                or any(job["status"] != "completed" for job in jobs)
            ):
                return {"status": "invalid", "code": "ci_diagnostic_job_set"}
            mode = value.get("mode")
            if mode not in ("local", "sync", "unknown"):
                return {"status": "invalid", "code": "ci_failure_mode"}
            try:
                identity = ci_failure_identity(repo, cast(CompletedRunAttempt, run), jobs, cast(list[CIDiagnostic], diagnostics), mode)
            except ValueError:
                return {"status": "invalid", "code": "ci_failure_classification"}
            if value.get("incident_id") != identity["id"] or run["conclusion"] not in CI_FAILURE_CONCLUSIONS:
                return {"status": "invalid", "code": "ci_failure_incident"}
            if not any(job["conclusion"] in CI_FAILURE_CONCLUSIONS for job in jobs):
                return {"status": "invalid", "code": "ci_failure_jobs"}
        return {"status": "valid", "value": cast(CIEvent, value)}
    if kind == "ci_monitor":
        if set(value) != common | {"pass_id", "page", "code", "incident_id"}:
            return {"status": "invalid", "code": "ci_monitor_shape"}
        if not is_int(value.get("pass_id")) or not is_int(value.get("page"), minimum=1):
            return {"status": "invalid", "code": "ci_monitor_position"}
        if not isinstance(value.get("code"), str) or _CODE.fullmatch(value["code"]) is None:
            return {"status": "invalid", "code": "ci_monitor_code"}
        try:
            expected_id = make_ci_monitor_occurrence_id(repo, value["pass_id"], value["page"], value["code"])
            incident = ci_monitor_identity(repo, value["code"])
        except ValueError:
            return {"status": "invalid", "code": "ci_monitor_identity"}
        if occurrence_id != expected_id or value.get("incident_id") != incident["id"]:
            return {"status": "invalid", "code": "ci_monitor_identity"}
        return {"status": "valid", "value": cast(CIEvent, value)}
    if kind == "ci_page":
        if set(value) != common | {"pass_id", "page", "payload_sha256", "run_ids"}:
            return {"status": "invalid", "code": "ci_page_shape"}
        if not is_int(value.get("pass_id")) or not is_int(value.get("page"), minimum=1):
            return {"status": "invalid", "code": "ci_page_position"}
        digest = value.get("payload_sha256")
        run_ids = value.get("run_ids")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            return {"status": "invalid", "code": "ci_page_digest"}
        if (
            not isinstance(run_ids, list) or len(run_ids) > CI_PAGE_SIZE
            or any(not is_int(run_id, minimum=1) for run_id in run_ids)
            or len(set(run_ids)) != len(run_ids)
        ):
            return {"status": "invalid", "code": "ci_page_runs"}
        try:
            expected_id = make_ci_page_occurrence_id(repo, value["pass_id"], value["page"], digest)
        except ValueError:
            return {"status": "invalid", "code": "ci_page_identity"}
        if occurrence_id != expected_id:
            return {"status": "invalid", "code": "ci_page_identity"}
        return {"status": "valid", "value": cast(CIEvent, value)}
    return {"status": "invalid", "code": "ci_event_kind"}
