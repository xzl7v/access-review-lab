"""Capture a GitHub account's effective repository role through the REST API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPException
import json
import re
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

API = "https://api.github.com"
API_VERSION = "2026-03-10"
CAPTURE_VERSION = 1
ACCESS_MODEL = "github_effective"
SOURCE = "github_permission"
PERMISSIONS = {"admin", "write", "read", "none"}
ACCOUNT_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}")
REPO_NAME = re.compile(r"[a-zA-Z0-9._-]{1,100}")
REQUEST_ID = re.compile(r"[a-zA-Z0-9:_-]{1,128}")
RESPONSE_LIMIT = 256 * 1024


@dataclass(frozen=True)
class EffectiveRole:
    repository: str
    repository_id: int
    login: str
    user_id: int
    permission: str
    role_name: str


def validate_target(repository: str, login: str) -> None:
    """Validate the two path components and account before making a request."""
    owner, slash, name = repository.partition("/")
    if not slash or not ACCOUNT_NAME.fullmatch(owner) or not REPO_NAME.fullmatch(name) or name in {".", ".."}:
        raise ValueError("repository must use the GitHub OWNER/REPO format")
    if not ACCOUNT_NAME.fullmatch(login):
        raise ValueError("account must be a GitHub login")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(opener, path: str, token: str) -> dict:
    request = Request(API + path, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Cache-Control": "no-cache",
        "User-Agent": "Access-Review-Lab",
        "X-GitHub-Api-Version": API_VERSION,
    })
    try:
        with opener.open(request, timeout=15) as response:
            status = response.status
            request_id = response.headers.get("X-GitHub-Request-Id", "")
            data = response.read(RESPONSE_LIMIT + 1)
    except HTTPError as exc:
        with exc:
            request_id = exc.headers.get("X-GitHub-Request-Id", "")
            return _receipt(exc.code, request_id)
    except (OSError, HTTPException):
        return {"status": None, "request_id": None, "problem": "The request did not complete."}
    receipt = _receipt(status, request_id)
    if status != 200:
        return receipt
    try:
        payload = json.loads(data) if len(data) <= RESPONSE_LIMIT else None
    except (ValueError, RecursionError):
        payload = None
    if not isinstance(payload, dict):
        return {**receipt, "problem": "The response did not contain a usable JSON object."}
    return {**receipt, "data": payload}


def _receipt(status: int, request_id: str) -> dict:
    return {"status": status, "request_id": request_id if REQUEST_ID.fullmatch(request_id) else None}


def _fields(data: object, *names: str) -> dict:
    if not isinstance(data, dict):
        return {}
    return {name: data[name] for name in names if name in data and type(data[name]) in (str, int, type(None))}


def _payload(receipt: object, label: str) -> dict:
    if not isinstance(receipt, dict):
        raise ValueError(f"GitHub {label} was not collected.")
    status = receipt.get("status")
    if type(status) is not int:
        raise ValueError(f"GitHub {label} did not complete.")
    if status != 200:
        raise ValueError(f"GitHub returned HTTP {status} for {label}.")
    data = receipt.get("data")
    if not isinstance(data, dict):
        raise ValueError(f"GitHub {label} returned an unusable response.")
    return data


def _identity(data: dict, key: str, requested: str, label: str) -> tuple[str, int]:
    name, identifier = data.get(key), data.get("id")
    if (not isinstance(name, str) or name.lower() != requested.lower()
            or type(identifier) is not int or identifier <= 0):
        raise ValueError(f"GitHub {label} did not confirm the requested identity.")
    return name, identifier


def effective_role(capture: dict) -> EffectiveRole:
    """Read an explicit role response and bind it to confirmed GitHub identities."""
    repository, login = capture.get("repository"), capture.get("account")
    if not isinstance(repository, str) or not isinstance(login, str):
        raise ValueError("GitHub capture needs a repository and an account.")
    validate_target(repository, login)
    metadata = _payload(capture.get("repository_lookup"), "repository lookup")
    canonical_repo, repository_id = _identity(metadata, "full_name", repository, "repository lookup")
    details = _payload(capture.get("role_lookup"), "role lookup")
    account = details.get("user")
    if account is None and details.get("permission") == "none":
        account = _payload(capture.get("account_lookup"), "account lookup")
    if not isinstance(account, dict):
        raise ValueError("GitHub role lookup did not identify the account.")
    canonical_login, user_id = _identity(account, "login", login, "account lookup")
    permission, role_name = details.get("permission"), details.get("role_name")
    if not isinstance(permission, str) or permission not in PERMISSIONS:
        raise ValueError("GitHub role lookup did not return a recognized permission.")
    if permission == "none" and role_name in ("none", None):
        role_name = "none"
    if (not isinstance(role_name, str) or not role_name or role_name.strip() != role_name
            or (role_name.lower() == "none") != (permission == "none")):
        raise ValueError("GitHub role lookup returned an inconsistent role.")
    return EffectiveRole(canonical_repo, repository_id, canonical_login, user_id, permission, role_name)


def capture_role(repository: str, login: str, token: str) -> dict:
    """Record only the fields that support the permission finding."""
    validate_target(repository, login)
    if not token or not token.isascii() or any(char.isspace() for char in token):
        raise ValueError("set GITHUB_TOKEN to a GitHub token for the repository")
    opener = build_opener(_NoRedirect())
    started = datetime.now(timezone.utc).isoformat()
    repository_lookup = _request(opener, f"/repos/{repository}", token)
    role_lookup = None
    account_lookup = None
    if "data" in repository_lookup:
        repository_lookup["data"] = _fields(repository_lookup["data"], "full_name", "id")
        try:
            _identity(repository_lookup["data"], "full_name", repository, "repository lookup")
        except ValueError:
            pass
        else:
            role_lookup = _request(opener, f"/repos/{repository}/collaborators/{login}/permission", token)
    if role_lookup is not None and "data" in role_lookup:
        response = role_lookup["data"]
        role_lookup["data"] = _fields(response, "permission", "role_name")
        if "user" in response and response["user"] is not None:
            role_lookup["data"]["user"] = _fields(response["user"], "login", "id")
        elif response.get("permission") == "none":
            account_lookup = _request(opener, f"/users/{login}", token)
            if "data" in account_lookup:
                account_lookup["data"] = _fields(account_lookup["data"], "login", "id")
    capture = {
        "capture_version": CAPTURE_VERSION,
        "origin": "github",
        "api_version": API_VERSION,
        "started_at": started,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "repository": repository,
        "account": login,
        "repository_lookup": repository_lookup,
        "role_lookup": role_lookup,
    }
    if account_lookup is not None:
        capture["account_lookup"] = account_lookup
    return capture
