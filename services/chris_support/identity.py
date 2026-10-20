"""Strict, bounded HTTP access to the Users identity/reference interfaces."""

import json

import httpx

from .errors import ApiError

CANONICAL_ROLES = frozenset({
    "security_administrator", "security_analyst", "regular_employee", "auditor",
})
ACCOUNT_STATES = frozenset({"active", "inactive", "suspended"})
MAX_USER_ID = 2_147_483_647


def user_id(value) -> int:
    if type(value) is not int or not 0 < value <= MAX_USER_ID:
        raise ValueError("Invalid user identifier")
    return value


def _request(client, settings, method: str, path: str, headers: dict[str, str], *, reference=False):
    try:
        with client.stream(
            method, settings.users_url + path, headers=headers,
            timeout=settings.http_timeout_seconds, follow_redirects=False,
        ) as response:
            if response.status_code == 401 and not reference:
                raise ApiError(401, "Valid authentication is required", {"WWW-Authenticate": "Bearer"})
            if response.status_code == 404 and reference:
                raise ApiError(404, "Asset owner does not exist")
            if response.status_code != 200:
                raise ApiError(503, "Users service is unavailable")
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise ApiError(503, "Users service returned invalid identity data")
            body = bytearray()
            for chunk in response.iter_bytes():
                if len(body) + len(chunk) > min(settings.max_upstream_bytes, 65_536):
                    raise ApiError(503, "Users service returned invalid identity data")
                body.extend(chunk)
    except httpx.HTTPError:
        raise ApiError(503, "Users service is unavailable") from None
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise ValueError("Missing success envelope")
        identity = payload["data"]
        if not isinstance(identity, dict):
            raise ValueError("Invalid data")
        user_id(identity["id"])
        if identity["role"] not in CANONICAL_ROLES or identity["account_status"] not in ACCOUNT_STATES:
            raise ValueError("Unknown identity values")
        if reference and type(identity["deleted"]) is not bool:
            raise ValueError("Invalid deleted flag")
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ApiError(503, "Users service returned invalid identity data") from None
    return identity


def current_identity(client, settings, service_name: str, token: str, subject: int) -> dict:
    from .service_auth import service_headers

    identity = _request(client, settings, "POST", "/internal/identity/verify", {
        **service_headers(settings, service_name), "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    if identity["id"] != subject:
        raise ApiError(503, "Users service returned inconsistent identity data")
    if identity["account_status"] != "active":
        raise ApiError(401, "Valid authentication is required", {"WWW-Authenticate": "Bearer"})
    return identity


def validate_asset_owner(client, settings, owner_id: int) -> None:
    from .service_auth import service_headers

    identity = _request(client, settings, "GET", f"/internal/users/{owner_id}", {
        **service_headers(settings, "assets"), "Accept": "application/json",
    }, reference=True)
    if identity["id"] != owner_id:
        raise ApiError(503, "Users service returned inconsistent identity data")
    if identity["deleted"] or identity["account_status"] != "active":
        raise ApiError(400, "Asset owner must be an active, available user")
