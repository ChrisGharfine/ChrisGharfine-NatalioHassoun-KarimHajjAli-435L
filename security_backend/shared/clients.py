"""Bounded, authenticated HTTP calls; never read another service's tables."""

import uuid

import requests
from flask import current_app

from .errors import APIError
from .constants import ACCOUNT_STATUSES, ROLES
from .tokens import valid_user_id


def service_headers():
    name = current_app.config["SERVICE_NAME"]
    return {"X-Service-Name": name, "X-Service-Key": current_app.config["SERVICE_TOKENS"][name]}


def call_users(path, method="GET", token=None):
    headers = service_headers()
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        # A local service call must not leak credentials to redirects or proxies.
        with requests.Session() as client:
            client.trust_env = False
            response = client.request(method, current_app.config["USERS_URL"] +
                                      current_app.config["API_PREFIX"] + path,
                                      headers=headers, timeout=current_app.config["SERVICE_TIMEOUT"],
                                      allow_redirects=False)
        if response.status_code in (401, 403) and token:
            if response.json().get("code") == "INVALID_SERVICE":
                raise APIError(503, "IDENTITY_UNAVAILABLE", "Identity service credentials were rejected.")
            raise APIError(401, "INVALID_TOKEN", "The account is unavailable or inactive.")
        if response.status_code == 404:
            raise APIError(400, "INVALID_REFERENCE", "The referenced user does not exist.")
        if response.status_code != 200:
            raise ValueError("Unexpected identity status")
        envelope = response.json()
        data = envelope["data"]
        if (envelope["status"] != "success" or not isinstance(data, dict)
                or not valid_user_id(data.get("id")) or data.get("role") not in ROLES
                or data.get("account_status") not in ACCOUNT_STATUSES):
            raise ValueError("Invalid identity response")
        if token:
            # Token was already verified locally by protected().
            from flask_jwt_extended import get_jwt_identity
            if data["id"] != int(get_jwt_identity()) or data["account_status"] != "active":
                raise ValueError("Identity does not match the verified subject")
        elif (data["id"] != int(path.rsplit("/", 1)[-1])
              or type(data.get("deleted")) is not bool):
            raise ValueError("Invalid reference response")
        return data
    except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError):
        raise APIError(503, "IDENTITY_UNAVAILABLE", "The identity service is unavailable.") from None


def log_event(payload, event_id=None):
    """Reuse event_id on retries. Raise on failure; callers must retain the event."""
    event_id = event_id or str(uuid.uuid4())
    try:
        with requests.Session() as client:
            client.trust_env = False
            response = client.post(current_app.config["LOGS_URL"] + current_app.config["API_PREFIX"] +
                                   "/internal/logs", json=payload,
                                   headers={**service_headers(), "Idempotency-Key": event_id},
                                   timeout=current_app.config["SERVICE_TIMEOUT"], allow_redirects=False)
        if response.status_code in (400, 401, 403, 404, 405, 413, 422):
            raise APIError(503, "AUDIT_REJECTED", "Audit input or credentials were rejected; inspect configuration before retrying.")
        if response.status_code == 409:
            if response.json().get("code") == "IDEMPOTENCY_CONFLICT":
                raise APIError(503, "AUDIT_IDEMPOTENCY_CONFLICT", "The audit event UUID conflicts with an accepted event.")
        if response.status_code not in (200, 201):
            raise ValueError("Unexpected audit status")
        envelope = response.json()
        data = envelope["data"]
        if (envelope["status"] != "success" or not isinstance(data, dict)
                or data.get("event_id") != event_id
                or type(data.get("duplicate")) is not bool
                or data["duplicate"] != (response.status_code == 200) or "log" not in data):
            raise ValueError("Invalid receipt envelope")
        log = data["log"]
        if log is None:
            if not data["duplicate"]:
                raise ValueError("New receipt needs a log")
        elif not isinstance(log, dict) or type(log.get("id")) is not int or log["id"] <= 0:
            raise ValueError("Invalid receipt log ID")
        return envelope
    except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError):
        raise APIError(503, "AUDIT_UNAVAILABLE", "Audit delivery is unavailable; retain and retry this event.") from None
