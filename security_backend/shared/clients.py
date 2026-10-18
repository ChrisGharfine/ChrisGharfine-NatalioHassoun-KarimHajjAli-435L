"""Bounded, authenticated HTTP calls; never read another service's tables."""

import uuid

import requests
from flask import current_app

from .errors import APIError


def service_headers():
    name = current_app.config["SERVICE_NAME"]
    return {"X-Service-Name": name, "X-Service-Key": current_app.config["SERVICE_TOKENS"][name]}


def call_users(path, method="GET", token=None):
    headers = service_headers()
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        response = requests.request(method, current_app.config["USERS_URL"] +
                                    current_app.config["API_PREFIX"] + path,
                                    headers=headers, timeout=current_app.config["SERVICE_TIMEOUT"])
        if response.status_code in (401, 403) and token:
            raise APIError(401, "INVALID_TOKEN", "The account is unavailable or inactive.")
        if response.status_code == 404:
            raise APIError(400, "INVALID_REFERENCE", "The referenced user does not exist.")
        response.raise_for_status()
        return response.json()["data"]
    except (requests.RequestException, ValueError, KeyError, TypeError):
        raise APIError(503, "IDENTITY_UNAVAILABLE", "The identity service is unavailable.") from None


def log_event(payload, event_id=None):
    """Reuse event_id on retries. Raise on failure; callers must retain the event."""
    event_id = event_id or str(uuid.uuid4())
    try:
        response = requests.post(current_app.config["LOGS_URL"] + current_app.config["API_PREFIX"] +
                                 "/internal/logs", json=payload,
                                 headers={**service_headers(), "Idempotency-Key": event_id},
                                 timeout=current_app.config["SERVICE_TIMEOUT"])
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError):
        raise APIError(503, "AUDIT_UNAVAILABLE", "Audit delivery is unavailable; retain and retry this event.") from None
