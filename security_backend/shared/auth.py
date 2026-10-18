"""Reuse protected() in teammate services with the same configuration and JWT setup."""

import hmac
from functools import wraps

from flask import current_app, g, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from sqlalchemy import select

from ..models import User
from .clients import call_users
from .errors import APIError


def service_auth():
    name = request.headers.get("X-Service-Name", "")
    supplied = request.headers.get("X-Service-Key", "")
    expected = current_app.config["SERVICE_TOKENS"].get(name)
    if not expected or not hmac.compare_digest(expected, supplied):
        raise APIError(401, "INVALID_SERVICE", "Valid service credentials are required.")
    return name


def local_identity(identity):
    if not isinstance(identity, str) or not identity.isdecimal() or not 0 < int(identity) <= 2147483647:
        raise APIError(401, "INVALID_TOKEN", "Invalid token identity.")
    user = g.db.scalar(select(User).where(User.id == int(identity), User.deleted_at.is_(None)))
    if not user or user.account_status != "active":
        raise APIError(401, "INVALID_TOKEN", "The account is unavailable or inactive.")
    return {"id": user.id, "role": user.role, "account_status": user.account_status}


def protected(*roles):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            verify_jwt_in_request()
            identity = get_jwt_identity()
            if not isinstance(identity, str) or not identity.isdecimal() or not 0 < int(identity) <= 2147483647:
                raise APIError(401, "INVALID_TOKEN", "Invalid token identity.")
            if current_app.config["SERVICE_NAME"] == "users":
                g.actor = local_identity(identity)
            else:
                token = request.headers["Authorization"].split()[1]
                g.actor = call_users("/internal/identity/verify", method="POST", token=token)
            if roles and g.actor["role"] not in roles:
                raise APIError(403, "FORBIDDEN", "You do not have permission to perform this operation.")
            return function(*args, **kwargs)
        return wrapped
    return decorate
