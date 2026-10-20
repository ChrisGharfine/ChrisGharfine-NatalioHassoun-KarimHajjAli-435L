"""Internal service credentials, separate from user authentication."""

import secrets
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .auth import persist_denial
from .database import get_session
from .errors import ApiError


@dataclass(frozen=True)
class ServicePrincipal:
    service_name: str


def service_headers(settings, service_name: str) -> dict[str, str]:
    try:
        key = settings.service_key(service_name)
    except ValueError:
        raise ApiError(503, "Required service credentials are not configured") from None
    return {"X-Service-Name": service_name, "X-Service-Key": key}


def allow_services(*allowed_services: str):
    def authorized(request: Request, session: Session = Depends(get_session)) -> ServicePrincipal:
        name = request.headers.get("X-Service-Name", "")
        supplied = request.headers.get("X-Service-Key", "")
        configured = request.app.state.settings.service_tokens.get(name)
        if (configured is None or not supplied or len(supplied) > 8192
                or not secrets.compare_digest(supplied.encode(), configured.get_secret_value().encode())):
            persist_denial(request, session, user_id=None)
            raise ApiError(401, "Valid service credentials are required")
        if name not in allowed_services:
            persist_denial(request, session, user_id=None)
            raise ApiError(403, "Service does not have permission to perform this operation")
        return ServicePrincipal(name)
    return authorized
