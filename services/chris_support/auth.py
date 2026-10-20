import math
import re
from dataclasses import dataclass
from enum import StrEnum

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .audit import enqueue
from .database import get_session
from .errors import ApiError
from .identity import MAX_USER_ID, current_identity


class Role(StrEnum):
    ADMIN = "security_administrator"
    ANALYST = "security_analyst"
    EMPLOYEE = "regular_employee"
    AUDITOR = "auditor"


# Explicit conversion for callers importing the old permission labels. Wire
# identity responses still require the canonical v1 values.
LEGACY_ROLES = {
    "Security Administrator": Role.ADMIN,
    "Security Analyst": Role.ANALYST,
    "Regular Employee/User": Role.EMPLOYEE,
    "Auditor": Role.AUDITOR,
}


@dataclass(frozen=True)
class Principal:
    user_id: int
    role: Role
    token: str


bearer = HTTPBearer(auto_error=False)


def persist_denial(request: Request, session: Session, *, user_id: int | None) -> None:
    # A route template avoids storing arbitrary path text or oversized input.
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    description = re.sub(r"[\x00-\x1f\x7f]", "?", f"Denied {request.method} {path}")[:2000]
    try:
        enqueue(
            session, user_id=user_id, action="unauthorized_access",
            service=request.app.state.service_name, severity="warning",
            description=description,
        )
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise ApiError(503, "Audit event storage is unavailable") from None


def authenticated(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: Session = Depends(get_session),
) -> Principal:
    unauthorized = ApiError(401, "Valid authentication is required", {"WWW-Authenticate": "Bearer"})
    def reject():
        persist_denial(request, session, user_id=None)
        raise unauthorized

    if credentials is None or len(credentials.credentials) > 8192:
        reject()
    settings = request.app.state.settings
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.jwt_verification_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm], issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "type"], "strict_aud": True},
        )
        subject = claims["sub"]
        if not isinstance(subject, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", subject):
            raise ValueError("Invalid subject")
        user_id = int(subject)
        if user_id > MAX_USER_ID:
            raise ValueError("Invalid subject")
        if any(type(claims[key]) not in {int, float} or not math.isfinite(claims[key])
               for key in ("exp", "iat", "nbf") if key in claims):
            raise ValueError("Invalid timestamp claims")
        if claims["type"] != "access":
            raise ValueError("An access token is required")
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        reject()
    try:
        identity = current_identity(
            request.app.state.http_client, settings, request.app.state.service_name,
            credentials.credentials, user_id,
        )
    except ApiError:
        persist_denial(request, session, user_id=None)
        raise
    role = Role(identity["role"])
    return Principal(user_id, role, credentials.credentials)


def allow(*roles: Role | str):
    permission_roles = {Role(LEGACY_ROLES.get(role, role)) for role in roles}
    def authorized(
        request: Request, principal: Principal = Depends(authenticated),
        session: Session = Depends(get_session),
    ) -> Principal:
        if principal.role not in permission_roles:
            persist_denial(request, session, user_id=principal.user_id)
            raise ApiError(403, "User does not have permission to perform this operation")
        return principal
    return authorized
