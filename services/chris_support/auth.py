import re
from dataclasses import dataclass
from enum import StrEnum

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .audit import enqueue
from .database import get_session
from .errors import ApiError


class Role(StrEnum):
    ADMIN = "Security Administrator"
    ANALYST = "Security Analyst"
    EMPLOYEE = "Regular Employee/User"
    AUDITOR = "Auditor"


@dataclass(frozen=True)
class Principal:
    user_id: int
    role: Role
    token: str


bearer = HTTPBearer(auto_error=False)


def authenticated(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: Session = Depends(get_session),
) -> Principal:
    unauthorized = ApiError(401, "Valid authentication is required", {"WWW-Authenticate": "Bearer"})
    def reject():
        enqueue(
            session, user_id=None, action="authentication.denied",
            service=request.app.state.service_name, severity="warning",
            description=f"Invalid or missing credentials for {request.method} {request.url.path}",
        )
        session.commit()
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
            options={"require": [
                "exp", "iat", "iss", "aud", "sub", settings.jwt_role_claim,
                settings.jwt_account_status_claim,
            ]},
        )
        subject = claims["sub"]
        if not isinstance(subject, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", subject):
            raise ValueError("Invalid subject")
        user_id = int(subject)
        if user_id > 9_223_372_036_854_775_807:
            raise ValueError("Invalid subject")
        if any(type(claims[key]) not in {int, float} for key in ("exp", "iat")):
            raise ValueError("Invalid timestamp claims")
        if claims[settings.jwt_account_status_claim] != settings.jwt_active_status:
            raise ValueError("Account is not active")
        role = Role(claims[settings.jwt_role_claim])
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError):
        reject()
    return Principal(user_id, role, credentials.credentials)


def allow(*roles: Role):
    def authorized(
        request: Request, principal: Principal = Depends(authenticated),
        session: Session = Depends(get_session),
    ) -> Principal:
        if principal.role not in roles:
            enqueue(
                session, user_id=principal.user_id, action="authorization.denied",
                service=request.app.state.service_name, severity="warning",
                description=f"Denied {request.method} {request.url.path}",
            )
            # Persist the denial even though the protected operation is rejected.
            session.commit()
            raise ApiError(403, "User does not have permission to perform this operation")
        return principal
    return authorized
