"""Team v1 access-token validation, shared by all protected entry points."""

import math

import jwt
from flask import current_app, request
from flask_jwt_extended import verify_jwt_in_request

from .errors import APIError


def valid_user_id(value):
    return type(value) is int and 0 < value <= 2147483647


def verify_access_request():
    """Verify the signed wire claims, including claims Flask may default away.

    Flask-JWT-Extended supplies type=access when absent. Team v1 requires that
    claim on the original token, so a second strict decode is intentional.
    """
    try:
        verify_jwt_in_request()
        claims = jwt.decode(
            request.headers["Authorization"].split()[1],
            current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"],
            issuer=current_app.config["JWT_DECODE_ISSUER"],
            audience=current_app.config["JWT_DECODE_AUDIENCE"],
            options={"require": ["sub", "iat", "exp", "iss", "aud", "type"]},
        )
        subject = claims["sub"]
        if (not isinstance(subject, str) or not subject.isascii()
                or not subject.isdecimal() or len(subject) > 10
                or not valid_user_id(int(subject)) or claims["type"] != "access"):
            raise ValueError("Invalid access identity/type")
        for name in ("iat", "exp", "nbf"):
            if name in claims and (type(claims[name]) not in (int, float)
                                   or not math.isfinite(claims[name])):
                raise ValueError("Numeric dates required")
        if claims["exp"] <= claims["iat"]:
            raise ValueError("Invalid token interval")
    except jwt.ExpiredSignatureError:
        raise APIError(401, "TOKEN_EXPIRED", "The token has expired.") from None
    except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError):
        raise APIError(401, "INVALID_TOKEN", "The token does not satisfy the team access-token contract.") from None
    return claims
