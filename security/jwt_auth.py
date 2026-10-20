"""Local verification of the access tokens Natalio's Users service issues.

This is the first half of section 4 of team-integration-v1.0.0. It proves
the token was signed with the shared secret and carries the claims v1
requires. It deliberately does **not** decide what the caller may do:
``role`` and ``account_status`` are not trusted from the token, because a
token minted before a suspension would still carry the old values. The
current authority comes from :mod:`security.identity`.

:author: Karim Hajj Ali
"""

import math
import re
import jwt

import config


class TokenError(Exception):
    """Raised when a bearer token cannot be accepted.

    :param message: Why the token was rejected, safe to return to the caller.
    :type message: str
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


#: Claims that must be present. ``role`` and ``account_status`` are
#: deliberately absent: section 4.1 forbids using them as the authority.
REQUIRED_CLAIMS = ("sub", "iat", "exp", "iss", "aud", "type")

#: The only accepted value of the ``type`` claim.
EXPECTED_TOKEN_TYPE = "access"


def verify_access_token(token):
    """Verify a bearer token and return its claims.

    The algorithm is pinned to HS256 from configuration and never read from
    the token header, so a token claiming ``alg: none`` or asking for an
    asymmetric algorithm is rejected before any signature work happens.

    :param token: The raw JWT from the ``Authorization`` header.
    :type token: str
    :raises TokenError: If the signature, claims, issuer, audience, type or
        expiry are wrong.
    :return: The decoded claims.
    :rtype: dict
    """
    if not token:
        raise TokenError("Authentication required")

    try:
        claims = jwt.decode(
            token,
            config.jwt_verification_key(),
            algorithms=[config.JWT_ALGORITHM],
            issuer=config.JWT_ISSUER,
            audience=config.JWT_AUDIENCE,
            options={
                "require": list(REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "strict_aud": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("Token has expired. Please log in again.")
    except jwt.ImmatureSignatureError:
        raise TokenError("Token is not valid yet")
    except jwt.InvalidIssuerError:
        raise TokenError("Token issuer is not accepted")
    except jwt.InvalidAudienceError:
        raise TokenError("Token audience is not accepted")
    except jwt.MissingRequiredClaimError as error:
        raise TokenError("Token is missing the '%s' claim" % error.claim)
    except jwt.InvalidTokenError:
        # Covers bad signatures, wrong algorithms and malformed tokens. The
        # message stays generic so it cannot be used to probe the secret.
        raise TokenError("Token is invalid")
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise TokenError("Token is invalid") from None

    if any(type(claims[name]) not in (int, float) or not math.isfinite(claims[name])
           for name in ("iat", "exp", "nbf") if name in claims):
        raise TokenError("Token dates must be finite numbers")
    if claims["exp"] <= claims["iat"]:
        raise TokenError("Token expiry must follow issue time")

    if claims.get("type") != EXPECTED_TOKEN_TYPE:
        raise TokenError("Only access tokens are accepted here")

    claims["sub_id"] = _subject_id(claims.get("sub"))
    return claims


def _subject_id(subject):
    """Convert the ``sub`` claim into a positive integer user id.

    Section 4.1 encodes the user id as text, and section 3 bounds user
    identities at 2147483647 to match Natalio's integer primary key.

    :param subject: The raw ``sub`` claim.
    :type subject: object
    :raises TokenError: If it is not a positive integer in range.
    :return: The user id.
    :rtype: int
    """
    if not isinstance(subject, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", subject):
        raise TokenError("Token subject is not a valid user id")
    user_id = int(subject)

    if user_id <= 0 or user_id > 2147483647:
        raise TokenError("Token subject is out of range")
    return user_id


def bearer_token_from(headers):
    """Pull the bearer token out of an ``Authorization`` header.

    :param headers: The request headers.
    :type headers: werkzeug.datastructures.Headers
    :return: The token, or ``None`` when the header is absent or malformed.
    :rtype: str or NoneType
    """
    header = headers.get("Authorization", "")
    if header.startswith("Bearer "):
        candidate = header[len("Bearer "):].strip()
        return candidate or None
    return None
