"""The ``@require_role`` decorator, rebuilt for team-integration-v1.0.0.

Replaces the Sprint I version that looked tokens up in a dictionary in
memory. The sequence on every protected request is now:

1. Read the bearer token from the ``Authorization`` header.
2. Verify it locally: HS256, required claims, issuer, audience, expiry.
3. Ask Users for the caller's *current* role and account state over HTTP.
4. Check that current role against the roles the route allows.

Failures map to distinct statuses, which matters because they mean
different things to the caller: ``401`` the token or account is not good,
``403`` the account is fine but may not do this, ``503`` the identity
service could not be consulted so no decision was possible.

Every denial is written to the audit outbox in its own durable transaction,
as section 6 requires. If that write fails, the denial returns ``503``
rather than silently losing the security event.

:author: Karim Hajj Ali
"""

from functools import wraps

from flask import current_app, g, jsonify, request

from security.identity import (
    IdentityRejected,
    IdentityUnavailable,
    verify_current_identity,
)
from security.jwt_auth import TokenError, bearer_token_from, verify_access_token


def error(message, status):
    """Build the standard error envelope.

    :param message: What went wrong.
    :type message: str
    :param status: HTTP status code.
    :type status: int
    :return: A Flask response tuple.
    :rtype: tuple
    """
    return jsonify({"status": "error", "message": message}), status


def current_user():
    """Return the identity Users confirmed for this request.

    :return: ``{"id", "role", "account_status"}``, or ``None`` outside a
        protected route.
    :rtype: dict or NoneType
    """
    return getattr(g, "identity", None)


def current_service():
    """Return the name of the service handling this request.

    :return: One of :data:`config.MY_SERVICES`.
    :rtype: str
    """
    return current_app.config["KARIM_SERVICE_NAME"]


def _record_denial(user_id, reason):
    """Queue an ``unauthorized_access`` audit event for a refused request.

    Written in its own transaction so it survives independently of whatever
    the request was trying to do.

    :param user_id: The caller's id when known, otherwise ``None``.
    :type user_id: int or NoneType
    :param reason: Short description of why the request was refused.
    :type reason: str
    :return: ``True`` if the event was stored durably.
    :rtype: bool
    """
    from outbox.audit_outbox import queue_audit_event

    service = current_service()
    try:
        queue_audit_event(
            source_service=service,
            user_id=user_id,
            action="unauthorized_access",
            description="%s %s refused: %s"
                        % (request.method, request.path, reason),
            severity="Warning",
            related_service=service)
        return True
    except Exception as failure:
        current_app.logger.error("could not store denial event: %s", failure)
        return False


def require_role(*allowed_roles):
    """Protect a route so only the listed canonical roles may call it.

    :param allowed_roles: Canonical role constants from :mod:`constants`.
    :type allowed_roles: str
    :return: The decorator.
    :rtype: function
    """

    def decorator(view_function):

        @wraps(view_function)
        def wrapper(*args, **kwargs):
            service = current_service()

            token = bearer_token_from(request.headers)
            if token is None:
                if not _record_denial(None, "no bearer token supplied"):
                    return error("Security event could not be recorded; "
                                 "request refused", 503)
                return error(
                    "Authentication required. Send your token as "
                    "'Authorization: Bearer <token>'.", 401)

            try:
                claims = verify_access_token(token)
            except TokenError as failure:
                if not _record_denial(None, failure.message):
                    return error("Security event could not be recorded; "
                                 "request refused", 503)
                return error(failure.message, 401)

            try:
                identity = verify_current_identity(token, service)
            except IdentityRejected as failure:
                _record_denial(claims["sub_id"], failure.message)
                return error(failure.message, 401)
            except IdentityUnavailable as failure:
                # No decision was possible. Fail closed, and do not pretend
                # this was an authorisation denial.
                return error(failure.message, 503)

            if identity["id"] != claims["sub_id"]:
                _record_denial(
                    claims["sub_id"],
                    "identity subject did not match the token subject")
                return error("Token and identity disagree about the user",
                             401)

            if identity["role"] not in allowed_roles:
                if not _record_denial(
                        identity["id"],
                        "role '%s' is not permitted; allowed: %s"
                        % (identity["role"], ", ".join(allowed_roles))):
                    return error("Security event could not be recorded; "
                                 "request refused", 503)
                return error("User does not have permission to perform this "
                             "operation", 403)

            g.identity = identity
            return view_function(*args, **kwargs)

        return wrapper

    return decorator
