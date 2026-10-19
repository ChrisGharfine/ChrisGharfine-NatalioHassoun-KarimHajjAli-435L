"""Authentication of other services calling my internal endpoints.

Section 4.2: internal endpoints are reached with a service name and key, not
with a user's JWT. A user token is never a substitute for a service
credential, and each process presents only its own identity.

Used by ``POST /internal/notifications``.

:author: Karim Hajj Ali
"""

import hmac

import config


class ServiceAuthError(Exception):
    """Raised when a caller's service credentials are missing or wrong.

    :param message: Safe explanation for the caller.
    :type message: str
    :param status: HTTP status to return, ``401`` or ``403``.
    :type status: int
    """

    def __init__(self, message, status):
        super().__init__(message)
        self.message = message
        self.status = status


def authenticate_service(headers, allowed_callers=None):
    """Identify the service behind a request to an internal endpoint.

    :param headers: The request headers.
    :type headers: werkzeug.datastructures.Headers
    :param allowed_callers: Service names permitted on this endpoint. ``None``
        allows any registered service.
    :type allowed_callers: tuple, optional
    :raises ServiceAuthError: ``401`` when the name or key is missing or
        wrong, ``403`` when a valid service is not allowed here.
    :return: The authenticated service name.
    :rtype: str
    """
    name = (headers.get("X-Service-Name") or "").strip()
    key = (headers.get("X-Service-Key") or "").strip()

    if not name or not key:
        raise ServiceAuthError(
            "X-Service-Name and X-Service-Key are required", 401)

    registered = config.trusted_service_tokens()
    expected = registered.get(name)

    if expected is None:
        # Unknown service name. Compared against a dummy value anyway so the
        # response time does not reveal whether the name was registered.
        hmac.compare_digest(key, "0" * len(key))
        raise ServiceAuthError("Invalid service credentials", 401)

    if not hmac.compare_digest(key, expected):
        raise ServiceAuthError("Invalid service credentials", 401)

    if allowed_callers is not None and name not in allowed_callers:
        raise ServiceAuthError(
            "Service '%s' is not permitted to call this endpoint" % name, 403)

    return name
