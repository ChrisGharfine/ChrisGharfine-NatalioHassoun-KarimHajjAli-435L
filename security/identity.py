"""Current-identity lookup against Natalio's Users service.

Second half of section 4. After the token has been verified locally, every
protected request asks Users who the caller is *right now*. There is no
cache, deliberately: a role change, suspension or deletion has to take
effect on the very next request made with the same token.

Three outcomes matter, and they are different on purpose:

* identity says inactive, suspended or deleted -> ``401``
* identity is healthy but the role is not allowed here -> ``403``
* Users is unreachable, slow, or answers something unexpected -> ``503``

The last one is the important one. An outage must never be read as
permission; the service fails closed.

:author: Karim Hajj Ali
"""

import requests

import config
import constants


class IdentityUnavailable(Exception):
    """Raised when Users cannot be consulted, or answered unusably.

    Maps to ``503``.

    :param message: Safe explanation for the caller.
    :type message: str
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class IdentityRejected(Exception):
    """Raised when Users says this identity may not authenticate.

    Maps to ``401``.

    :param message: Safe explanation for the caller.
    :type message: str
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def verify_current_identity(user_jwt, calling_service):
    """Ask Users for the caller's current role and account state.

    :param user_jwt: The original bearer token the caller presented.
    :type user_jwt: str
    :param calling_service: Which of my services is asking, used as the
        ``X-Service-Name`` header.
    :type calling_service: str
    :raises IdentityRejected: If the account cannot authenticate.
    :raises IdentityUnavailable: If Users is unreachable or malformed.
    :return: ``{"id": int, "role": str, "account_status": str}``.
    :rtype: dict
    """
    url = "%s/internal/identity/verify" % config.USERS_BASE_URL.rstrip("/")

    try:
        response = requests.post(
            url,
            headers={
                "Authorization": "Bearer %s" % user_jwt,
                "X-Service-Name": calling_service,
                "X-Service-Key": config.my_service_key(calling_service),
            },
            timeout=config.HTTP_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.Timeout:
        raise IdentityUnavailable(
            "The identity service did not respond in time")
    except requests.RequestException:
        raise IdentityUnavailable("The identity service is unreachable")

    if response.status_code in (401, 403):
        raise IdentityRejected(
            "This account is not permitted to authenticate")

    if response.status_code != 200:
        raise IdentityUnavailable(
            "The identity service returned an unexpected status")

    try:
        body = response.json()
    except ValueError:
        raise IdentityUnavailable(
            "The identity service returned a non-JSON response")

    return _parse_identity(body)


def _parse_identity(body):
    """Validate the identity envelope and extract the fields v1 defines.

    :param body: Parsed JSON from Users.
    :type body: object
    :raises IdentityRejected: If the account is not active.
    :raises IdentityUnavailable: If the envelope is not the documented shape.
    :return: The validated identity.
    :rtype: dict
    """
    if not isinstance(body, dict) or body.get("status") != "success":
        raise IdentityUnavailable(
            "The identity service returned an unrecognised envelope")

    data = body.get("data")
    if not isinstance(data, dict):
        raise IdentityUnavailable(
            "The identity service returned no identity data")

    raw_id = data.get("id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int) or raw_id <= 0:
        raise IdentityUnavailable(
            "The identity service returned an invalid user id")

    role = constants.canonical_role(data.get("role"))
    if role is None:
        raise IdentityUnavailable(
            "The identity service returned an unrecognised role")

    status = data.get("account_status")
    if status not in constants.ACCOUNT_STATUSES:
        raise IdentityUnavailable(
            "The identity service returned an unrecognised account status")

    if status != constants.ACCOUNT_ACTIVE:
        raise IdentityRejected("This account is %s" % status)

    if data.get("deleted") is True:
        raise IdentityRejected("This account has been deleted")

    return {"id": raw_id, "role": role, "account_status": status}


def lookup_user(user_id, calling_service):
    """Look up any user by id, using a service credential rather than a JWT.

    Section 4.3. Used when validating a reporter, an analyst being assigned
    an incident, or a notification recipient.

    :param user_id: The user to look up.
    :type user_id: int
    :param calling_service: Which of my services is asking.
    :type calling_service: str
    :raises IdentityUnavailable: If Users is unreachable or malformed.
    :return: ``{"id", "role", "account_status", "deleted"}``, or ``None``
        when Users reports the user does not exist.
    :rtype: dict or NoneType
    """
    url = "%s/internal/users/%d" % (config.USERS_BASE_URL.rstrip("/"),
                                    int(user_id))

    try:
        response = requests.get(
            url,
            headers={
                "X-Service-Name": calling_service,
                "X-Service-Key": config.my_service_key(calling_service),
            },
            timeout=config.HTTP_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.Timeout:
        raise IdentityUnavailable("The users service did not respond in time")
    except requests.RequestException:
        raise IdentityUnavailable("The users service is unreachable")

    if response.status_code == 404:
        return None

    if response.status_code != 200:
        raise IdentityUnavailable(
            "The users service returned an unexpected status")

    try:
        body = response.json()
    except ValueError:
        raise IdentityUnavailable(
            "The users service returned a non-JSON response")

    if not isinstance(body, dict) or body.get("status") != "success":
        raise IdentityUnavailable(
            "The users service returned an unrecognised envelope")

    data = body.get("data")
    if not isinstance(data, dict):
        raise IdentityUnavailable("The users service returned no user data")

    raw_id = data.get("id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int) or raw_id <= 0:
        raise IdentityUnavailable(
            "The users service returned an invalid user id")

    role = constants.canonical_role(data.get("role"))
    if role is None:
        raise IdentityUnavailable(
            "The users service returned an unrecognised role")

    status = data.get("account_status")
    if status not in constants.ACCOUNT_STATUSES:
        raise IdentityUnavailable(
            "The users service returned an unrecognised account status")

    return {
        "id": raw_id,
        "role": role,
        "account_status": status,
        "deleted": bool(data.get("deleted", False)),
    }


def is_assignable(user):
    """Check that a user may receive new ownership or an assignment.

    Section 4.3 rejects deleted and non-active accounts for new work while
    still allowing historical references to them.

    :param user: A record from :func:`lookup_user`.
    :type user: dict
    :return: ``True`` if new work may be given to this user.
    :rtype: bool
    """
    return (user is not None
            and not user["deleted"]
            and user["account_status"] == constants.ACCOUNT_ACTIVE)
