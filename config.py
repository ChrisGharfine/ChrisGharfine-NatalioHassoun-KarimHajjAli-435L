"""Configuration for Karim's three services under team-integration-v1.0.0.

Everything here comes from the environment. No secret has a usable default:
the JWT verification key and the service keys must be supplied, and the
process refuses to start a protected service without them rather than
falling back to something guessable.

See ``.env.example`` for a secret-free template.

:author: Karim Hajj Ali
"""

import os

# ---------------------------------------------------------------------------
# Service identity
# ---------------------------------------------------------------------------

#: The three service names I own, as registered in section 2 of the spec.
SERVICE_INCIDENTS = "incidents"
SERVICE_VULNERABILITIES = "vulnerabilities"
SERVICE_NOTIFICATIONS = "notifications"

MY_SERVICES = (SERVICE_INCIDENTS, SERVICE_VULNERABILITIES,
               SERVICE_NOTIFICATIONS)

#: Every service name in the system, used to validate inbound service keys.
ALL_SERVICES = ("users", "assets", "incidents", "threats", "logs", "reports",
                "vulnerabilities", "notifications", "playbooks")

#: Default development ports from section 2.
DEFAULT_PORTS = {
    SERVICE_INCIDENTS: 8003,
    SERVICE_VULNERABILITIES: 8007,
    SERVICE_NOTIFICATIONS: 8008,
}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def database_url():
    """Return the PostgreSQL connection string.

    :raises RuntimeError: If ``KARIM_DATABASE_URL`` is not set.
    :return: A libpq connection URI.
    :rtype: str
    """
    url = os.environ.get("KARIM_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "KARIM_DATABASE_URL is not set. Example: "
            "postgresql://postgres:PASSWORD@127.0.0.1:5432/sirms_integration")
    return url


# ---------------------------------------------------------------------------
# JWT verification (section 4.1)
# ---------------------------------------------------------------------------

#: HS256 is the only algorithm accepted. The algorithm is never read from an
#: untrusted token header.
JWT_ALGORITHM = "HS256"

JWT_ISSUER = os.environ.get("KARIM_JWT_ISSUER", "security-sprint1-users")
JWT_AUDIENCE = os.environ.get("KARIM_JWT_AUDIENCE",
                              "security-sprint1-services")


def jwt_verification_key():
    """Return the shared HS256 verification key.

    :raises RuntimeError: If the key is missing or shorter than 32 bytes.
    :return: The verification key.
    :rtype: str
    """
    key = os.environ.get("KARIM_JWT_VERIFICATION_KEY")
    if not key:
        raise RuntimeError(
            "KARIM_JWT_VERIFICATION_KEY is not set. It must match the secret "
            "Natalio's Users service signs with, and be at least 32 bytes.")
    if len(key.encode("utf-8")) < 32:
        raise RuntimeError(
            "KARIM_JWT_VERIFICATION_KEY must be at least 32 bytes.")
    return key


# ---------------------------------------------------------------------------
# Upstream service base URLs (section 2)
# ---------------------------------------------------------------------------
# Each value is the COMPLETE base URL including any path prefix. The resource
# path is appended exactly once. Natalio's services carry an /api prefix;
# Chris's and mine do not.

USERS_BASE_URL = os.environ.get(
    "KARIM_USERS_URL", "http://127.0.0.1:8001/api/natalio-hassoun")
ASSETS_BASE_URL = os.environ.get(
    "KARIM_ASSETS_URL", "http://127.0.0.1:8002")
LOGS_BASE_URL = os.environ.get(
    "KARIM_LOGS_URL", "http://127.0.0.1:8005/api/natalio-hassoun")
NOTIFICATIONS_BASE_URL = os.environ.get(
    "KARIM_NOTIFICATIONS_URL", "http://127.0.0.1:8008")

#: Finite per-call timeout. Section 5 caps this at five seconds.
HTTP_TIMEOUT_SECONDS = float(os.environ.get("KARIM_HTTP_TIMEOUT_SECONDS", "5"))


# ---------------------------------------------------------------------------
# Service-to-service keys (section 4.2)
# ---------------------------------------------------------------------------

def my_service_key(service_name):
    """Return the outbound key this process presents as its own identity.

    :param service_name: One of :data:`MY_SERVICES`.
    :type service_name: str
    :raises RuntimeError: If the key for that service is not configured.
    :return: The service key.
    :rtype: str
    """
    variable = "KARIM_%s_SERVICE_KEY" % service_name.upper()
    key = os.environ.get(variable)
    if not key:
        raise RuntimeError(
            "%s is not set. Each of my three services needs its own distinct "
            "key, separate from the JWT secret." % variable)
    return key


def trusted_service_tokens():
    """Return the inbound service keys this process will accept.

    Used by the Notifications internal endpoint to authenticate callers.
    Configured as ``KARIM_SERVICE_TOKENS`` in ``name:key`` pairs separated by
    commas, for example ``incidents:abc,vulnerabilities:def``.

    :return: Mapping of service name to key. Empty when unset.
    :rtype: dict
    """
    raw = os.environ.get("KARIM_SERVICE_TOKENS", "")
    tokens = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, key = pair.partition(":")
        name = name.strip()
        key = key.strip()
        if name and key:
            tokens[name] = key
    return tokens


# ---------------------------------------------------------------------------
# Delivery worker
# ---------------------------------------------------------------------------

#: How many outbox rows one flush pass claims.
OUTBOX_BATCH_SIZE = int(os.environ.get("KARIM_OUTBOX_BATCH_SIZE", "50"))

#: Exponential backoff ceiling, in seconds (section 6).
OUTBOX_MAX_BACKOFF_SECONDS = int(
    os.environ.get("KARIM_OUTBOX_MAX_BACKOFF_SECONDS", "300"))

#: Seconds the worker sleeps between passes when running continuously.
WORKER_POLL_SECONDS = float(os.environ.get("KARIM_WORKER_POLL_SECONDS", "5"))
