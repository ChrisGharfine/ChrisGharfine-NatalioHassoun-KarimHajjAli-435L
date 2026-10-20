"""End-to-end checks for services 3, 7 and 8 under team-integration-v1.0.0.

Replaces the Sprint I suite, which assumed SQLite, an in-memory token
dictionary and one process. This one runs the three services as three real
HTTP servers on their own ports, against real PostgreSQL, with Natalio's
and Chris's services replaced by :mod:`tests.upstream_double`.

**What this proves and what it does not.** It proves my services behave
correctly against the contracts written in v1. It does **not** prove live
integration: Natalio's and Chris's real services are never contacted.
Section 8 is explicit that "fixture responses are never real execution
evidence."

It uses a generated schema inside an existing dedicated *_test database.
Only that generated schema is removed; the integration database is never reset.

Run it with::

    python tests/test_integration_v1.py

:author: Karim Hajj Ali
"""

import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configuration must be in the environment before config.py is imported,
# because it reads the upstream URLs at import time.
_TEST_SECRET = "integration_test_secret_at_least_32_bytes_long_padding"
_UPSTREAM_PORT = 18001
_PORTS = {"incidents": 18003, "vulnerabilities": 18007,
          "notifications": 18008}

def _swap_database(url, database):
    """Point a connection string at a different database on the same server.

    Lets the suite derive its own database from ``KARIM_DATABASE_URL``
    rather than carrying a second copy of the credentials. No password is
    ever written into this file.

    :param url: An existing libpq connection URI.
    :type url: str
    :param database: The database name to switch to.
    :type database: str
    :raises RuntimeError: If no connection string is configured.
    :return: The rewritten URI.
    :rtype: str
    """
    if not url:
        raise RuntimeError(
            "Set KARIM_DATABASE_URL (or KARIM_TEST_DATABASE_URL) before "
            "running the tests. See .env.example.")
    base, _, _ = url.rpartition("/")
    return "%s/%s" % (base, database)


_SOURCE_URL = os.environ.get("KARIM_DATABASE_URL", "")
_TEST_DB = os.environ.get("KARIM_TEST_DATABASE_URL") or _swap_database(_SOURCE_URL, "sirms_test")
_TEST_SCHEMA = "karim_owned_test_" + uuid.uuid4().hex
_SCHEMA_CREATED = False
os.environ["KARIM_DATABASE_URL"] = _TEST_DB
os.environ["KARIM_JWT_VERIFICATION_KEY"] = _TEST_SECRET
os.environ["KARIM_USERS_URL"] = \
    "http://127.0.0.1:%d/api/natalio-hassoun" % _UPSTREAM_PORT
os.environ["KARIM_ASSETS_URL"] = "http://127.0.0.1:%d" % _UPSTREAM_PORT
os.environ["KARIM_LOGS_URL"] = \
    "http://127.0.0.1:%d/api/natalio-hassoun" % _UPSTREAM_PORT
os.environ["KARIM_NOTIFICATIONS_URL"] = \
    "http://127.0.0.1:%d/api/karim-hajj-ali" % _PORTS["notifications"]
os.environ["KARIM_INCIDENTS_SERVICE_KEY"] = "test-incidents-key"
os.environ["KARIM_VULNERABILITIES_SERVICE_KEY"] = "test-vulnerabilities-key"
os.environ["KARIM_NOTIFICATIONS_SERVICE_KEY"] = "test-notifications-key"
os.environ["KARIM_SERVICE_TOKENS"] = (
    "incidents:test-incidents-key,"
    "vulnerabilities:test-vulnerabilities-key,"
    "notifications:test-notifications-key,"
    "threats:test-threats-key")
os.environ["KARIM_HTTP_TIMEOUT_SECONDS"] = "3"
os.environ["KARIM_ALLOW_DEV_BOOTSTRAP"] = "yes"

import jwt  # noqa: E402
import psycopg  # noqa: E402
import requests  # noqa: E402
from wsgiref.simple_server import WSGIRequestHandler, make_server  # noqa: E402
import threading  # noqa: E402

import db  # noqa: E402
from tests import upstream_double  # noqa: E402

_RESULTS = {"passed": 0, "failed": 0}
_SERVERS = []
_STATE = upstream_double.UpstreamState(_TEST_SECRET)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def check(description, condition, detail=""):
    """Record one assertion and print the outcome.

    :param description: What was being checked.
    :type description: str
    :param condition: ``True`` if it passed.
    :type condition: bool
    :param detail: Context printed on failure.
    :type detail: str
    :return: ``None``
    :rtype: NoneType
    """
    if condition:
        _RESULTS["passed"] += 1
        print("  PASS  %s" % description)
    else:
        _RESULTS["failed"] += 1
        print("  FAIL  %s" % description)
        if detail:
            print("        %s" % str(detail)[:300])


def section(title):
    """Print a heading.

    :param title: Heading text.
    :type title: str
    :return: ``None``
    :rtype: NoneType
    """
    print("\n" + title)
    print("-" * len(title))


def token_for(user_id, **overrides):
    """Mint a JWT the way Natalio's Users service is specified to.

    :param user_id: Value of the ``sub`` claim.
    :type user_id: int
    :param overrides: Claims to replace or remove (pass ``None`` to drop).
    :type overrides: object
    :return: The encoded token.
    :rtype: str
    """
    now = int(time.time())
    claims = {"sub": str(user_id), "iat": now, "exp": now + 1800,
              "iss": "security-sprint1-users",
              "aud": "security-sprint1-services", "type": "access"}
    for key, value in overrides.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    return jwt.encode(claims, _TEST_SECRET, algorithm="HS256")


def auth(user_id):
    """Build an Authorization header for a user.

    :param user_id: The user to authenticate as.
    :type user_id: int
    :return: Headers.
    :rtype: dict
    """
    return {"Authorization": "Bearer %s" % token_for(user_id)}


def url(service, path):
    """Build a URL for one of my services.

    :param service: ``incidents``, ``vulnerabilities`` or ``notifications``.
    :type service: str
    :param path: Path beginning with ``/``.
    :type path: str
    :return: The full URL.
    :rtype: str
    """
    return "http://127.0.0.1:%d/api/karim-hajj-ali%s" % (_PORTS[service], path)


def get(service, path, user_id=None, headers=None):
    """Send a GET to one of my services.

    :param service: Target service.
    :type service: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param user_id: Authenticate as this user, defaults to None.
    :type user_id: int, optional
    :param headers: Extra headers, defaults to None.
    :type headers: dict, optional
    :return: The response.
    :rtype: requests.Response
    """
    merged = dict(headers or {})
    if user_id is not None:
        merged.update(auth(user_id))
    return requests.get(url(service, path), headers=merged, timeout=10)


def send(method, service, path, user_id=None, json=None, headers=None):
    """Send a request with a body to one of my services.

    :param method: HTTP method.
    :type method: str
    :param service: Target service.
    :type service: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param user_id: Authenticate as this user, defaults to None.
    :type user_id: int, optional
    :param json: JSON body, defaults to None.
    :type json: dict, optional
    :param headers: Extra headers, defaults to None.
    :type headers: dict, optional
    :return: The response.
    :rtype: requests.Response
    """
    merged = dict(headers or {})
    if user_id is not None:
        merged.update(auth(user_id))
    return requests.request(method, url(service, path), json=json,
                            headers=merged, timeout=10)


class _QuietHandler(WSGIRequestHandler):
    """Request handler that does not log each request."""

    def log_message(self, fmt, *args):
        """Swallow the access log.

        :param fmt: Format string.
        :type fmt: str
        :return: ``None``
        :rtype: NoneType
        """
        return


def start_services():
    """Start the three services and the upstream double.

    :return: ``None``
    :rtype: NoneType
    """
    from app_factory import create_app
    import config
    from services.incidents_api import incidents_bp
    from services.notifications_api import notifications_bp
    from services.vulnerabilities_api import vulnerabilities_bp

    _SERVERS.append(upstream_double.start(_STATE, _UPSTREAM_PORT))

    for name, blueprint in (("incidents", incidents_bp),
                            ("vulnerabilities", vulnerabilities_bp),
                            ("notifications", notifications_bp)):
        app = create_app(name, blueprint)
        server = make_server("127.0.0.1", _PORTS[name], app,
                             handler_class=_QuietHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        _SERVERS.append(server)

    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            if all(requests.get(url(n, "/health"), timeout=2).status_code
                   == 200 for n in _PORTS):
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError("services did not become healthy")


def prepare_database():
    """Create the test database, stand-ins and my tables.

    The integration database is never touched. Only my own tables and the
    development stand-ins are truncated between runs.

    :return: ``None``
    :rtype: NoneType
    """
    global _SCHEMA_CREATED
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    if not conninfo_to_dict(_TEST_DB).get("dbname", "").endswith("_test"):
        raise RuntimeError("Refusing tests: set an explicit dedicated *_test database")
    with psycopg.connect(_TEST_DB, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(_TEST_SCHEMA)))
    _SCHEMA_CREATED = True
    os.environ["KARIM_DATABASE_URL"] = make_conninfo(_TEST_DB, options="-csearch_path=" + _TEST_SCHEMA)

    import devtools.bootstrap_dev_dependencies as bootstrap
    with db.transaction() as cur:
        cur.execute(bootstrap.STANDIN_SQL)

    import migrate
    migrate.main([])

    # This schema is new and empty; never truncate existing database tables.
    with db.transaction() as cur:
        for user in upstream_double.USERS.values():
            cur.execute(
                "INSERT INTO users (id, username, full_name, role, "
                "account_status, deleted) VALUES (%s, %s, %s, %s, %s, %s)",
                (user["id"], "user%d" % user["id"], "User %d" % user["id"],
                 user["role"], user["account_status"], user["deleted"]))
        for asset in upstream_double.ASSETS.values():
            cur.execute(
                "INSERT INTO assets (id, name, asset_type, criticality, "
                "owner_id) VALUES (%s, %s, %s, %s, %s)",
                (asset["id"], asset["name"], "server", asset["criticality"],
                 asset["owner_id"]))


def flush_outboxes():
    """Deliver everything queued, so assertions see a settled state.

    :return: ``None``
    :rtype: NoneType
    """
    from outbox import audit_outbox, notification_outbox
    for _ in range(6):
        a = notification_outbox.deliver_pending()
        b = audit_outbox.deliver_pending()
        if a["attempted"] == 0 and b["attempted"] == 0:
            break


# ---------------------------------------------------------------------------
# Section 4 -- authentication
# ---------------------------------------------------------------------------

def test_authentication():
    """Check local token verification and the current-identity call.

    :return: ``None``
    :rtype: NoneType
    """
    section("Section 4 -- authentication and current identity")

    check("no token -> 401",
          get("incidents", "/incidents").status_code == 401)

    check("malformed token -> 401",
          get("incidents", "/incidents",
              headers={"Authorization": "Bearer not.a.jwt"}).status_code
          == 401)

    for label, overrides in (
            ("expired", {"exp": int(time.time()) - 60}),
            ("wrong issuer", {"iss": "attacker"}),
            ("wrong audience", {"aud": "someone-else"}),
            ("missing type claim", {"type": None}),
            ("missing sub", {"sub": None}),
            ("wrong token type", {"type": "refresh"})):
        token = jwt.encode(
            {k: v for k, v in
             {"sub": "1", "iat": int(time.time()),
              "exp": int(time.time()) + 1800,
              "iss": "security-sprint1-users",
              "aud": "security-sprint1-services",
              "type": "access", **overrides}.items() if v is not None},
            _TEST_SECRET, algorithm="HS256")
        response = get("incidents", "/incidents",
                       headers={"Authorization": "Bearer %s" % token})
        check("%s -> 401" % label, response.status_code == 401,
              response.text)

    unsigned = jwt.encode({"sub": "1", "iss": "security-sprint1-users",
                           "aud": "security-sprint1-services",
                           "type": "access"}, key="", algorithm="none")
    check("alg=none token -> 401",
          get("incidents", "/incidents",
              headers={"Authorization": "Bearer %s" % unsigned}).status_code
          == 401)

    wrong_key = jwt.encode(
        {"sub": "1", "iat": int(time.time()), "exp": int(time.time()) + 1800,
         "iss": "security-sprint1-users",
         "aud": "security-sprint1-services", "type": "access"},
        "a_different_secret_that_is_also_long_enough_32", algorithm="HS256")
    check("token signed with the wrong key -> 401",
          get("incidents", "/incidents",
              headers={"Authorization": "Bearer %s" % wrong_key}).status_code
          == 401)

    check("suspended account -> 401", get("incidents", "/incidents",
                                          user_id=6).status_code == 401)
    check("deleted account -> 401", get("incidents", "/incidents",
                                        user_id=7).status_code == 401)
    check("insufficient role -> 403", get("incidents", "/incidents",
                                          user_id=4).status_code == 403)
    check("administrator allowed -> 200", get("incidents", "/incidents",
                                              user_id=1).status_code == 200)
    check("auditor allowed -> 200", get("incidents", "/incidents",
                                        user_id=5).status_code == 200)

    _STATE.offline = True
    response = get("incidents", "/incidents", user_id=1)
    check("Users outage fails CLOSED with 503", response.status_code == 503,
          response.text)
    _STATE.offline = False

    check("recovers once Users returns",
          get("incidents", "/incidents", user_id=1).status_code == 200)


# ---------------------------------------------------------------------------
# Service 3
# ---------------------------------------------------------------------------

def test_incidents():
    """Exercise Service 3 against the v1 contracts.

    :return: The id of the incident used for the lifecycle walk.
    :rtype: int
    """
    section("Service 3 -- Incident Management")

    created = send("POST", "incidents", "/incidents", user_id=1, json={
        "title": "Ransomware detected on domain controller",
        "description": "Encryption activity flagged on the DC.",
        "category": "Malware Infection", "severity": "Critical",
        "affected_asset": 1})
    check("admin creates a Critical incident", created.status_code == 201,
          created.text)
    incident_id = created.json()["incident"]["incident_id"]

    body = created.json()["incident"]
    check("creation_date is timezone aware",
          isinstance(body["creation_date"], str)
          and ("+" in body["creation_date"]
               or body["creation_date"].endswith("Z")),
          body["creation_date"])
    check("joined display names are gone",
          "reporter_name" not in body and "affected_asset_name" not in body,
          sorted(body))

    employee = send("POST", "incidents", "/incidents", user_id=4, json={
        "title": "Phishing email", "description": "Credential request.",
        "category": "Phishing Attack", "severity": "Medium",
        "affected_asset": 3})
    check("employee reports an incident", employee.status_code == 201,
          employee.text)
    employee_incident = employee.json()["incident"]["incident_id"]
    check("employee is forced to be their own reporter",
          employee.json()["incident"]["reporter_id"] == 4)

    check("analyst cannot create -> 403",
          send("POST", "incidents", "/incidents", user_id=2,
               json={"title": "x", "description": "y", "category": "z",
                     "severity": "Low"}).status_code == 403)

    check("invalid severity -> 400",
          send("POST", "incidents", "/incidents", user_id=1,
               json={"title": "t", "description": "d", "category": "c",
                     "severity": "Catastrophic"}).status_code == 400)

    check("unknown asset -> 404",
          send("POST", "incidents", "/incidents", user_id=1,
               json={"title": "t", "description": "d", "category": "c",
                     "severity": "Low",
                     "affected_asset": 9999}).status_code == 404)

    listing = get("incidents", "/incidents", user_id=1).json()
    check("list envelope matches section 5",
          listing.get("status") == "success" and "count" in listing
          and isinstance(listing.get("incidents"), list),
          sorted(listing))
    check("count equals the array length",
          listing["count"] == len(listing["incidents"]))
    check("records carry incident_id, severity, status",
          all({"incident_id", "severity", "status"} <= set(r)
              for r in listing["incidents"]))

    check("employee reads their own incident",
          get("incidents", "/incidents/%d" % employee_incident,
              user_id=4).status_code == 200)
    check("employee cannot read another's -> 403",
          get("incidents", "/incidents/%d" % incident_id,
              user_id=4).status_code == 403)
    check("unknown incident -> 404",
          get("incidents", "/incidents/9999", user_id=1).status_code == 404)

    # -- assignment ---------------------------------------------------------
    assigned = send("PUT", "incidents", "/incidents/%d/assign" % incident_id,
                    user_id=1, json={"analyst_id": 2})
    check("assign to a real analyst -> 200", assigned.status_code == 200,
          assigned.text)

    check("assign to a non-analyst -> 400",
          send("PUT", "incidents", "/incidents/%d/assign" % incident_id,
               user_id=1, json={"analyst_id": 4}).status_code == 400)
    check("assign to a suspended analyst -> 400",
          send("PUT", "incidents", "/incidents/%d/assign" % incident_id,
               user_id=1, json={"analyst_id": 6}).status_code == 400)
    check("assign to an unknown user -> 404",
          send("PUT", "incidents", "/incidents/%d/assign" % incident_id,
               user_id=1, json={"analyst_id": 9999}).status_code == 404)
    check("analyst cannot assign -> 403",
          send("PUT", "incidents", "/incidents/%d/assign" % incident_id,
               user_id=2, json={"analyst_id": 3}).status_code == 403)

    # -- lifecycle ----------------------------------------------------------
    check("Open -> Closed rejected -> 400",
          send("PUT", "incidents", "/incidents/%d/status" % incident_id,
               user_id=2, json={"status": "Closed"}).status_code == 400)

    for expected in ("Under Investigation", "Mitigated", "Resolved",
                     "Closed"):
        step = send("PUT", "incidents",
                    "/incidents/%d/status" % incident_id, user_id=2,
                    json={"status": expected})
        check("status -> '%s'" % expected,
              step.status_code == 200
              and step.json()["incident"]["status"] == expected, step.text)

    final = get("incidents", "/incidents/%d" % incident_id,
                user_id=1).json()["incident"]
    check("resolution_date stamped and timezone aware",
          final["resolution_date"] is not None
          and ("+" in final["resolution_date"]
               or final["resolution_date"].endswith("Z")),
          final["resolution_date"])
    check("closed incident refuses further transitions -> 400",
          send("PUT", "incidents", "/incidents/%d/status" % incident_id,
               user_id=2, json={"status": "Open"}).status_code == 400)

    # -- notes --------------------------------------------------------------
    note = send("POST", "incidents", "/incidents/%d/notes" % incident_id,
                user_id=2, json={"note_content": "Host isolated."})
    check("analyst adds a note -> 201", note.status_code == 201, note.text)
    check("empty note -> 400",
          send("POST", "incidents", "/incidents/%d/notes" % incident_id,
               user_id=2, json={"note_content": "   "}).status_code == 400)
    check("note on unknown incident -> 404",
          send("POST", "incidents", "/incidents/9999/notes", user_id=2,
               json={"note_content": "x"}).status_code == 404)

    with_notes = get("incidents", "/incidents/%d" % incident_id,
                     user_id=1).json()["incident"]
    check("notes returned with the incident",
          len(with_notes["investigation_notes"]) == 1)

    return incident_id


# ---------------------------------------------------------------------------
# Service 7
# ---------------------------------------------------------------------------

def test_vulnerabilities():
    """Exercise Service 7 against the v1 contracts.

    :return: ``None``
    :rtype: NoneType
    """
    section("Service 7 -- Vulnerability Management")

    critical = send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
                    json={"title": "RCE in XZ Utils",
                          "description": "Backdoor allows RCE.",
                          "severity": "Critical", "affected_asset": 2,
                          "cve_identifier": "CVE-2024-3094",
                          "cvss_score": 10.0,
                          "discovery_source": "Vendor advisory"})
    check("admin registers a Critical vulnerability",
          critical.status_code == 201, critical.text)
    critical_id = critical.json()["vulnerability"]["vulnerability_id"]

    medium = send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
                  json={"title": "Outdated TLS",
                        "description": "TLS 1.0 still negotiated.",
                        "severity": "Medium", "affected_asset": 6,
                        "cve_identifier": "CVE-2023-11111",
                        "cvss_score": 5.3})
    check("admin registers a Medium vulnerability",
          medium.status_code == 201, medium.text)
    medium_id = medium.json()["vulnerability"]["vulnerability_id"]

    high = send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
                json={"title": "SMB signing not enforced",
                      "description": "Relay attacks possible.",
                      "severity": "High", "affected_asset": 2,
                      "cve_identifier": "CVE-2024-21345",
                      "cvss_score": 8.1})
    check("admin registers a High vulnerability", high.status_code == 201,
          high.text)

    check("malformed CVE -> 400",
          send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
               json={"title": "t", "description": "d", "severity": "Low",
                     "affected_asset": 1,
                     "cve_identifier": "CVE-BAD"}).status_code == 400)
    check("CVSS above 10 -> 400",
          send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
               json={"title": "t", "description": "d", "severity": "Low",
                     "affected_asset": 1,
                     "cvss_score": 44}).status_code == 400)
    check("missing affected asset -> 400",
          send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
               json={"title": "t", "description": "d",
                     "severity": "Low"}).status_code == 400)
    check("unknown asset -> 404",
          send("POST", "vulnerabilities", "/vulnerabilities", user_id=1,
               json={"title": "t", "description": "d", "severity": "Low",
                     "affected_asset": 9999}).status_code == 404)
    check("analyst cannot create -> 403",
          send("POST", "vulnerabilities", "/vulnerabilities", user_id=2,
               json={"title": "t", "description": "d", "severity": "Low",
                     "affected_asset": 1}).status_code == 403)
    check("employee has no access -> 403",
          get("vulnerabilities", "/vulnerabilities", user_id=4).status_code
          == 403)

    listing = get("vulnerabilities", "/vulnerabilities", user_id=2).json()
    check("list envelope matches section 5",
          listing.get("status") == "success" and "count" in listing
          and isinstance(listing.get("vulnerabilities"), list))
    check("records carry vulnerability_id, severity_level, status",
          all({"vulnerability_id", "severity_level", "status"} <= set(r)
              for r in listing["vulnerabilities"]))

    updated = send("PUT", "vulnerabilities",
                   "/vulnerabilities/%d" % medium_id, user_id=2,
                   json={"description": "Also on staging.",
                         "cvss_score": 6.5})
    check("analyst updates description and score",
          updated.status_code == 200
          and updated.json()["vulnerability"]["cvss_score"] == 6.5,
          updated.text)
    check("non-numeric CVSS -> 400",
          send("PUT", "vulnerabilities", "/vulnerabilities/%d" % medium_id,
               user_id=2, json={"cvss_score": "nope"}).status_code == 400)
    check("empty update -> 400",
          send("PUT", "vulnerabilities", "/vulnerabilities/%d" % medium_id,
               user_id=2, json={}).status_code == 400)

    check("Open -> Resolved rejected -> 400",
          send("PUT", "vulnerabilities",
               "/vulnerabilities/%d" % critical_id, user_id=2,
               json={"status": "Resolved"}).status_code == 400)
    for expected in ("Under Investigation", "In Progress", "Resolved",
                     "Closed"):
        step = send("PUT", "vulnerabilities",
                    "/vulnerabilities/%d" % critical_id, user_id=2,
                    json={"status": expected})
        check("vulnerability status -> '%s'" % expected,
              step.status_code == 200
              and step.json()["vulnerability"]["status"] == expected,
              step.text)

    for query, expected, label in (
            ("?severity=High", 1, "by severity"),
            ("?status=Open", 2, "by status"),
            ("?cve=2024", 2, "partial CVE"),
            ("?asset_id=2", 2, "by asset"),
            ("?severity=High&status=Open", 1, "two filters"),
            ("?severity=Low", 0, "no matches")):
        response = get("vulnerabilities", "/vulnerabilities/search" + query,
                       user_id=2)
        check("search %s -> %d" % (label, expected),
              response.status_code == 200
              and response.json()["count"] == expected, response.text)

    check("invalid search filter -> 400",
          get("vulnerabilities", "/vulnerabilities/search?severity=Extreme",
              user_id=2).status_code == 400)

    check("analyst cannot delete -> 403",
          send("DELETE", "vulnerabilities",
               "/vulnerabilities/%d" % medium_id, user_id=2).status_code
          == 403)
    check("admin deletes -> 200",
          send("DELETE", "vulnerabilities",
               "/vulnerabilities/%d" % medium_id, user_id=1).status_code
          == 200)
    check("deleted vulnerability is gone -> 404",
          get("vulnerabilities", "/vulnerabilities/%d" % medium_id,
              user_id=1).status_code == 404)


# ---------------------------------------------------------------------------
# Service 8 -- public and internal
# ---------------------------------------------------------------------------

def test_notifications_internal():
    """Exercise the section 7 internal endpoint, including idempotency.

    :return: ``None``
    :rtype: NoneType
    """
    section("Service 8 -- internal delivery endpoint (section 7)")

    target = url("notifications", "/internal/notifications")
    payload = {"user_id": 2, "actor_user_id": 1, "title": "Incident assigned",
               "message": "Incident 1 was assigned to you.",
               "notification_type": "Incident Assignment",
               "severity_level": "High"}

    def post(body, key, service="incidents",
             service_key="test-incidents-key"):
        """Post to the internal endpoint.

        :param body: JSON body.
        :type body: dict
        :param key: Idempotency key.
        :type key: str
        :param service: Service name header.
        :type service: str
        :param service_key: Service key header.
        :type service_key: str
        :return: The response.
        :rtype: requests.Response
        """
        return requests.post(target, json=body, timeout=10, headers={
            "X-Service-Name": service, "X-Service-Key": service_key,
            "Idempotency-Key": key})

    check("no service credentials -> 401",
          requests.post(target, json=payload, timeout=10).status_code == 401)
    check("wrong service key -> 401",
          post(payload, str(uuid.uuid4()),
               service_key="wrong").status_code == 401)
    check("a user JWT is not a service credential -> 401",
          requests.post(target, json=payload, timeout=10,
                        headers={**auth(1),
                                 "Idempotency-Key": str(uuid.uuid4())}
                        ).status_code == 401)
    check("missing Idempotency-Key -> 400",
          requests.post(target, json=payload, timeout=10, headers={
              "X-Service-Name": "incidents",
              "X-Service-Key": "test-incidents-key"}).status_code == 400)
    check("non-UUID Idempotency-Key -> 400",
          post(payload, "not-a-uuid").status_code == 400)

    check("caller may not raise another service's type -> 403",
          post({**payload, "notification_type": "Vulnerability Alert"},
               str(uuid.uuid4())).status_code == 403)
    check("threats may not raise Incident Assignment -> 403",
          post(payload, str(uuid.uuid4()), service="threats",
               service_key="test-threats-key").status_code == 403)

    check("unknown recipient -> 404",
          post({**payload, "user_id": 9999},
               str(uuid.uuid4())).status_code == 404)

    unavailable = post({**payload, "user_id": 7}, str(uuid.uuid4()))
    check("deleted recipient -> 409 RECIPIENT_UNAVAILABLE",
          unavailable.status_code == 409
          and unavailable.json().get("code") == "RECIPIENT_UNAVAILABLE",
          unavailable.text)

    check("empty title -> 400",
          post({**payload, "title": "  "},
               str(uuid.uuid4())).status_code == 400)

    # -- the happy path and idempotency -------------------------------------
    key = str(uuid.uuid4())
    first = post(payload, key)
    check("first delivery -> 201", first.status_code == 201, first.text)
    data = first.json().get("data", {})
    check("response carries event_id and duplicate=false",
          data.get("event_id") == key and data.get("duplicate") is False,
          first.text)
    notification_id = data["notification"]["notification_id"]

    retry = post(payload, key)
    check("identical retry -> 200 duplicate=true",
          retry.status_code == 200
          and retry.json()["data"]["duplicate"] is True, retry.text)
    check("retry returns the same notification",
          retry.json()["data"]["notification"]["notification_id"]
          == notification_id)

    conflict = post({**payload, "title": "Different title"}, key)
    check("changed payload under the same key -> 409 IDEMPOTENCY_CONFLICT",
          conflict.status_code == 409
          and conflict.json().get("code") == "IDEMPOTENCY_CONFLICT",
          conflict.text)

    # Drain first, so the baseline is not polluted by the original
    # creation event still sitting in the outbox.
    flush_outboxes()
    before = len(_STATE.received_logs)
    post(payload, key)
    flush_outboxes()
    check("a retry does not emit a second creation audit event",
          len([e for e in _STATE.received_logs[before:]
               if e["action"] == "notification_created"]) == 0,
          _STATE.received_logs[before:])
    check("exactly one notification_created exists for this delivery",
          len([e for e in _STATE.received_logs
               if e["action"] == "notification_created"
               and str(notification_id) in e["description"]]) == 1,
          [e["description"] for e in _STATE.received_logs
           if e["action"] == "notification_created"])

    # -- receipt outlives the notification ----------------------------------
    send("DELETE", "notifications", "/notifications/%d" % notification_id,
         user_id=1)
    after_delete = post(payload, key)
    check("retry after deletion -> 200 with notification null",
          after_delete.status_code == 200
          and after_delete.json()["data"]["duplicate"] is True
          and after_delete.json()["data"]["notification"] is None,
          after_delete.text)

    _STATE.offline = True
    outage = post({**payload, "user_id": 3}, str(uuid.uuid4()))
    check("Users outage during delivery -> 503", outage.status_code == 503,
          outage.text)
    _STATE.offline = False


def test_notifications_public():
    """Exercise the six public notification endpoints.

    :return: ``None``
    :rtype: NoneType
    """
    section("Service 8 -- public endpoints")

    created = send("POST", "notifications", "/notifications", user_id=1,
                   json={"user_id": 3, "title": "Access review due",
                         "message": "Please review access rights.",
                         "notification_type": "System Notification",
                         "severity": "Low"})
    check("admin creates a notification", created.status_code == 201,
          created.text)
    notification_id = created.json()["notification"]["notification_id"]
    check("new notification starts Unread",
          created.json()["notification"]["status"] == "Unread")

    check("invalid type -> 400",
          send("POST", "notifications", "/notifications", user_id=1,
               json={"user_id": 3, "title": "t", "message": "m",
                     "notification_type": "Carrier Pigeon",
                     "severity": "Low"}).status_code == 400)
    check("unknown recipient -> 404",
          send("POST", "notifications", "/notifications", user_id=1,
               json={"user_id": 9999, "title": "t", "message": "m",
                     "notification_type": "Security Alert",
                     "severity": "Low"}).status_code == 404)
    check("analyst cannot create -> 403",
          send("POST", "notifications", "/notifications", user_id=2,
               json={"user_id": 3, "title": "t", "message": "m",
                     "notification_type": "Security Alert",
                     "severity": "Low"}).status_code == 403)

    check("analyst reads own inbox -> 200",
          get("notifications", "/notifications/user/2", user_id=2
              ).status_code == 200)
    check("analyst cannot read another inbox -> 403",
          get("notifications", "/notifications/user/4", user_id=2
              ).status_code == 403)
    check("auditor may read any inbox -> 200",
          get("notifications", "/notifications/user/2", user_id=5
              ).status_code == 200)
    check("unknown user inbox -> 404",
          get("notifications", "/notifications/user/9999", user_id=1
              ).status_code == 404)
    check("empty inbox -> 200 with count 0",
          get("notifications", "/notifications/user/5",
              user_id=1).json()["count"] == 0)

    marked = send("PUT", "notifications",
                  "/notifications/%d/read" % notification_id, user_id=3)
    check("recipient marks read, read_date set",
          marked.status_code == 200
          and marked.json()["notification"]["status"] == "Read"
          and marked.json()["notification"]["read_date"] is not None,
          marked.text)
    first_date = marked.json()["notification"]["read_date"]
    again = send("PUT", "notifications",
                 "/notifications/%d/read" % notification_id, user_id=3)
    check("second mark keeps the original read_date",
          again.json()["notification"]["read_date"] == first_date)
    check("auditor is read-only -> 403",
          send("PUT", "notifications",
               "/notifications/%d/read" % notification_id,
               user_id=5).status_code == 403)

    check("search by status -> 200",
          get("notifications", "/notifications/search?status=Unread",
              user_id=1).status_code == 200)
    scoped = get("notifications", "/notifications/search?user_id=4",
                 user_id=2).json()
    check("analyst search is scoped to their own inbox",
          scoped["filters_applied"]["user_id"] == 2, scoped)
    check("invalid search filter -> 400",
          get("notifications", "/notifications/search?status=Archived",
              user_id=1).status_code == 400)
    check("employee cannot search -> 403",
          get("notifications", "/notifications/search", user_id=4
              ).status_code == 403)

    check("analyst cannot delete -> 403",
          send("DELETE", "notifications",
               "/notifications/%d" % notification_id, user_id=2
               ).status_code == 403)
    check("admin deletes -> 200",
          send("DELETE", "notifications",
               "/notifications/%d" % notification_id, user_id=1
               ).status_code == 200)


# ---------------------------------------------------------------------------
# Section 6 -- durable audit delivery
# ---------------------------------------------------------------------------

def test_audit_delivery():
    """Check the outbox, the transport action codes and retry behaviour.

    :return: ``None``
    :rtype: NoneType
    """
    section("Section 6 -- durable audit delivery")

    flush_outboxes()
    actions = set(_STATE.actions())

    for expected in ("incident_created", "incident_assigned",
                     "incident_status_updated", "investigation_note_added",
                     "vulnerability_created", "vulnerability_updated",
                     "vulnerability_deleted", "notification_created",
                     "notification_deleted", "unauthorized_access"):
        check("Logs received '%s'" % expected, expected in actions,
              sorted(actions))

    check("every action matches [a-z][a-z0-9_]*",
          all(a.replace("_", "").isalnum() and a.islower()
              for a in actions), sorted(actions))
    check("every severity is one of the four allowed",
          all(e["severity"] in ("Information", "Warning", "Error",
                                "Critical")
              for e in _STATE.received_logs))
    check("related_service always names one of my three",
          all(e["related_service"] in ("incidents", "vulnerabilities",
                                       "notifications")
              for e in _STATE.received_logs))
    check("no event carries a body-level event_id, id or timestamp",
          all("timestamp" not in e or e.get("timestamp") is None
              for e in _STATE.received_logs))

    from outbox import audit_outbox
    check("audit outbox fully drained",
          audit_outbox.pending_count()["pending"] == 0,
          audit_outbox.pending_count())

    # -- outage and recovery -------------------------------------------------
    _STATE.logs_offline = True
    response = send("POST", "incidents", "/incidents", user_id=1, json={
        "title": "Logged during a Logs outage",
        "description": "The business change must still succeed.",
        "category": "Data Leakage", "severity": "Low"})
    check("business change succeeds while Logs is down",
          response.status_code == 201, response.text)

    audit_outbox.deliver_pending()
    pending = audit_outbox.pending_count()
    check("event stays pending during the outage", pending["pending"] >= 1,
          pending)
    check("nothing marked permanently failed",
          pending["permanent_error"] == 0, pending)

    _STATE.logs_offline = False
    with db.transaction() as cur:
        cur.execute("UPDATE karim_audit_outbox SET next_attempt_at = now() "
                    "WHERE delivered_at IS NULL")
    before = len(_STATE.received_logs)
    flush_outboxes()
    check("recovery delivers the queued event exactly once",
          len(_STATE.received_logs) == before + 1,
          "%d -> %d" % (before, len(_STATE.received_logs)))
    check("audit outbox drained after recovery",
          audit_outbox.pending_count()["pending"] == 0)

    delivered_ids = [e["event_id"] for e in _STATE.received_logs]
    check("no event delivered twice under the same UUID",
          len(delivered_ids) == len(set(delivered_ids)))


def test_notification_triggers():
    """Check that both automatic triggers delivered over HTTP.

    :return: ``None``
    :rtype: NoneType
    """
    section("Section 7 -- automatic triggers delivered over HTTP")

    flush_outboxes()

    analyst_inbox = get("notifications", "/notifications/user/2",
                        user_id=1).json()
    check("incident assignment notified the analyst",
          any(n["notification_type"] == "Incident Assignment"
              for n in analyst_inbox["notifications"]), analyst_inbox)

    owner_inbox = get("notifications", "/notifications/user/4",
                      user_id=1).json()
    check("High/Critical vulnerability notified the asset owner",
          any(n["notification_type"] == "Vulnerability Alert"
              for n in owner_inbox["notifications"]), owner_inbox)

    from outbox import notification_outbox
    check("notification outbox drained",
          notification_outbox.pending_count()["pending"] == 0,
          notification_outbox.pending_count())


def test_health():
    """Check the health shape fixed by section 2.

    :return: ``None``
    :rtype: NoneType
    """
    section("Section 2 -- health and readiness")

    for name in _PORTS:
        response = requests.get(url(name, "/health"), timeout=5)
        body = response.json()
        check("%s /health is {'status':'ok','service':'%s'}" % (name, name),
              response.status_code == 200 and body.get("status") == "ok"
              and body.get("service") == name, body)
        check("%s /ready -> 200" % name,
              requests.get(url(name, "/ready"), timeout=5).status_code
              == 200)


# ---------------------------------------------------------------------------

def main():
    """Prepare, run everything, report totals.

    :return: Process exit code.
    :rtype: int
    """
    print("Preparing an isolated schema in the dedicated test database")
    prepare_database()
    print("Starting services and the upstream double")
    start_services()

    test_health()
    test_authentication()
    test_incidents()
    test_vulnerabilities()
    test_notifications_internal()
    test_notifications_public()
    test_notification_triggers()
    test_audit_delivery()

    print("\n" + "=" * 64)
    print("passed: %d    failed: %d"
          % (_RESULTS["passed"], _RESULTS["failed"]))
    print("=" * 64)
    print("\nNOTE: Natalio's and Chris's services were replaced by test")
    print("doubles. This does not demonstrate live team integration.")
    return 1 if _RESULTS["failed"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        for server in _SERVERS:
            server.shutdown()
            server.server_close()
        if _SCHEMA_CREATED:
            from psycopg import sql
            assert _TEST_SCHEMA.startswith("karim_owned_test_") and len(_TEST_SCHEMA) == len("karim_owned_test_") + 32
            with psycopg.connect(_TEST_DB, autocommit=True) as conn:
                conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(_TEST_SCHEMA)))
