"""Stand-in Users, Assets and Logs services for testing my three.

.. warning::

   **These are test doubles, not the real services.** Section 8 of
   team-integration-v1.0.0 is explicit: "fixture responses are never real
   execution evidence." Passing the suite that uses this file proves my
   services behave correctly *against the documented contracts*. It proves
   nothing about whether Natalio's and Chris's actual implementations
   match those contracts. That can only be established by running against
   their real services.

What is implemented here is only what my services call:

* ``POST /internal/identity/verify`` -- section 4.2
* ``GET  /internal/users/{id}``      -- section 4.3
* ``GET  /internal/assets/{id}``     -- section 4.3
* ``POST /internal/logs``            -- section 6, including idempotency

The Logs double keeps every event it receives so the tests can assert on
the audit trail, and it can be told to fail or go offline so the outbox
retry behaviour can be exercised.

:author: Karim Hajj Ali
"""

import threading
import uuid
from wsgiref.simple_server import WSGIRequestHandler, make_server

import jwt
from flask import Flask, jsonify, request

#: Users the double knows about, keyed by id.
USERS = {
    1: {"id": 1, "role": "security_administrator",
        "account_status": "active", "deleted": False},
    2: {"id": 2, "role": "security_analyst",
        "account_status": "active", "deleted": False},
    3: {"id": 3, "role": "security_analyst",
        "account_status": "active", "deleted": False},
    4: {"id": 4, "role": "regular_employee",
        "account_status": "active", "deleted": False},
    5: {"id": 5, "role": "auditor",
        "account_status": "active", "deleted": False},
    6: {"id": 6, "role": "security_analyst",
        "account_status": "suspended", "deleted": False},
    7: {"id": 7, "role": "regular_employee",
        "account_status": "inactive", "deleted": True},
}

#: Assets the double knows about, keyed by id.
ASSETS = {
    1: {"id": 1, "name": "Primary Domain Controller",
        "criticality": "critical", "owner_id": 1},
    2: {"id": 2, "name": "Finance File Server",
        "criticality": "high", "owner_id": 4},
    3: {"id": 3, "name": "HR Workstation 14",
        "criticality": "medium", "owner_id": 4},
    4: {"id": 4, "name": "Customer Records Database",
        "criticality": "critical", "owner_id": 1},
    5: {"id": 5, "name": "Branch Office Router",
        "criticality": "high", "owner_id": 2},
    6: {"id": 6, "name": "Payroll Web Application",
        "criticality": "high", "owner_id": 4},
    9: {"id": 9, "name": "Orphan Asset", "criticality": "low",
        "owner_id": None},
}

#: Service keys the double accepts, matching the test configuration.
SERVICE_KEYS = {
    "incidents": "test-incidents-key",
    "vulnerabilities": "test-vulnerabilities-key",
    "notifications": "test-notifications-key",
}


class UpstreamState:
    """Mutable state the tests manipulate to simulate real conditions.

    :param jwt_secret: Secret the identity endpoint verifies tokens with.
    :type jwt_secret: str
    """

    def __init__(self, jwt_secret):
        self.jwt_secret = jwt_secret
        #: Every accepted audit event, newest last.
        self.received_logs = []
        #: Idempotency key -> stored log id, so retries can be detected.
        self.log_receipts = {}
        #: Idempotency key -> payload digest, to detect conflicts.
        self.log_payloads = {}
        #: When True, every endpoint returns 503.
        self.offline = False
        #: When True, /internal/logs returns 503 only.
        self.logs_offline = False
        #: Log ids that were "deleted" after ingestion.
        self.deleted_log_ids = set()
        self._next_log_id = 1

    def reset(self):
        """Clear everything the tests may have changed.

        :return: ``None``
        :rtype: NoneType
        """
        self.received_logs.clear()
        self.log_receipts.clear()
        self.log_payloads.clear()
        self.deleted_log_ids.clear()
        self.offline = False
        self.logs_offline = False
        self._next_log_id = 1

    def next_log_id(self):
        """Return the next log id and advance the counter.

        :return: A fresh log id.
        :rtype: int
        """
        value = self._next_log_id
        self._next_log_id += 1
        return value

    def actions(self):
        """Return the action code of every accepted event, in order.

        :return: Action codes.
        :rtype: list
        """
        return [event["action"] for event in self.received_logs]


def build_app(state):
    """Build the Flask app implementing the three upstream services.

    :param state: Shared mutable state the tests inspect.
    :type state: UpstreamState
    :return: The configured application.
    :rtype: flask.Flask
    """
    app = Flask("upstream_double")

    def _service_ok():
        """Validate the caller's service credentials.

        :return: ``(True, None)`` or ``(False, response tuple)``.
        :rtype: tuple
        """
        name = request.headers.get("X-Service-Name")
        key = request.headers.get("X-Service-Key")
        if not name or not key or SERVICE_KEYS.get(name) != key:
            return False, (jsonify({"status": "error",
                                    "message": "bad service key"}), 401)
        return True, None

    @app.before_request
    def _maybe_offline():
        """Simulate a total outage when the tests ask for one.

        :return: A ``503`` response, or ``None`` to continue.
        :rtype: flask.Response or NoneType
        """
        if state.offline:
            return jsonify({"status": "error",
                            "message": "simulated outage"}), 503
        return None

    # -- Users -------------------------------------------------------------

    @app.route("/api/natalio-hassoun/internal/identity/verify",
               methods=["POST"])
    def identity_verify():
        """Return the caller's current identity, section 4.2.

        :return: ``200`` with the identity, ``401`` when it cannot
            authenticate, ``403`` on bad service credentials.
        :rtype: flask.Response
        """
        ok, failure = _service_ok()
        if not ok:
            return failure

        header = request.headers.get("Authorization", "")
        token = header[len("Bearer "):] if header.startswith("Bearer ") else ""
        try:
            claims = jwt.decode(
                token, state.jwt_secret, algorithms=["HS256"],
                issuer="security-sprint1-users",
                audience="security-sprint1-services")
        except jwt.InvalidTokenError:
            return jsonify({"status": "error",
                            "message": "invalid token"}), 401

        user = USERS.get(int(claims["sub"]))
        if user is None or user["deleted"] or \
                user["account_status"] != "active":
            return jsonify({"status": "error",
                            "message": "not permitted"}), 401

        return jsonify({"status": "success", "data": {
            "id": user["id"], "role": user["role"],
            "account_status": user["account_status"]}}), 200

    @app.route("/api/natalio-hassoun/internal/users/<int:user_id>",
               methods=["GET"])
    def internal_user(user_id):
        """Return any user by id, section 4.3.

        :param user_id: The user to return.
        :type user_id: int
        :return: ``200`` with the user, ``404`` if unknown.
        :rtype: flask.Response
        """
        ok, failure = _service_ok()
        if not ok:
            return failure

        user = USERS.get(user_id)
        if user is None:
            return jsonify({"status": "error",
                            "message": "no such user"}), 404
        return jsonify({"status": "success", "data": dict(user)}), 200

    # -- Assets ------------------------------------------------------------

    @app.route("/internal/assets/<int:asset_id>", methods=["GET"])
    def internal_asset(asset_id):
        """Return any asset by id, section 4.3.

        :param asset_id: The asset to return.
        :type asset_id: int
        :return: ``200`` with the asset, ``404`` if unknown.
        :rtype: flask.Response
        """
        ok, failure = _service_ok()
        if not ok:
            return failure

        asset = ASSETS.get(asset_id)
        if asset is None:
            return jsonify({"status": "error",
                            "message": "no such asset"}), 404
        return jsonify({"status": "success", "data": dict(asset)}), 200

    # -- Logs --------------------------------------------------------------

    @app.route("/api/natalio-hassoun/internal/logs", methods=["POST"])
    def internal_logs():
        """Ingest one audit event idempotently, section 6.

        :return: ``201`` first time, ``200`` on an identical retry, ``409``
            on a conflicting reuse of the key, ``503`` when simulated down.
        :rtype: flask.Response
        """
        if state.logs_offline:
            return jsonify({"status": "error",
                            "message": "logs are down"}), 503

        ok, failure = _service_ok()
        if not ok:
            return failure

        key = request.headers.get("Idempotency-Key", "")
        try:
            uuid.UUID(key)
        except ValueError:
            return jsonify({"status": "error",
                            "message": "bad idempotency key"}), 400

        body = request.get_json(silent=True) or {}
        digest = repr(sorted(body.items()))

        if key in state.log_receipts:
            if state.log_payloads.get(key) != digest:
                return jsonify({"status": "error",
                                "code": "IDEMPOTENCY_CONFLICT",
                                "message": "payload changed"}), 409
            log_id = state.log_receipts[key]
            log = None if log_id in state.deleted_log_ids else {"id": log_id}
            return jsonify({"status": "success", "data": {
                "event_id": key, "log": log, "duplicate": True}}), 200

        log_id = state.next_log_id()
        state.log_receipts[key] = log_id
        state.log_payloads[key] = digest
        stored = dict(body)
        stored["id"] = log_id
        stored["event_id"] = key
        state.received_logs.append(stored)

        return jsonify({"status": "success", "data": {
            "event_id": key, "log": {"id": log_id},
            "duplicate": False}}), 201

    return app


class _QuietHandler(WSGIRequestHandler):
    """Request handler that does not print a line per request."""

    def log_message(self, fmt, *args):
        """Swallow the access log.

        :param fmt: Format string.
        :type fmt: str
        :return: ``None``
        :rtype: NoneType
        """
        return


def start(state, port):
    """Start the double on a background thread.

    :param state: Shared mutable state.
    :type state: UpstreamState
    :param port: Port to listen on.
    :type port: int
    :return: The running server, so the caller can shut it down.
    :rtype: wsgiref.simple_server.WSGIServer
    """
    server = make_server("127.0.0.1", port, build_app(state),
                         handler_class=_QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
