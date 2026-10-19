"""V1 security tests: live three-service PostgreSQL checks and labeled fault doubles.

Mocked outbound HTTP tests verify rejection of malformed dependencies; they are
unit/fault-injection checks, not evidence that teammates' services are running.
"""

import uuid
from datetime import timedelta
from unittest.mock import Mock, patch

import jwt
import pytest
from sqlalchemy import select, text

from security_backend.__main__ import migrate
from security_backend.models import UsersOutbox
from security_backend.shared.audit import drain_outbox
from security_backend.shared.clients import call_users, log_event
from security_backend.shared.errors import APIError
from security_backend.shared.tokens import verify_access_request
from security_backend.shared.validation import utcnow
from security_backend.app import create_app
from scripts.export_openapi import build
from .conftest import PREFIX


def wire_claims(api):
    return jwt.decode(api.admin_token, options={"verify_signature": False})


def test_live_issued_token_contract_and_unchanged_public_shapes(api):
    claims = wire_claims(api)
    assert claims["iss"] == "security-sprint1-users"
    assert claims["aud"] == "security-sprint1-services"
    assert claims["type"] == "access" and claims["sub"] == str(api.admin_id)
    assert claims["exp"] - claims["iat"] == 1800
    assert "role" not in claims and "account_status" not in claims
    for service, path in (("users", "/users"), ("logs", "/logs"), ("playbooks", "/playbooks")):
        result = api.request(service, "GET", path, api.admin_token)
        assert result.status_code == 200
        assert result.json()["status"] == "success" and isinstance(result.json()["data"], list)


BAD_CLAIMS = [("missing_" + field, field, None) for field in ("sub", "iat", "exp", "iss", "aud", "type")]
BAD_CLAIMS += [("wrong_issuer", "iss", "another-project"), ("wrong_audience", "aud", "another-service"),
               ("refresh", "type", "refresh"), ("numeric_subject", "sub", 1),
               ("zero_subject", "sub", "0"), ("large_subject", "sub", "2147483648"),
               ("string_iat", "iat", "1"), ("bool_iat", "iat", True),
               ("string_exp", "exp", "9999999999"), ("bool_exp", "exp", True),
               ("future_iat", "iat", 9999999999), ("future_nbf", "nbf", 9999999999)]


@pytest.mark.parametrize("label,field,value", BAD_CLAIMS, ids=[row[0] for row in BAD_CLAIMS])
def test_live_invalid_wire_claims_rejected_by_all_owned_services(api, label, field, value):
    claims = wire_claims(api)
    if label.startswith("missing_"):
        claims.pop(field)
    else:
        claims[field] = value
    token = jwt.encode(claims, api.apps["users"].config["JWT_SECRET_KEY"], algorithm="HS256")
    for service, path in (("users", "/users"), ("logs", "/logs"), ("playbooks", "/playbooks")):
        assert api.request(service, "GET", path, token).status_code == 401


@pytest.mark.parametrize("algorithm", ["HS384", "none"])
def test_live_algorithm_allowlist(api, algorithm):
    key = "" if algorithm == "none" else api.apps["users"].config["JWT_SECRET_KEY"]
    token = jwt.encode(wire_claims(api), key, algorithm=algorithm)
    assert api.request("users", "GET", "/users", token).status_code == 401


@pytest.mark.parametrize("name", ["assets", "threats", "reports", "incidents", "vulnerabilities", "notifications"])
def test_live_teammate_service_identity_and_receipts(api, name):
    headers = {"X-Service-Name": name, "X-Service-Key": api.apps["users"].config["SERVICE_TOKENS"][name]}
    verified = api.request("users", "POST", "/internal/identity/verify", api.admin_token, headers=headers)
    assert verified.status_code == 200 and verified.json()["data"]["id"] == api.admin_id
    event_id = str(uuid.uuid4())
    payload = {"user_id": None, "action": "unauthorized_access", "description": "Unknown actor rejected.",
               "severity": "Warning", "related_service": name}
    headers["Idempotency-Key"] = event_id
    for expected, duplicate in ((201, False), (200, True)):
        result = api.request("logs", "POST", "/internal/logs", json=payload, headers=headers)
        assert result.status_code == expected
        assert result.json()["data"]["event_id"] == event_id
        assert result.json()["data"]["duplicate"] is duplicate


def dependency_response(status, body):
    response = Mock(status_code=status)
    response.json.return_value = body
    return response


@pytest.mark.parametrize("change", [{"id": 9999999}, {"id": True}, {"role": "Security Analyst"},
                                    {"account_status": "suspended"}, {"id": "1"}])
def test_unit_malformed_identity_fails_closed(api, change):
    app = api.apps["playbooks"]
    identity = {"id": api.admin_id, "role": "security_administrator", "account_status": "active", **change}
    with app.test_request_context(PREFIX + "/playbooks", headers={"Authorization": "Bearer " + api.admin_token}):
        verify_access_request()
        with patch("security_backend.shared.clients.requests.Session") as factory:
            client = factory.return_value.__enter__.return_value
            client.request.return_value = dependency_response(200, {"status": "success", "data": identity})
            with pytest.raises(APIError) as error:
                call_users("/internal/identity/verify", "POST", api.admin_token)
            assert error.value.status == 503 and error.value.code == "IDENTITY_UNAVAILABLE"
            assert client.trust_env is False and client.request.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("status,body", [(200, []), (200, {"status": "error", "data": {}}),
                                       (302, {}), (503, {}), (401, {"code": "INVALID_SERVICE"})])
def test_unit_identity_envelope_or_service_failure(api, status, body):
    app = api.apps["playbooks"]
    with app.test_request_context(headers={"Authorization": "Bearer " + api.admin_token}):
        verify_access_request()
        with patch("security_backend.shared.clients.requests.Session") as factory:
            factory.return_value.__enter__.return_value.request.return_value = dependency_response(status, body)
            with pytest.raises(APIError) as error:
                call_users("/internal/identity/verify", "POST", api.admin_token)
            assert error.value.status == 503


@pytest.mark.parametrize("variant", ["wrong_uuid", "missing_log", "bad_id", "bad_duplicate", "new_null", "accepted_202", "redirect"])
def test_unit_invalid_receipt_never_delivers_outbox(api, variant):
    app = api.apps["users"]
    event_id = str(uuid.uuid4())
    payload = {"user_id": None, "action": "receipt_check", "description": "Receipt validation.",
               "severity": "Information", "related_service": "users"}
    receipt = {"event_id": event_id, "log": {"id": 1}, "duplicate": False}
    status = 201
    if variant == "wrong_uuid": receipt["event_id"] = str(uuid.uuid4())
    if variant == "missing_log": receipt.pop("log")
    if variant == "bad_id": receipt["log"]["id"] = True
    if variant == "bad_duplicate": receipt["duplicate"] = "false"
    if variant == "new_null": receipt["log"] = None
    if variant == "accepted_202": status = 202
    if variant == "redirect": status = 302
    with app.extensions["session_factory"]() as session:
        session.add(UsersOutbox(id=event_id, payload=payload))
        session.commit()
    try:
        with app.app_context(), patch("security_backend.shared.clients.requests.Session") as factory:
            factory.return_value.__enter__.return_value.post.return_value = dependency_response(status, {"status": "success", "data": receipt})
            drain_outbox()
        with app.extensions["session_factory"]() as session:
            row = session.get(UsersOutbox, event_id)
            assert row.delivered_at is None and row.last_error == "AUDIT_UNAVAILABLE"
            assert row.next_attempt_at > utcnow() and row.attempts == 1
    finally:
        with app.extensions["session_factory"]() as session:
            session.delete(session.get(UsersOutbox, event_id))
            session.commit()


def test_live_receipt_after_deletion_and_permanent_failure_recovery(api):
    app = api.apps["users"]
    event_id = str(uuid.uuid4())
    payload = {"user_id": None, "action": "recover_once", "description": "Recover exactly once.",
               "severity": "Information", "related_service": "users"}
    with app.app_context():
        first = log_event(payload, event_id)
    log_id = first["data"]["log"]["id"]
    assert api.request("logs", "DELETE", f"/logs/{log_id}", api.admin_token).status_code == 200
    with app.app_context():
        result = log_event(payload, event_id)
        assert result["data"]["duplicate"] and result["data"]["log"] is None
        with pytest.raises(APIError) as error:
            log_event({**payload, "description": "Changed"}, event_id)
        assert error.value.code == "AUDIT_IDEMPOTENCY_CONFLICT"
    blocked_id = str(uuid.uuid4())
    with app.extensions["session_factory"]() as session:
        session.add(UsersOutbox(id=blocked_id, payload=payload))
        session.commit()
    tokens = app.config["SERVICE_TOKENS"]
    try:
        app.config["SERVICE_TOKENS"] = {**tokens, "users": "incorrect-key-for-delivery-only"}
        with app.app_context():
            drain_outbox()
            drain_outbox()
        with app.extensions["session_factory"]() as session:
            row = session.get(UsersOutbox, blocked_id)
            assert row.delivery_blocked and row.delivered_at is None and row.attempts == 1
    finally:
        app.config["SERVICE_TOKENS"] = tokens
    with app.app_context():
        drain_outbox(retry_blocked=True)
    with app.extensions["session_factory"]() as session:
        row = session.get(UsersOutbox, blocked_id)
        assert row.delivered_at is not None and row.attempts == 2


def test_live_additive_migration_keeps_pending_work(api):
    app = api.apps["users"]
    event_id = str(uuid.uuid4())
    with app.extensions["session_factory"]() as session:
        session.add(UsersOutbox(id=event_id, payload={"retained": True}, delivery_blocked=True))
        session.commit()
    with app.app_context():
        migrate(app)
        migrate(app)
    with app.extensions["session_factory"]() as session:
        assert session.get(UsersOutbox, event_id).payload == {"retained": True}
        assert session.execute(text("SELECT version FROM student1_schema_versions ORDER BY version")).scalars().all() == [1, 2]
        session.delete(session.get(UsersOutbox, event_id))
        session.commit()


def test_live_upgrade_from_original_schema_preserves_existing_events(api):
    from pathlib import Path
    app = api.apps["users"]
    schema = "upgrade_test_" + uuid.uuid4().hex
    directory = Path(__file__).resolve().parents[1] / "database"
    with app.extensions["engine"].connect() as connection:
        transaction = connection.begin()
        try:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'SET LOCAL search_path TO "{schema}"')
            connection.exec_driver_sql((directory / "001_student1.sql").read_text(encoding="utf-8"))
            connection.execute(text("INSERT INTO users_audit_outbox (id,payload,created_at,attempts) "
                                    "VALUES (:id,CAST(:payload AS JSON),CURRENT_TIMESTAMP,3)"),
                               {"id": "retained-original-event", "payload": '{"retained":true}'})
            for _ in range(2):
                connection.exec_driver_sql((directory / "002_team_v1.sql").read_text(encoding="utf-8"))
            row = connection.execute(text("SELECT payload,attempts,delivery_blocked,next_attempt_at FROM users_audit_outbox")).one()
            assert row.payload == {"retained": True} and row.attempts == 3
            assert row.delivery_blocked is False and row.next_attempt_at is None
        finally:
            transaction.rollback()  # Only this test's uncommitted schema/DDL is removed.


def test_live_retry_backoff_cap_and_worker_restart(api):
    app = api.apps["users"]
    event_id = str(uuid.uuid4())
    payload = {"user_id": None, "action": "retry_persistence", "description": "Retry scheduling persists.",
               "severity": "Information", "related_service": "users"}
    with app.extensions["session_factory"]() as session:
        session.add(UsersOutbox(id=event_id, payload=payload, attempts=8))
        session.commit()
    original = app.config["LOGS_URL"]
    try:
        app.config["LOGS_URL"] = "http://127.0.0.1:1"
        with app.app_context():
            drain_outbox()
            drain_outbox()  # Scheduled future event must not be attempted again.
        with app.extensions["session_factory"]() as session:
            row = session.get(UsersOutbox, event_id)
            assert row.delivered_at is None and row.attempts == 9
            assert 295 <= (row.next_attempt_at - utcnow()).total_seconds() <= 300
            assert row.payload == payload
            row.next_attempt_at = utcnow() - timedelta(seconds=1)
            session.commit()
    finally:
        app.config["LOGS_URL"] = original
    restarted = create_app("users", dict(app.config))
    try:
        with restarted.app_context():
            drain_outbox()
        with restarted.extensions["session_factory"]() as session:
            row = session.get(UsersOutbox, event_id)
            assert row.delivered_at is not None and row.attempts == 10 and row.payload == payload
    finally:
        restarted.extensions["engine"].dispose()


def test_contract_exports_cover_all_registered_operations(api):
    for service, port in (("users", 8001), ("logs", 8005), ("playbooks", 8009)):
        document = build(service, port)
        operations = {(path, method.upper()) for path, methods in document["paths"].items() for method in methods}
        import re
        actual = {(re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", rule.rule.removeprefix(PREFIX)), method)
                  for rule in api.apps[service].url_map.iter_rules() if rule.endpoint != "static"
                  for method in rule.methods - {"HEAD", "OPTIONS"}}
        # Flask calls internal references user_id; OpenAPI uses the same path position as id.
        actual = {(path.replace("/internal/users/{user_id}", "/internal/users/{id}")
                   .replace("/users/{user_id}", "/users/{id}")
                   .replace("{playbook_id}", "{id}").replace("{action_id}", "{id}")
                   .replace("{log_id}", "{id}"), method) for path, method in actual}
        assert actual == operations
