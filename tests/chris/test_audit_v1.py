"""Audit contract fixtures and disposable-PostgreSQL delivery tests, not team evidence."""

import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from services.chris_support.audit import AuditOutbox, enqueue, validate_payload, wire_payload
from services.chris_support.audit_worker import deliver_batch, queue_counts, requeue_failed, valid_receipt
from services.chris_support.database import utcnow


def receipt(event_id, *, duplicate=False, log_id=1):
    return {"status": "success", "data": {
        "event_id": event_id, "duplicate": duplicate,
        "log": None if log_id is None else {"id": log_id},
    }}


@pytest.fixture
def delivery_settings():
    keys = {name: name + "-local-fixture-key" for name in ("assets", "threats", "reports")}
    def service_key(service):
        if service not in keys:
            raise ValueError("Missing service key")
        return keys[service]
    return SimpleNamespace(
        audit_url="http://logs.test/api/natalio-hassoun", http_timeout_seconds=5,
        service_key=service_key, keys=keys,
    )


@pytest.mark.parametrize("status,duplicate,log_id,expected", [
    (201, False, 1, True), (200, True, 1, True), (200, True, None, True),
    (201, True, 1, False), (200, False, 1, False), (201, False, None, False),
    (202, False, 1, False), (200, True, True, False), (201, False, 0, False),
    (200, True, -1, False),
])
def test_receipt_requires_status_duplicate_and_log_consistency(status, duplicate, log_id, expected):
    identifier = str(uuid4())
    assert valid_receipt(receipt(identifier, duplicate=duplicate, log_id=log_id), status, identifier) is expected


@pytest.mark.parametrize("body", [None, [], {"id": 1}, {"status": "error", "data": {}},
    {"status": "success", "data": []}, {"status": "success", "data": {"event_id": "invalid"}}])
def test_receipt_rejects_malformed_or_legacy_shapes(body):
    assert not valid_receipt(body, 201, str(uuid4()))


def test_receipt_requires_matching_uuid_and_boolean_duplicate():
    identifier = str(uuid4())
    assert not valid_receipt(receipt(str(uuid4())), 201, identifier)
    body = receipt(identifier)
    body["data"]["duplicate"] = 0
    assert not valid_receipt(body, 201, identifier)
    body["data"]["duplicate"] = False
    del body["data"]["log"]
    assert not valid_receipt(body, 201, identifier)


def test_additive_migration_preserves_pending_and_delivered_originals(empty_db_engine, monkeypatch):
    monkeypatch.setenv("CHRIS_DATABASE_URL", empty_db_engine.url.render_as_string(hide_password=False))
    identifiers = [str(uuid4()), str(uuid4())]
    config = Config("services/chris_support/alembic.ini")
    with empty_db_engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
        config.attributes["connection"] = connection
        command.upgrade(config, "chris_0002")
        for index, identifier in enumerate(identifiers):
            connection.execute(text("""
                INSERT INTO chris_audit_outbox
                    (id,user_id,action,description,severity,related_service,created_at,
                     attempts,next_attempt_at,delivered_at,last_error)
                VALUES (:id,1,'assets.created','Original event','information','assets',now(),
                        3,now(),CASE WHEN :delivered THEN now() ELSE NULL END,:error)
            """), {"id": identifier, "delivered": bool(index), "error": None if index else "HTTP 503"})
        command.upgrade(config, "head")
    with sessionmaker(bind=empty_db_engine)() as session:
        records = [session.get(AuditOutbox, identifier) for identifier in identifiers]
        assert [record.id for record in records] == identifiers
        assert all(record.action == "assets.created" and record.severity == "information" for record in records)
        assert all(record.description == "Original event" and record.attempts == 3 for record in records)
        assert all(record.transport_payload is None and record.failed_at is None for record in records)
        assert records[0].delivered_at is None and records[0].last_error == "HTTP 503"
        assert records[1].delivered_at is not None and records[1].last_error is None


@pytest.mark.parametrize("old,new", [
    ("assets.created", "asset_created"), ("assets.updated", "asset_updated"),
    ("assets.deleted", "asset_deleted"), ("threats.created", "threat_created"),
    ("threats.updated", "threat_updated"), ("threats.deleted", "threat_deleted"),
    ("authentication.denied", "unauthorized_access"), ("authorization.denied", "unauthorized_access"),
])
def test_only_explicit_legacy_actions_are_normalized(old, new):
    payload = wire_payload(user_id=1, action=old, service="assets", description="Fixture", severity="warning")
    assert payload["action"] == new and payload["severity"] == "Warning"
    assert set(payload) == {"user_id", "action", "description", "severity", "related_service"}


@pytest.mark.parametrize("field,value", [
    ("user_id", True), ("user_id", 0), ("user_id", 2_147_483_648),
    ("action", "unknown.dotted"), ("action", "Human action"), ("action", "a" * 101),
    ("description", " "), ("description", "a" * 2001), ("severity", "information"),
    ("related_service", "logs"),
])
def test_invalid_frozen_payload_is_rejected(field, value):
    payload = wire_payload(user_id=1, action="asset_created", service="assets", description="Fixture", severity="information")
    payload[field] = value
    with pytest.raises(ValueError):
        validate_payload(payload)


def test_dispatches_each_event_with_its_own_identity(db_engine, delivery_settings):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        for service in ("assets", "threats", "reports"):
            enqueue(session, user_id=1, service=service, action="unauthorized_access", description="Fixture")
    captured = []
    def handler(request):
        captured.append(request)
        return httpx.Response(201, json=receipt(request.headers["Idempotency-Key"]))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_batch(factory, client, delivery_settings) == 3
    assert len(captured) == 3
    for request in captured:
        body = json.loads(request.content)
        service = body["related_service"]
        assert request.headers["X-Service-Name"] == service
        assert request.headers["X-Service-Key"] == delivery_settings.keys[service]
        assert "Authorization" not in request.headers
        assert request.url.path == "/api/natalio-hassoun/internal/logs"
        assert set(body) == {"user_id", "action", "description", "severity", "related_service"}
        assert body["severity"] == "Information"
    assert queue_counts(factory) == (0, 0)


def test_legacy_payload_is_frozen_before_remote_acceptance_and_reused(db_engine, delivery_settings):
    factory = sessionmaker(bind=db_engine)
    identifier = str(uuid4())
    with factory.begin() as session:
        session.add(AuditOutbox(id=identifier, user_id=1, action="assets.created", description="Original text",
                                severity="information", related_service="assets"))
    payloads = []
    def handler(request):
        body = json.loads(request.content)
        payloads.append(body)
        with factory() as independent_session:
            stored = independent_session.get(AuditOutbox, identifier)
            assert stored.transport_payload == body
            assert stored.action == "assets.created" and stored.severity == "information"
        if len(payloads) == 1:
            return httpx.Response(503, json={"status": "error"})
        return httpx.Response(200, json=receipt(identifier, duplicate=True, log_id=None))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_batch(factory, client, delivery_settings) == 0
        with factory.begin() as session:
            record = session.get(AuditOutbox, identifier)
            assert record.attempts == 1 and record.failed_at is None
            record.next_attempt_at = utcnow() - timedelta(seconds=1)
        assert deliver_batch(factory, client, delivery_settings) == 1
    assert payloads == [payloads[0], payloads[0]]
    assert payloads[0]["action"] == "asset_created"
    with factory() as session:
        record = session.get(AuditOutbox, identifier)
        assert record.id == identifier and record.delivered_at is not None


@pytest.mark.parametrize("code,permanent", [("CONFLICT", False), ("IDEMPOTENCY_CONFLICT", True)])
def test_conflict_classification_and_no_automatic_permanent_retry(db_engine, delivery_settings, code, permanent):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        enqueue(session, user_id=1, action="asset_created", service="assets", description="Fixture")
    calls = []
    def handler(request):
        calls.append(request.headers["Idempotency-Key"])
        return httpx.Response(409, json={"status": "error", "error": {"code": code}})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_batch(factory, client, delivery_settings) == 0
        with factory.begin() as session:
            row = session.scalar(select(AuditOutbox))
            assert (row.failed_at is not None) is permanent
            assert row.delivered_at is None
            row.next_attempt_at = utcnow() - timedelta(seconds=1)
        assert deliver_batch(factory, client, delivery_settings) == 0
    assert len(calls) == (1 if permanent else 2)
    assert len(set(calls)) == 1
    if permanent:
        assert requeue_failed(factory, "assets") == 0
        assert queue_counts(factory) == (0, 1)


def test_rejected_credentials_require_explicit_scoped_retry(db_engine, delivery_settings):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        for service in ("assets", "threats"):
            enqueue(session, user_id=1, action="unauthorized_access", service=service, description="Fixture")
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(401, json={"message": "SECRET"}))) as client:
        assert deliver_batch(factory, client, delivery_settings) == 0
        assert deliver_batch(factory, client, delivery_settings) == 0
    assert queue_counts(factory) == (0, 2)
    assert requeue_failed(factory, "assets") == 1
    assert queue_counts(factory) == (1, 1)
    with factory() as session:
        rows = session.scalars(select(AuditOutbox)).all()
        frozen = {row.id: row.transport_payload for row in rows}
        assert all("SECRET" not in row.last_error for row in rows if row.last_error)
    def accept(request):
        assert json.loads(request.content) == frozen[request.headers["Idempotency-Key"]]
        return httpx.Response(201, json=receipt(request.headers["Idempotency-Key"]))
    with httpx.Client(transport=httpx.MockTransport(accept)) as client:
        assert deliver_batch(factory, client, delivery_settings) == 1
    assert queue_counts(factory) == (0, 1)


def test_missing_service_key_is_visible_without_making_request(db_engine, delivery_settings):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        enqueue(session, user_id=1, action="asset_created", service="assets", description="Fixture")
    delivery_settings.keys.pop("assets")
    def unreachable(_):
        pytest.fail("Must not send without a service key")
    with httpx.Client(transport=httpx.MockTransport(unreachable)) as client:
        assert deliver_batch(factory, client, delivery_settings) == 0
    with factory() as session:
        row = session.scalar(select(AuditOutbox))
        assert row.failed_at is not None and row.last_error.startswith("SERVICE_CREDENTIAL_MISSING")


@pytest.mark.parametrize("kind", ["wrong_uuid", "oversize", "redirect", "timeout", "deep_json", "wrong_media"])
def test_bad_receipts_and_transient_transport_failures_never_mark_delivered(db_engine, delivery_settings, kind):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        enqueue(session, user_id=1, action="asset_created", service="assets", description="Fixture")
    requests = []
    def handler(request):
        requests.append(request)
        if kind == "timeout":
            raise httpx.ReadTimeout("SECRET", request=request)
        if kind == "redirect":
            return httpx.Response(307, headers={"Location": "http://elsewhere.test"})
        if kind == "oversize":
            return httpx.Response(201, content=b" " * 65_537, headers={"Content-Type": "application/json"})
        if kind == "deep_json":
            return httpx.Response(201, content=b"[" * 2000 + b"]" * 2000,
                                  headers={"Content-Type": "application/json"})
        if kind == "wrong_media":
            return httpx.Response(201, text=json.dumps(receipt(request.headers["Idempotency-Key"])))
        return httpx.Response(201, json=receipt(str(uuid4())))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_batch(factory, client, delivery_settings) == 0
    assert len(requests) == 1
    with factory() as session:
        row = session.scalar(select(AuditOutbox))
        assert row.delivered_at is None and row.failed_at is None and row.attempts == 1
        assert "SECRET" not in row.last_error
        assert 0 < (row.next_attempt_at - utcnow()).total_seconds() <= 2
