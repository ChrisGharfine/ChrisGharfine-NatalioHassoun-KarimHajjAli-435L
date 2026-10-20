from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import httpx
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import CheckConstraint, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from tools.chris.http_test_client import TestClient

from services.chris_support.audit import AuditOutbox, enqueue
from services.chris_support.audit_worker import deliver_batch
from services.chris_support.app import create_app
from services.chris_support.database import Base, utcnow


def test_migration_requires_real_users_table(empty_db_engine, monkeypatch):
    monkeypatch.setenv("CHRIS_DATABASE_URL", empty_db_engine.url.render_as_string(hide_password=False))
    config = Config("services/chris_support/alembic.ini")
    with empty_db_engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "chris_0001")
    with pytest.raises(RuntimeError, match="users table"):
        with empty_db_engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
    with empty_db_engine.connect() as connection:
        inspector = inspect(connection)
        assert inspector.has_table("threats") and inspector.has_table("chris_audit_outbox")
        assert not inspector.has_table("users") and not inspector.has_table("assets")


@pytest.mark.parametrize("service", ["assets", "threats", "reports"])
def test_readiness_requires_v1_delivery_migration(empty_db_engine, settings, service, monkeypatch):
    monkeypatch.setenv("CHRIS_DATABASE_URL", empty_db_engine.url.render_as_string(hide_password=False))
    config = Config("services/chris_support/alembic.ini")
    with empty_db_engine.begin() as connection:
        # External Users fixture, confined to this test's random schema.
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
        config.attributes["connection"] = connection
        command.upgrade(config, "chris_0002")
    app = create_app(service, settings=settings, engine=empty_db_engine)
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 503
        with empty_db_engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        assert client.get("/ready").status_code == 200


def test_schema_foreign_key_and_unique_constraint(db_engine, monkeypatch):
    inspector = inspect(db_engine)
    assert inspector.get_foreign_keys("assets")[0]["referred_table"] == "users"
    assert inspector.get_foreign_keys("assets")[0]["options"]["ondelete"] == "RESTRICT"
    assert any(c["column_names"] == ["threat_type", "threat_value"] for c in inspector.get_unique_constraints("threats"))
    monkeypatch.setenv("CHRIS_DATABASE_URL", db_engine.url.render_as_string(hide_password=False))
    with db_engine.begin() as connection:
        config = Config("services/chris_support/alembic.ini")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")  # Repeated upgrade is a no-op.
        assert connection.scalar(text("SELECT count(*) FROM users")) == 4


def test_migrated_schema_matches_orm_metadata(db_engine):
    owned = {"assets", "threats", "chris_audit_outbox"}
    inspector = inspect(db_engine)
    for name in owned:
        expected = {constraint.name for constraint in Base.metadata.tables[name].constraints
                    if isinstance(constraint, CheckConstraint)}
        actual = {constraint["name"] for constraint in inspector.get_check_constraints(name)}
        assert actual == expected
    with db_engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={
            "version_table": "chris_alembic_version",
            "include_object": lambda obj, name, type_, reflected, compare_to: type_ != "table" or name in owned,
        })
        assert compare_metadata(context, Base.metadata) == []


@pytest.mark.parametrize("column,value", [("severity", "urgent"), ("threat_type", "invalid"), ("source", " ")])
def test_postgres_rejects_invalid_values_outside_api(db_engine, column, value):
    assert column in {"severity", "threat_type", "source"}
    row = {"threat_type": "other", "threat_value": "test", "description": "Test", "severity": "low", "source": "Test"}
    row[column] = value
    with pytest.raises(IntegrityError):
        with db_engine.begin() as connection:
            connection.execute(text("INSERT INTO threats (threat_type, threat_value, description, severity, source, date_added) VALUES (:threat_type,:threat_value,:description,:severity,:source,now())"), row)


def test_outbox_delivery_retry_and_idempotency(db_engine, settings):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        enqueue(session, user_id=1, action="assets.created", service="assets", description="Test event")
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(503, json={}) if len(requests) == 1 else httpx.Response(201, json={
            "status": "success", "data": {"event_id": request.headers["idempotency-key"], "duplicate": False, "log": {"id": 5}},
        })
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert deliver_batch(factory, client, settings) == 0
        with factory.begin() as session:
            record = session.scalar(select(AuditOutbox))
            assert record.attempts == 1 and record.delivered_at is None
            assert "503" in record.last_error and "credential" not in record.last_error
            record.next_attempt_at = utcnow() - timedelta(seconds=1)
        assert deliver_batch(factory, client, settings) == 1
        assert deliver_batch(factory, client, settings) == 0
    assert requests[0].headers["idempotency-key"] == requests[1].headers["idempotency-key"]
    assert "authorization" not in requests[0].headers
    assert requests[0].headers["x-service-name"] == "assets"
    assert requests[0].headers["x-service-key"] == settings.service_key("assets")
    with factory() as session:
        record = session.scalar(select(AuditOutbox))
        assert record.attempts == 2 and record.delivered_at is not None and record.last_error is None


@pytest.mark.parametrize("response", [
    httpx.Response(200, json=[]), httpx.Response(201, json={"id": True}),
    httpx.Response(202, json={"id": 1}), httpx.Response(201, text="invalid"),
    httpx.Response(403, json={}),
])
def test_invalid_audit_acknowledgments_remain_pending(db_engine, settings, response):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        enqueue(session, user_id=1, action="test", service="assets", description="Test")
    with httpx.Client(transport=httpx.MockTransport(lambda _: response)) as client:
        assert deliver_batch(factory, client, settings) == 0
    with factory() as session:
        assert session.scalar(select(AuditOutbox)).delivered_at is None


def test_concurrent_audit_workers_skip_locked_rows(db_engine, settings):
    factory = sessionmaker(bind=db_engine)
    with factory.begin() as session:
        for _ in range(2):
            enqueue(session, user_id=1, action="test", service="assets", description="Test")
    barrier = Barrier(2)
    ids = []
    def handler(request):
        ids.append(request.headers["idempotency-key"])
        barrier.wait(timeout=10)
        return httpx.Response(201, json={"status": "success", "data": {
            "event_id": request.headers["idempotency-key"], "duplicate": False, "log": {"id": 1},
        }})
    def deliver():
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return deliver_batch(factory, client, settings, batch_size=1)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: deliver(), range(2)))
    assert results == [1, 1] and len(set(ids)) == 2
