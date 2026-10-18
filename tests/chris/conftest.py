import os
import re
import time
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from services.chris_support.app import create_app
from services.chris_support.auth import Role
from services.chris_support.config import Settings
from services.chris_support.database import get_session

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def signing_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, public


@pytest.fixture
def settings(signing_keys):
    return Settings(
        database_url="postgresql+psycopg://localhost/chris_test_unconfigured",
        jwt_verification_key=signing_keys[1], jwt_issuer="test-identity", jwt_audience="test-platform",
        users_url="http://users.test", assets_url="http://assets.test", incidents_url="http://incidents.test",
        threats_url="http://threats.test", audit_url="http://audit.test",
        vulnerabilities_url="http://vulnerabilities.test",
    )


@pytest.fixture
def token(signing_keys):
    def make(role=Role.ADMIN, *, overrides=None, remove=(), key=None, algorithm="RS256"):
        now = int(time.time())
        claims = {
            "sub": "1", "role": role.value if isinstance(role, Role) else role,
            "account_status": "active", "iss": "test-identity", "aud": "test-platform",
            "iat": now - 1, "exp": now + 300,
        }
        claims.update(overrides or {})
        for name in remove:
            claims.pop(name, None)
        return jwt.encode(claims, key if key is not None else signing_keys[0], algorithm=algorithm)
    return make


@pytest.fixture
def auth_headers(token):
    return lambda role=Role.ADMIN: {"Authorization": f"Bearer {token(role)}"}


class AuditSessionDouble:
    """Unit-test audit sink only; not used to test persistence or constraints."""
    def __init__(self):
        self.events = []
        self.commits = 0

    def add(self, record):
        self.events.append(record)

    def commit(self):
        self.commits += 1


@pytest.fixture
def audit_sink():
    return AuditSessionDouble()


@pytest.fixture
def reports_client(settings, audit_sink):
    def make(handler, *, config=None):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        app = create_app("reports", settings=config or settings, http_client=client)
        app.dependency_overrides[get_session] = lambda: audit_sink
        return TestClient(app), client
    return make


@pytest.fixture(scope="session")
def postgres_root():
    url = os.environ.get("CHRIS_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set CHRIS_TEST_DATABASE_URL to a dedicated chris_test* PostgreSQL database")
    parsed = make_url(url)
    if not (parsed.database or "").startswith("chris_test"):
        pytest.fail("Refusing schema creation outside a dedicated chris_test* database")
    engine = create_engine(url, hide_parameters=True)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT 1")) == 1
    yield engine
    engine.dispose()


@pytest.fixture
def empty_db_engine(postgres_root):
    schema = "chris_test_" + uuid4().hex
    assert re.fullmatch(r"chris_test_[0-9a-f]{32}", schema)
    with postgres_root.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = create_engine(
        postgres_root.url, connect_args={"options": f"-csearch_path={schema}"}, hide_parameters=True,
    )
    try:
        yield scoped
    finally:
        scoped.dispose()
        # Only the randomly generated schema created by this fixture is removed.
        assert re.fullmatch(r"chris_test_[0-9a-f]{32}", schema)
        with postgres_root.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


@pytest.fixture
def db_engine(empty_db_engine, monkeypatch):
    scoped = empty_db_engine
    # Explicit external-service test double, isolated in this test's schema.
    # Production migrations never create a Users table.
    with scoped.begin() as connection:
        connection.execute(text("CREATE TABLE users (id BIGINT PRIMARY KEY)"))
        connection.execute(text("INSERT INTO users (id) VALUES (1), (2), (3), (4)"))
        config = Config(str(ROOT / "services/chris_support/alembic.ini"))
        config.attributes["connection"] = connection
        monkeypatch.setenv("CHRIS_DATABASE_URL", scoped.url.render_as_string(hide_password=False))
        command.upgrade(config, "head")
    yield scoped


@pytest.fixture
def api_clients(db_engine, settings):
    clients = {}
    try:
        for service in ("assets", "threats", "reports"):
            app = create_app(service, settings=settings, engine=db_engine)
            clients[service] = TestClient(app)
        yield clients
    finally:
        for client in clients.values():
            client.app.state.http_client.close()
            client.close()


@pytest.fixture
def asset_body():
    return {
        "name": "Lab Server", "asset_type": "server", "ip_address": "192.0.2.10",
        "department": "Security", "owner_id": 1, "criticality": "high",
        "operating_system": "Linux", "location": "Lab 1", "status": "active",
    }


@pytest.fixture
def threat_body():
    return {
        "threat_type": "domain", "threat_value": "suspicious.example",
        "description": "Indicator used in isolated tests", "severity": "critical", "source": "Lab feed",
    }
