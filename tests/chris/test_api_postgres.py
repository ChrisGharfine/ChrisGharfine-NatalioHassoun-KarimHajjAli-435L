from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from services.assets.models import Asset
from services.chris_support.audit import AuditOutbox
from services.chris_support.auth import Role
from services.threats.models import Threat


CASES = [
    ("assets", "POST", "/assets", "asset", {Role.ADMIN}, 201),
    ("assets", "PUT", "/assets/{id}", "asset_update", {Role.ADMIN}, 200),
    ("assets", "DELETE", "/assets/{id}", None, {Role.ADMIN}, 204),
    ("assets", "GET", "/assets", None, {Role.ADMIN, Role.AUDITOR}, 200),
    ("assets", "GET", "/assets/{id}", None, {Role.ADMIN, Role.ANALYST, Role.AUDITOR}, 200),
    ("assets", "GET", "/assets/search?criticality=high", None, {Role.ADMIN, Role.ANALYST, Role.AUDITOR}, 200),
    ("threats", "POST", "/threats", "threat", {Role.ADMIN}, 201),
    ("threats", "PUT", "/threats/{id}", "threat_update", {Role.ADMIN}, 200),
    ("threats", "DELETE", "/threats/{id}", None, {Role.ADMIN}, 204),
    ("threats", "GET", "/threats", None, {Role.ADMIN, Role.ANALYST, Role.AUDITOR}, 200),
    ("threats", "GET", "/threats/{id}", None, {Role.ADMIN, Role.ANALYST, Role.AUDITOR}, 200),
    ("threats", "GET", "/threats/search?severity=critical", None, {Role.ADMIN, Role.ANALYST}, 200),
] + [
    ("reports", "GET", f"/reports/{name}", None, {Role.ADMIN, Role.AUDITOR}, 200)
    for name in ("summary", "incidents", "assets", "threats", "vulnerabilities", "activity")
]


def counts(engine):
    with Session(engine) as session:
        return tuple(session.scalar(select(func.count()).select_from(model))
                     for model in (Asset, Threat, AuditOutbox))


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("service,method,path,body_key,allowed,success", CASES)
def test_all_18_endpoints_role_matrix(
    api_clients, db_engine, auth_headers, asset_body, threat_body,
    role, service, method, path, body_key, allowed, success,
):
    admin = auth_headers()
    asset = api_clients["assets"].post("/assets", json=asset_body, headers=admin)
    threat = api_clients["threats"].post("/threats", json=threat_body, headers=admin)
    assert asset.status_code == threat.status_code == 201
    identifier = asset.json()["id"] if service == "assets" else threat.json()["id"]
    bodies = {
        "asset": asset_body | {"name": "Second asset"}, "asset_update": {"status": "under_maintenance"},
        "threat": threat_body | {"threat_value": "second.example"}, "threat_update": {"severity": "low"},
        None: None,
    }
    before = counts(db_engine)
    client = api_clients[service]
    response = client.request(method, path.format(id=identifier), json=bodies[body_key], headers=auth_headers(role))
    assert response.status_code == (success if role in allowed else 403), response.text
    after = counts(db_engine)
    if role not in allowed:
        assert before[:2] == after[:2]
        assert after[2] == before[2] + 1
        with Session(db_engine) as session:
            assert session.scalar(select(AuditOutbox).order_by(AuditOutbox.created_at.desc())).action == "unauthorized_access"


def test_assets_persistence_update_search_and_errors(api_clients, db_engine, auth_headers, asset_body):
    client = api_clients["assets"]
    headers = auth_headers()
    first = client.post("/assets", json=asset_body, headers=headers).json()
    client.post("/assets", json=asset_body | {"name": "Payroll", "criticality": "critical", "ip_address": "2001:db8::1"}, headers=headers)
    response = client.put(f'/assets/{first["id"]}', json={"owner_id": 2, "location": None, "status": "under_maintenance"}, headers=headers)
    assert response.status_code == 200 and response.json()["owner_id"] == 2
    with Session(db_engine) as session:
        assert session.get(Asset, first["id"]).owner_id == 2
    for filters in (
        {"name": "lab"}, {"asset_type": "server", "department": "security"},
        {"ip_address": "192.0.2.10"}, {"criticality": "high"}, {"status": "under_maintenance"},
    ):
        data = client.get("/assets/search", params=filters, headers=headers).json()
        assert any(item["id"] == first["id"] for item in data)
    for query in ("%", "' OR 1=1 --", "no such asset"):
        assert client.get("/assets/search", params={"name": query}, headers=headers).json() == []
    for path in ("/assets/0", "/assets/-1", "/assets/abc", "/assets/999999999999999999999", "/assets/search", "/assets/search?unknown=yes"):
        assert client.get(path, headers=headers).status_code == 422
    assert client.get("/assets/999999", headers=headers).status_code == 404
    before = counts(db_engine)
    assert client.post("/assets", json=asset_body | {"owner_id": 999999}, headers=headers).status_code == 404
    assert client.put(f'/assets/{first["id"]}', json={"owner_id": 999999}, headers=headers).status_code == 404
    assert counts(db_engine) == before
    assert client.get(f'/assets/{first["id"]}', headers=headers).json()["owner_id"] == 2


@pytest.mark.parametrize("reference_table", ["test_incident_refs", "test_vulnerability_refs"])
def test_asset_deletion_preserves_external_references(api_clients, db_engine, auth_headers, asset_body, reference_table):
    client = api_clients["assets"]
    headers = auth_headers()
    identifier = client.post("/assets", json=asset_body, headers=headers).json()["id"]
    assert reference_table in {"test_incident_refs", "test_vulnerability_refs"}
    with db_engine.begin() as connection:
        connection.execute(text(f'CREATE TABLE {reference_table} (id BIGINT PRIMARY KEY, asset_id BIGINT REFERENCES assets(id) ON DELETE RESTRICT)'))
        connection.execute(text(f'INSERT INTO {reference_table} VALUES (1, :asset_id)'), {"asset_id": identifier})
    before = counts(db_engine)
    assert client.delete(f"/assets/{identifier}", headers=headers).status_code == 409
    assert counts(db_engine) == before
    assert client.get(f"/assets/{identifier}", headers=headers).status_code == 200


def test_threats_duplicate_normalization_search_update_and_delete(api_clients, db_engine, auth_headers, threat_body):
    client = api_clients["threats"]
    headers = auth_headers()
    created = client.post("/threats", json=threat_body | {"threat_value": "SUSPICIOUS.EXAMPLE."}, headers=headers)
    assert created.status_code == 201
    identifier = created.json()["id"]
    assert created.json()["threat_value"] == "suspicious.example"
    assert created.json()["date_added"].endswith(("Z", "+00:00"))
    before = counts(db_engine)
    assert client.post("/threats", json=threat_body, headers=headers).status_code == 409
    assert counts(db_engine) == before
    for filters in (
        {"threat_type": "domain"}, {"threat_value": "suspicious"}, {"severity": "critical"},
        {"source": "feed"}, {"threat_type": "domain", "threat_value": "SUSPICIOUS.EXAMPLE."},
    ):
        response = client.get("/threats/search", params=filters, headers=headers)
        assert response.status_code == 200 and len(response.json()) == 1
    assert client.get("/threats/search?source=%25", headers=headers).json() == []
    assert client.get("/threats/search", headers=headers).status_code == 422
    assert client.put(f"/threats/{identifier}", json={"description": "Updated analysis", "severity": "medium", "source": "Analyst"}, headers=headers).status_code == 200
    with Session(db_engine) as session:
        assert session.get(Threat, identifier).severity == "medium"
    assert client.delete(f"/threats/{identifier}", headers=headers).status_code == 204
    assert client.get(f"/threats/{identifier}", headers=headers).status_code == 404
    assert client.delete(f"/threats/{identifier}", headers=headers).status_code == 404


def test_concurrent_duplicate_threats(api_clients, db_engine, auth_headers, threat_body):
    app = api_clients["threats"].app
    barrier = Barrier(2)
    def insert():
        with TestClient(app) as client:
            barrier.wait(timeout=10)
            return client.post("/threats", json=threat_body, headers=auth_headers()).status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _: insert(), range(2)))
    assert sorted(statuses) == [201, 409]
    assert counts(db_engine)[1:] == (1, 1)


def test_business_write_rolls_back_if_audit_cannot_be_persisted(api_clients, db_engine, auth_headers, asset_body):
    with db_engine.begin() as connection:
        connection.execute(text("""
            CREATE FUNCTION test_block_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'isolated test audit failure'; END; $$
        """))
        connection.execute(text("CREATE TRIGGER block_audit BEFORE INSERT ON chris_audit_outbox FOR EACH ROW EXECUTE FUNCTION test_block_audit()"))
    response = api_clients["assets"].post("/assets", json=asset_body, headers=auth_headers())
    assert response.status_code == 503
    assert counts(db_engine) == (0, 0, 0)
    assert "test_block" not in response.text


def test_missing_auth_is_durably_audited_and_readiness(api_clients, db_engine):
    assert api_clients["assets"].get("/assets").status_code == 401
    with Session(db_engine) as session:
        entry = session.scalar(select(AuditOutbox))
        assert entry.action == "unauthorized_access" and entry.user_id is None
    for client in api_clients.values():
        assert client.get("/ready").status_code == 200
        assert client.get("/health").status_code == 200
