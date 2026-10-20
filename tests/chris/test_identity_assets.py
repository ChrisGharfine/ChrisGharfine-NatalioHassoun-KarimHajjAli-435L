"""Owned identity/reference contract checks; HTTP fixtures are not live evidence."""

import httpx
import pytest
from tools.chris.http_test_client import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from services.assets.models import Asset
from services.assets.schemas import AssetCreate
from services.chris_support.app import create_app
from services.chris_support.audit import AuditOutbox
from services.chris_support.database import get_session
from services.chris_support.errors import ApiError
from services.chris_support.identity import validate_asset_owner


def reference_headers(settings, service):
    return {"X-Service-Name": service, "X-Service-Key": settings.service_key(service)}


@pytest.fixture
def internal_asset_client(settings, audit_sink):
    record = Asset(id=7, name="Reference asset", owner_id=1, criticality="high")
    audit_sink.get = lambda model, identifier: record if model is Asset and identifier == 7 else None
    source = httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("Internal Assets must not call Users")))
    app = create_app("assets", settings=settings, http_client=source)
    app.dependency_overrides[get_session] = lambda: audit_sink
    with TestClient(app) as client, source:
        yield client


@pytest.mark.parametrize("service", ["incidents", "vulnerabilities"])
def test_internal_asset_reference_is_scoped_and_minimal(internal_asset_client, settings, audit_sink, service):
    response = internal_asset_client.get("/internal/assets/7", headers=reference_headers(settings, service))
    assert response.status_code == 200
    assert response.json() == {"status": "success", "data": {
        "id": 7, "name": "Reference asset", "criticality": "high", "owner_id": 1,
    }}
    assert audit_sink.events == []


@pytest.mark.parametrize("service", ["users", "assets", "threats", "logs", "reports", "notifications", "playbooks"])
def test_other_valid_service_cannot_read_assets(internal_asset_client, settings, audit_sink, service):
    response = internal_asset_client.get("/internal/assets/7", headers=reference_headers(settings, service))
    assert response.status_code == 403
    assert audit_sink.events[0].action == "unauthorized_access"
    assert audit_sink.events[0].related_service == "assets"
    assert audit_sink.events[0].user_id is None
    assert audit_sink.commits == 1


def test_internal_reference_requires_service_credentials(internal_asset_client, settings, audit_sink, token):
    for headers in (
        {}, {"Authorization": f"Bearer {token()}"},
        {"X-Service-Name": "incidents", "X-Service-Key": "wrong"},
        {"X-Service-Name": "incidents", "X-Service-Key": settings.service_key("vulnerabilities")},
        {"X-Service-Name": "unknown", "X-Service-Key": settings.service_key("incidents")},
    ):
        assert internal_asset_client.get("/internal/assets/7", headers=headers).status_code == 401
    assert audit_sink.commits == 5


def test_non_ascii_internal_key_is_rejected(internal_asset_client):
    response = internal_asset_client.get("/internal/assets/7", headers=[
        (b"x-service-name", b"incidents"), (b"x-service-key", b"\xff"),
    ])
    assert response.status_code == 401


def test_denial_uses_bounded_route_template(internal_asset_client, audit_sink):
    response = internal_asset_client.get("/internal/assets/" + "9" * 3000)
    assert response.status_code == 401
    assert audit_sink.events[0].description == "Denied GET /internal/assets/{id}"


def test_unknown_internal_asset(internal_asset_client, settings):
    response = internal_asset_client.get("/internal/assets/999", headers=reference_headers(settings, "incidents"))
    assert response.status_code == 404


def test_service_key_is_not_a_public_assets_permission(internal_asset_client, settings):
    response = internal_asset_client.get("/assets/7", headers=reference_headers(settings, "incidents"))
    assert response.status_code == 401


@pytest.mark.parametrize("updates,status", [
    ({"deleted": True}, 400), ({"account_status": "inactive"}, 400),
    ({"account_status": "suspended"}, 400), ({"id": 2}, 503),
    ({"id": True}, 503), ({"deleted": "false"}, 503),
    ({"role": "unexpected"}, 503),
])
def test_asset_owner_reference_is_current_and_strict(settings, updates, status):
    def handler(request):
        assert request.method == "GET"
        assert request.url.path.endswith("/internal/users/1")
        assert request.headers["x-service-name"] == "assets"
        assert request.headers["x-service-key"] == settings.service_key("assets")
        assert "Authorization" not in request.headers
        return httpx.Response(200, json={"status": "success", "data": {
            "id": 1, "role": "regular_employee", "account_status": "active", "deleted": False,
            **updates,
        }})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ApiError) as failure:
            validate_asset_owner(client, settings, 1)
    assert failure.value.status_code == status


def test_asset_owner_unknown_and_unavailable_are_distinct(settings):
    for status, expected in ((404, 404), (401, 503), (403, 503), (500, 503), (302, 503)):
        with httpx.Client(transport=httpx.MockTransport(lambda _, code=status: httpx.Response(code))) as client:
            with pytest.raises(ApiError) as failure:
                validate_asset_owner(client, settings, 1)
        assert failure.value.status_code == expected


def test_owner_identifier_matches_users_limit(asset_body):
    with pytest.raises(ValueError):
        AssetCreate.model_validate(asset_body | {"owner_id": 2_147_483_648})


def test_unavailable_new_owner_prevents_mutation(api_clients, auth_headers, identity_state, asset_body, db_engine):
    identity_state[2]["account_status"] = "inactive"
    response = api_clients["assets"].post("/assets", headers=auth_headers(), json=asset_body | {"owner_id": 2})
    assert response.status_code == 400
    with Session(db_engine) as session:
        assert session.scalar(select(func.count()).select_from(Asset)) == 0
        assert session.scalar(select(func.count()).select_from(AuditOutbox)) == 0


def test_owner_reassignment_uses_current_reference_only_when_changed(
    api_clients, auth_headers, identity_state, asset_body, db_engine,
):
    client = api_clients["assets"]
    created = client.post("/assets", headers=auth_headers(), json=asset_body)
    assert created.status_code == 201
    identifier = created.json()["id"]
    identity_state[2]["deleted"] = True
    assert client.put(f"/assets/{identifier}", headers=auth_headers(), json={"owner_id": 2}).status_code == 400
    with Session(db_engine) as session:
        assert session.get(Asset, identifier).owner_id == 1
    identity_state[2]["deleted"] = False
    assert client.put(f"/assets/{identifier}", headers=auth_headers(), json={"owner_id": 2}).status_code == 200
    identity_state[2]["account_status"] = "inactive"
    # Unrelated edits preserve historical ownership; only new/changed references
    # must be available. The administrator actor remains current and active.
    assert client.put(f"/assets/{identifier}", headers=auth_headers(), json={"location": "Lab 2"}).status_code == 200
    assert client.put(f"/assets/{identifier}", headers=auth_headers(), json={"owner_id": 2}).status_code == 200
