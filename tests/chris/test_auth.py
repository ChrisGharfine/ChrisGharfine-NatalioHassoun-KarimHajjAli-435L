import base64
import hashlib
import hmac
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from services.chris_support.app import create_app
from services.chris_support.auth import LEGACY_ROLES, Role
from services.chris_support.database import get_session


@pytest.mark.parametrize("overrides,remove", [
    ({"exp": 1}, ()), ({"iss": "untrusted"}, ()), ({"aud": "another-platform"}, ()),
    ({"aud": ["test-platform"]}, ()), ({"sub": "0"}, ()), ({"sub": "-1"}, ()),
    ({"sub": "abc"}, ()), ({"sub": "2147483648"}, ()), ({"sub": 1}, ()),
    ({"iat": True}, ()), ({"exp": True}, ()), ({"nbf": True}, ()),
    ({"iat": "1"}, ()), ({"nbf": "1"}, ()), ({"type": "refresh"}, ()),
    ({"iat": int(time.time()) + 300}, ()), ({"nbf": int(time.time()) + 300}, ()),
    ({}, ("exp",)), ({}, ("iat",)), ({}, ("sub",)), ({}, ("type",)),
    ({}, ("iss",)), ({}, ("aud",)),
])
def test_invalid_jwt_is_rejected_and_audited(reports_client, token, audit_sink, overrides, remove):
    client, source = reports_client(lambda _: pytest.fail("Invalid tokens must not reach source services"))
    with client, source:
        response = client.get("/reports/assets", headers={
            "Authorization": f"Bearer {token(overrides=overrides, remove=remove)}",
        })
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["status"] == "error"
    assert audit_sink.events[0].action == "unauthorized_access"
    assert audit_sink.events[0].user_id is None
    assert audit_sink.commits == 1


@pytest.mark.parametrize("value", [None, "Basic abc", "Bearer invalid.token", "Bearer " + "x" * 8193])
def test_missing_and_malformed_credentials(reports_client, audit_sink, value):
    client, source = reports_client(lambda _: pytest.fail("No source call expected"))
    with client, source:
        response = client.get("/reports/assets", headers={} if value is None else {"Authorization": value})
    assert response.status_code == 401
    assert audit_sink.events[0].action == "unauthorized_access"


def test_wrong_signing_key_and_algorithm(reports_client, token):
    client, source = reports_client(lambda _: pytest.fail("No source call expected"))
    with client, source:
        for encoded in (token(key="wrong-signing-key-only-for-tests-" * 2), token(algorithm="HS384")):
            assert client.get("/reports/assets", headers={"Authorization": f"Bearer {encoded}"}).status_code == 401


def test_deeply_nested_signed_token_is_rejected(reports_client, settings, audit_sink):
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
    header = encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = encode(b'{"sub":' + b"[" * 1500 + b"1" + b"]" * 1500 + b"}")
    signed = header + b"." + payload
    signature = hmac.new(settings.jwt_verification_key.get_secret_value().encode(), signed, hashlib.sha256).digest()
    encoded = (signed + b"." + encode(signature)).decode()
    client, source = reports_client(lambda _: pytest.fail("Malformed token must not reach a dependency"))
    with client, source:
        assert client.get("/reports/assets", headers={"Authorization": f"Bearer {encoded}"}).status_code == 401
    assert audit_sink.commits == 1


@pytest.mark.parametrize("role", [Role.ANALYST, Role.EMPLOYEE])
@pytest.mark.parametrize("path", ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"])
def test_reports_denied_to_other_roles(reports_client, auth_headers, audit_sink, role, path):
    client, source = reports_client(lambda _: pytest.fail("Forbidden report must not call source"))
    with client, source:
        response = client.get(f"/reports/{path}", headers=auth_headers(role))
    assert response.status_code == 403
    assert audit_sink.events[0].action == "unauthorized_access"
    assert audit_sink.events[0].user_id == (2 if role == Role.ANALYST else 3)


def identity_client(settings, audit_sink, handler):
    source = httpx.Client(transport=httpx.MockTransport(handler))
    app = create_app("reports", settings=settings, http_client=source)
    app.dependency_overrides[get_session] = lambda: audit_sink
    return TestClient(app), source


def identity_payload(**updates):
    return {"status": "success", "data": {
        "id": 1, "role": "security_administrator", "account_status": "active", **updates,
    }}


def test_current_role_is_checked_on_every_request(settings, token, audit_sink):
    calls = []
    role = "security_administrator"
    def handler(request):
        if request.url.path.endswith("/internal/identity/verify"):
            assert request.method == "POST" and request.content == b""
            assert request.headers["x-service-name"] == "reports"
            assert request.headers["x-service-key"] == settings.service_key("reports")
            calls.append(request)
            return httpx.Response(200, json=identity_payload(role=role))
        assert request.url.path == "/assets"
        return httpx.Response(200, json=[])
    client, source = identity_client(settings, audit_sink, handler)
    headers = {"Authorization": f"Bearer {token(remove=('role', 'account_status'))}"}
    with client, source:
        assert client.get("/reports/assets", headers=headers).status_code == 200
        role = "security_analyst"
        assert client.get("/reports/assets", headers=headers).status_code == 403
        role = "auditor"
        assert client.get("/reports/assets", headers=headers).status_code == 200
    assert len(calls) == 3
    assert audit_sink.events[-1].user_id == 1


def test_stale_jwt_role_and_status_are_ignored(settings, token, audit_sink):
    def handler(request):
        if request.url.path.endswith("/internal/identity/verify"):
            return httpx.Response(200, json=identity_payload())
        return httpx.Response(200, json=[])
    client, source = identity_client(settings, audit_sink, handler)
    with client, source:
        response = client.get("/reports/assets", headers={"Authorization": "Bearer " + token(overrides={
            "role": "untrusted legacy role", "account_status": "suspended",
        })})
    assert response.status_code == 200


@pytest.mark.parametrize("status", ["inactive", "suspended"])
def test_current_account_state_rejects_existing_token(settings, token, audit_sink, status):
    client, source = identity_client(settings, audit_sink, lambda _: httpx.Response(
        200, json=identity_payload(account_status=status),
    ))
    with client, source:
        assert client.get("/reports/assets", headers={"Authorization": f"Bearer {token()}"}).status_code == 401
    assert audit_sink.events[-1].action == "unauthorized_access"


@pytest.mark.parametrize("payload", [
    {}, [], {"status": "success", "data": None}, {"status": "error", "data": {}},
    identity_payload(id=2), identity_payload(id=True), identity_payload(id="1"),
    identity_payload(id=2_147_483_648), identity_payload(role="Security Administrator"),
    identity_payload(role=[]), identity_payload(account_status="unknown"),
])
def test_invalid_identity_fails_closed(settings, token, audit_sink, payload):
    client, source = identity_client(settings, audit_sink, lambda _: httpx.Response(200, json=payload))
    with client, source:
        response = client.get("/reports/assets", headers={"Authorization": f"Bearer {token()}"})
    assert response.status_code == 503
    assert audit_sink.commits == 1


@pytest.mark.parametrize("status,expected", [(401, 401), (403, 503), (404, 503), (500, 503), (302, 503)])
def test_identity_refusal_or_unavailability(settings, token, audit_sink, status, expected):
    client, source = identity_client(settings, audit_sink, lambda _: httpx.Response(
        status, headers={"Location": "http://other-host.invalid/"},
    ))
    with client, source:
        assert client.get("/reports/assets", headers={"Authorization": f"Bearer {token()}"}).status_code == expected


def test_identity_transport_timeout_is_sanitized(settings, token, audit_sink):
    def unavailable(request):
        raise httpx.ReadTimeout("do not expose private response material", request=request)
    client, source = identity_client(settings, audit_sink, unavailable)
    with client, source:
        response = client.get("/reports/assets", headers={"Authorization": f"Bearer {token()}"})
    assert response.status_code == 503
    assert "private" not in response.text


def test_missing_service_key_fails_closed(settings, token, audit_sink):
    config = type(settings).model_validate(settings.model_dump() | {"service_tokens": {}})
    client, source = identity_client(config, audit_sink, lambda _: pytest.fail("No key means no HTTP request"))
    with client, source:
        assert client.get("/reports/assets", headers={"Authorization": f"Bearer {token()}"}).status_code == 503


def test_identity_response_size_and_content_type(settings, token, audit_sink):
    for response in (
        httpx.Response(200, content=b"x" * 65_537, headers={"Content-Type": "application/json"}),
        httpx.Response(200, content=b"{}", headers={"Content-Type": "text/html"}),
        httpx.Response(200, content=b"not-json", headers={"Content-Type": "application/json"}),
        httpx.Response(200, content=b"[" * 2000 + b"]" * 2000, headers={"Content-Type": "application/json"}),
    ):
        client, source = identity_client(settings, audit_sink, lambda _, result=response: result)
        with client, source:
            assert client.get("/reports/assets", headers={"Authorization": f"Bearer {token()}"}).status_code == 503


def test_audit_storage_failure_fails_denial_with_503(settings, audit_sink):
    def fail():
        raise SQLAlchemyError("private database detail")
    audit_sink.commit = fail
    audit_sink.rollback = lambda: None
    client, source = identity_client(settings, audit_sink, lambda _: pytest.fail("No HTTP call expected"))
    with client, source:
        response = client.get("/reports/assets")
    assert response.status_code == 503
    assert "private" not in response.text


def test_configuration_rejects_unsafe_keys_and_urls(settings):
    for updates in (
        {"jwt_algorithm": "RS256"}, {"jwt_verification_key": "short"},
        {"users_url": "http://name:password@host"}, {"database_url": "sqlite://"},
        {"users_url": "file:///tmp"}, {"http_timeout_seconds": 6},
        {"users_url": "http://users.invalid:bad-port"}, {"users_url": "http://users.invalid/with space"},
        {"max_upstream_records": 50_001}, {"max_upstream_bytes": 5_000_001},
        {"recent_limit": 11}, {"service_tokens": {"unknown": "x" * 32}},
        {"service_tokens": {"assets": "short"}},
        {"service_tokens": {"assets": "x" * 32 + "\r\n"}},
        {"service_tokens": {"assets": "é" * 32}},
        {"service_tokens": {"assets": "x" * 32, "reports": "x" * 32}},
        {"service_tokens": {"assets": settings.jwt_verification_key.get_secret_value()}},
    ):
        with pytest.raises(ValidationError):
            type(settings).model_validate(settings.model_dump() | updates)


def test_role_display_mapping_is_explicit():
    assert LEGACY_ROLES["Security Administrator"] == Role.ADMIN
    assert LEGACY_ROLES["Security Analyst"] == Role.ANALYST
    assert LEGACY_ROLES["Regular Employee/User"] == Role.EMPLOYEE
    assert LEGACY_ROLES["Auditor"] == Role.AUDITOR
