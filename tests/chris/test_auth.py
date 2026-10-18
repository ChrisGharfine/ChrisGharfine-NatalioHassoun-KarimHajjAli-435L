import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from services.chris_support.auth import Role


@pytest.mark.parametrize("overrides,remove", [
    ({"exp": 1}, ()), ({"iss": "untrusted"}, ()), ({"aud": "another-platform"}, ()),
    ({"account_status": "inactive"}, ()), ({"account_status": "suspended"}, ()),
    ({"role": "Superuser"}, ()), ({"sub": "0"}, ()), ({"sub": "-1"}, ()),
    ({"sub": "abc"}, ()), ({"sub": "9999999999999999999"}, ()),
    ({"iat": True}, ()), ({}, ("exp",)), ({}, ("role",)),
    ({}, ("account_status",)), ({}, ("iat",)), ({}, ("sub",)),
])
def test_invalid_jwt_is_rejected_and_audited(reports_client, token, audit_sink, overrides, remove):
    def forbidden_upstream(_):
        pytest.fail("Unauthorized calls must not reach source services")
    client, source = reports_client(forbidden_upstream)
    with client, source:
        response = client.get("/reports/summary", headers={
            "Authorization": f"Bearer {token(overrides=overrides, remove=remove)}",
        })
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["status"] == "error"
    assert audit_sink.events[0].action == "authentication.denied"
    assert audit_sink.events[0].user_id is None
    assert audit_sink.commits == 1


@pytest.mark.parametrize("value", [None, "Basic abc", "Bearer invalid.token", "Bearer " + "x" * 8193])
def test_missing_and_malformed_credentials(reports_client, audit_sink, value):
    client, source = reports_client(lambda _: pytest.fail("No upstream call expected"))
    with client, source:
        response = client.get("/reports/assets", headers={} if value is None else {"Authorization": value})
    assert response.status_code == 401
    assert audit_sink.events[0].action == "authentication.denied"


def test_wrong_signing_key_and_algorithm(reports_client, token):
    client, source = reports_client(lambda _: pytest.fail("No upstream call expected"))
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with client, source:
        for encoded in (token(key=wrong_key), token(key="x" * 64, algorithm="HS256")):
            assert client.get("/reports/assets", headers={"Authorization": f"Bearer {encoded}"}).status_code == 401


@pytest.mark.parametrize("role", [Role.ANALYST, Role.EMPLOYEE])
@pytest.mark.parametrize("path", ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"])
def test_reports_denied_to_other_roles(reports_client, auth_headers, audit_sink, role, path):
    client, source = reports_client(lambda _: pytest.fail("Forbidden report must not call upstream"))
    with client, source:
        response = client.get(f"/reports/{path}", headers=auth_headers(role))
    assert response.status_code == 403
    assert audit_sink.events[0].action == "authorization.denied"
    assert audit_sink.events[0].user_id == 1


@pytest.mark.parametrize("role", [Role.ADMIN, Role.AUDITOR])
def test_authorized_reports_forward_verified_token(reports_client, auth_headers, role):
    headers = auth_headers(role)
    paths = []
    def handler(request):
        assert request.headers["authorization"] == headers["Authorization"]
        paths.append(request.url.path)
        return httpx.Response(200, json=[])
    client, source = reports_client(handler)
    with client, source:
        assert client.get("/reports/summary", headers=headers).status_code == 200
    assert paths == ["/users", "/assets", "/incidents", "/threats"]


def test_configuration_rejects_unsafe_keys_and_urls(settings):
    for updates in (
        {"jwt_algorithm": "HS256", "jwt_verification_key": "short"},
        {"jwt_algorithm": "HS256"}, {"users_url": "http://name:password@host"},
        {"database_url": "sqlite://"}, {"users_url": "file:///tmp"},
    ):
        with pytest.raises(ValidationError):
            type(settings).model_validate(settings.model_dump() | updates)
