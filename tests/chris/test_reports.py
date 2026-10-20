import httpx
import pytest

from services.chris_support.errors import ApiError
from services.reports.client import SourceClient


@pytest.fixture
def source_data(threat_body):
    return {
        "/users": {"status": "success", "data": [{"id": 1}, {"id": 2}, {"id": 3}]},
        "/assets": [
            {"id": 1, "asset_type": "server", "criticality": "critical", "status": "active"},
            {"id": 2, "asset_type": "server", "criticality": "low", "status": "inactive"},
        ],
        "/incidents": {"status": "success", "count": 3, "incidents": [
            {"incident_id": 1, "severity": "Critical", "status": "Open"},
            {"incident_id": 2, "severity": "High", "status": "Under Investigation"},
            {"incident_id": 3, "severity": "Low", "status": "Closed"},
        ]},
        "/threats": [
            threat_body | {"id": 1, "date_added": "2026-10-01T10:00:00Z"},
            threat_body | {"id": 2, "severity": "low", "date_added": "2026-10-02T10:00:00Z"},
            threat_body | {"id": 3, "date_added": "2026-10-02T10:00:00Z"},
        ],
        "/vulnerabilities": {"status": "success", "count": 2, "vulnerabilities": [
            {"vulnerability_id": 1, "severity_level": "Critical", "status": "Open"},
            {"vulnerability_id": 2, "severity_level": "High", "status": "In Progress"},
        ]},
        "/logs": {"status": "success", "data": [
            {"id": index, "user_id": 1, "action": action, "timestamp": "2026-10-01T10:00:00Z",
             "severity": "Information", "related_service": "users"}
            for index, action in enumerate([
                "login_success", "login_failed", "login_failed", "user_created",
            ], 1)
        ]},
    }


def test_all_report_statistics(reports_client, source_data, auth_headers):
    client, source = reports_client(lambda req: httpx.Response(200, json=source_data[req.url.path]))
    with client, source:
        headers = auth_headers()
        assert client.get("/reports/summary", headers=headers).json() == {
            "users": 3, "assets": 2, "open_incidents": 1, "critical_threats": 2,
        }
        incidents = client.get("/reports/incidents", headers=headers).json()
        assert incidents["total_incidents"] == 3
        assert incidents["incidents_by_severity"] == {"low": 1, "medium": 0, "high": 1, "critical": 1}
        assert incidents["incidents_by_status"]["open"] == 1
        assets = client.get("/reports/assets", headers=headers).json()
        assert assets["total_assets"] == 2 and assets["critical_assets"] == 1
        assert assets["assets_by_type"]["server"] == 2
        threats = client.get("/reports/threats", headers=headers).json()
        assert threats["total_threats"] == 3 and threats["threats_by_severity"]["critical"] == 2
        assert threats["threats_by_type"]["domain"] == 3
        assert [item["id"] for item in threats["recent_threats"]] == [3, 2, 1]
        vulnerabilities = client.get("/reports/vulnerabilities", headers=headers).json()
        assert vulnerabilities["total_vulnerabilities"] == 2 and vulnerabilities["critical_vulnerabilities"] == 1
        assert vulnerabilities["vulnerabilities_by_status"]["in_progress"] == 1
        activity = client.get("/reports/activity", headers=headers).json()
        assert activity["total_user_activities"] == 4
        assert activity["login_attempts"] == 3 and activity["failed_login_attempts"] == 2
        assert activity["most_performed_actions"][0] == {"action": "login_failed", "count": 2}
        assert [item["id"] for item in activity["recent_activities"]] == [4, 3, 2, 1]


@pytest.mark.parametrize("path,total", [
    ("incidents", "total_incidents"), ("assets", "total_assets"), ("threats", "total_threats"),
    ("vulnerabilities", "total_vulnerabilities"), ("activity", "total_user_activities"),
])
def test_empty_datasets(reports_client, auth_headers, path, total):
    payload = []
    if path in {"incidents", "vulnerabilities"}:
        payload = {"status": "success", "count": 0, path: []}
    elif path == "activity":
        payload = {"status": "success", "data": []}
    client, source = reports_client(lambda _: httpx.Response(200, json=payload))
    with client, source:
        response = client.get(f"/reports/{path}", headers=auth_headers())
    assert response.status_code == 200 and response.json()[total] == 0


@pytest.mark.parametrize("status,expected", [(401, 401), (403, 403), (404, 502), (302, 502), (429, 503), (500, 503), (503, 503)])
def test_upstream_statuses(reports_client, auth_headers, status, expected):
    client, source = reports_client(lambda _: httpx.Response(status, json={"secret": "must not leak"}))
    with client, source:
        response = client.get("/reports/assets", headers=auth_headers())
    assert response.status_code == expected and response.json()["status"] == "error"
    assert "secret" not in response.text


@pytest.mark.parametrize("payload", [
    {"items": [], "next": "/page/2"}, None, [None], [{"id": 1}],
    [{"id": 1, "asset_type": "server", "criticality": "unknown", "status": "active"}],
    [{"id": True, "asset_type": "server", "criticality": "low", "status": "active"}],
    [{"id": 1, "asset_type": "server", "criticality": "low", "status": "active"}] * 2,
])
def test_incomplete_or_invalid_source_data(reports_client, auth_headers, payload):
    client, source = reports_client(lambda _: httpx.Response(200, json=payload))
    with client, source:
        assert client.get("/reports/assets", headers=auth_headers()).status_code == 502


def test_timeout_and_invalid_json(reports_client, auth_headers):
    def timeout(request):
        raise httpx.ReadTimeout("test timeout", request=request)
    for handler, status in (
        (timeout, 503),
        (lambda _: httpx.Response(200, text="not JSON", headers={"content-type": "application/json"}), 502),
        (lambda _: httpx.Response(200, text="[]", headers={"content-type": "text/html"}), 502),
    ):
        client, source = reports_client(handler)
        with client, source:
            assert client.get("/reports/assets", headers=auth_headers()).status_code == status


def test_source_size_and_record_limits(settings):
    for changes in ({"max_upstream_bytes": 1}, {"max_upstream_records": 1}):
        with httpx.Client(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"status": "success", "data": [{"id": 1}, {"id": 2}]}),
        )) as source:
            with pytest.raises(ApiError) as failure:
                SourceClient(settings.model_copy(update=changes), source, "original-user-token").fetch("users")
            assert failure.value.status_code == 502


@pytest.mark.parametrize("timestamp", ["2026-10-01T10:00:00", "invalid", 1])
def test_invalid_or_naive_threat_timestamps(reports_client, auth_headers, threat_body, timestamp):
    client, source = reports_client(lambda _: httpx.Response(200, json=[
        threat_body | {"id": 1, "date_added": timestamp},
    ]))
    with client, source:
        assert client.get("/reports/threats", headers=auth_headers()).status_code == 502


def test_configurable_recent_limit(reports_client, source_data, settings, auth_headers):
    client, source = reports_client(
        lambda req: httpx.Response(200, json=source_data[req.url.path]),
        config=settings.model_copy(update={"recent_limit": 1}),
    )
    with client, source:
        assert len(client.get("/reports/threats", headers=auth_headers()).json()["recent_threats"]) == 1
