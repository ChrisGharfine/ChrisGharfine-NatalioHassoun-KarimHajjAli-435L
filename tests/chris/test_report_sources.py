"""Reports validates provider wire contracts; these are explicit HTTP doubles."""

import httpx
import pytest

from services.chris_support.errors import ApiError
from services.reports.client import SourceClient
from services.reports.contracts import (
    INCIDENT_STATES, KARIM_SEVERITIES, LOG_SEVERITIES, PAGINATION_FIELDS,
    VULNERABILITY_STATES,
)


def fetch(settings, source, payload):
    with httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=payload),
    )) as client:
        return SourceClient(settings, client, "original-user-token").fetch(source)


def test_json_media_type_is_case_insensitive(settings):
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(
        200, headers={"Content-Type": "Application/JSON; charset=utf-8"},
        json={"status": "success", "data": [{"id": 1}]},
    ))) as client:
        assert SourceClient(settings, client, "isolated-test-token").fetch("users")[0].id == 1


@pytest.mark.parametrize("field", ["action", "related_service"])
def test_activity_rejects_blank_consumed_text(settings, field):
    row = {"id": 1, "user_id": None, "action": "login_failed", "related_service": "users",
           "timestamp": "2026-10-19T00:00:00Z", "severity": "Warning"}
    with pytest.raises(ApiError) as failure:
        fetch(settings, "audit", {"status": "success", "data": [row | {field: "   "}]})
    assert failure.value.status_code == 502


@pytest.mark.parametrize("source,array_key", [
    ("users", "data"), ("audit", "data"),
    ("incidents", "incidents"), ("vulnerabilities", "vulnerabilities"),
])
@pytest.mark.parametrize("invalid_envelope", [
    [], None, {"status": "error", "data": []}, {"data": []},
])
def test_source_requires_its_exact_success_envelope(settings, source, array_key, invalid_envelope):
    with pytest.raises(ApiError) as failure:
        fetch(settings, source, invalid_envelope)
    assert failure.value.status_code == 502


@pytest.mark.parametrize("field", sorted(PAGINATION_FIELDS))
def test_source_rejects_pagination_even_with_empty_array(settings, field):
    with pytest.raises(ApiError) as failure:
        fetch(settings, "users", {"status": "success", "data": [], field: None})
    assert failure.value.status_code == 502


@pytest.mark.parametrize("source", ["incidents", "vulnerabilities"])
@pytest.mark.parametrize("count", [None, True, False, "0", 0.0, -1, 1])
def test_karim_complete_count_is_required_strict_integer(settings, source, count):
    with pytest.raises(ApiError) as failure:
        fetch(settings, source, {"status": "success", "count": count, source: []})
    assert failure.value.status_code == 502


@pytest.mark.parametrize("wire_severity,normalized", list(KARIM_SEVERITIES.items()))
def test_incident_severity_normalization(settings, wire_severity, normalized):
    records = fetch(settings, "incidents", {
        "status": "success", "count": 1, "incidents": [
            {"incident_id": 7, "severity": wire_severity, "status": "Open", "extra": "ignored"},
        ],
    })
    assert records[0].id == 7 and records[0].severity == normalized


@pytest.mark.parametrize("wire_status,normalized", list(INCIDENT_STATES.items()))
def test_incident_status_normalization(settings, wire_status, normalized):
    records = fetch(settings, "incidents", {
        "status": "success", "count": 1, "incidents": [
            {"incident_id": 7, "severity": "High", "status": wire_status},
        ],
    })
    assert records[0].status == normalized


@pytest.mark.parametrize("wire_status,normalized", list(VULNERABILITY_STATES.items()))
def test_vulnerability_field_and_status_normalization(settings, wire_status, normalized):
    records = fetch(settings, "vulnerabilities", {
        "status": "success", "count": 1, "vulnerabilities": [
            {"vulnerability_id": 8, "severity_level": "Critical", "status": wire_status},
        ],
    })
    assert records[0].id == 8 and records[0].severity == "critical"
    assert records[0].status == normalized


@pytest.mark.parametrize("source,row", [
    ("incidents", {"id": 1, "severity": "Critical", "status": "Open"}),
    ("incidents", {"incident_id": 1, "severity": "critical", "status": "Open"}),
    ("incidents", {"incident_id": 1, "severity": "Critical", "status": "open"}),
    ("incidents", {"incident_id": 1, "severity": "Critical", "status": "In Progress"}),
    ("vulnerabilities", {"id": 1, "severity_level": "High", "status": "Open"}),
    ("vulnerabilities", {"vulnerability_id": 1, "severity": "High", "status": "Open"}),
    ("vulnerabilities", {"vulnerability_id": 1, "severity_level": "High", "status": "Mitigated"}),
])
def test_provider_internal_aliases_are_not_alternate_wire_inputs(settings, source, row):
    with pytest.raises(ApiError) as failure:
        fetch(settings, source, {"status": "success", "count": 1, source: [row]})
    assert failure.value.status_code == 502


@pytest.mark.parametrize("identifier", [True, False, "1", 0, -1, 1.0, None])
def test_source_identifiers_must_be_positive_integers(settings, identifier):
    with pytest.raises(ApiError) as failure:
        fetch(settings, "incidents", {
            "status": "success", "count": 1, "incidents": [
                {"incident_id": identifier, "severity": "High", "status": "Open"},
            ],
        })
    assert failure.value.status_code == 502


def test_duplicate_karim_identifiers_are_rejected(settings):
    row = {"vulnerability_id": 9, "severity_level": "High", "status": "Open"}
    with pytest.raises(ApiError) as failure:
        fetch(settings, "vulnerabilities", {
            "status": "success", "count": 2, "vulnerabilities": [row, row],
        })
    assert failure.value.status_code == 502


@pytest.mark.parametrize("severity,normalized", list(LOG_SEVERITIES.items()))
def test_log_normalization_preserves_consumed_fields_and_normalizes_utc(settings, severity, normalized):
    records = fetch(settings, "audit", {"status": "success", "data": [{
        "id": 5, "user_id": None, "action": "login_failed",
        "timestamp": "2026-10-19T12:00:00+02:00", "severity": severity,
        "related_service": "users", "description": "not in the report",
    }]})
    assert records[0].model_dump(mode="json") == {
        "id": 5, "user_id": None, "action": "login_failed",
        "timestamp": "2026-10-19T10:00:00Z", "severity": normalized,
        "related_service": "users",
    }


@pytest.mark.parametrize("timestamp", [
    "2026-10-19T10:00:00", "invalid", 0, "1729332000",
    "0001-01-01T00:00:00+02:00", "9999-12-31T23:59:59-02:00",
])
def test_log_timestamps_require_iso_text_with_timezone(settings, timestamp):
    with pytest.raises(ApiError) as failure:
        fetch(settings, "audit", {"status": "success", "data": [{
            "id": 5, "user_id": 1, "action": "login_failed", "timestamp": timestamp,
            "severity": "Information", "related_service": "users",
        }]})
    assert failure.value.status_code == 502


def test_threat_timestamp_output_is_utc(settings, threat_body):
    records = fetch(settings, "threats", [
        threat_body | {"id": 1, "date_added": "2026-10-19T12:00:00+02:00"},
    ])
    assert records[0].model_dump(mode="json")["date_added"] == "2026-10-19T10:00:00Z"


def test_forwarded_caller_and_reports_credentials_keep_url_prefix(settings):
    observed = []
    def handler(request):
        observed.append(request)
        return httpx.Response(200, json={"status": "success", "data": []})
    config = settings.model_copy(update={"users_url": "http://users.test/api/natalio-hassoun"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        SourceClient(config, client, "original-user-token").fetch("users")
    assert len(observed) == 1
    request = observed[0]
    assert str(request.url) == "http://users.test/api/natalio-hassoun/users"
    assert request.headers["Authorization"] == "Bearer original-user-token"
    assert request.headers["X-Service-Name"] == "reports"
    assert request.headers["X-Service-Key"] == settings.service_key("reports")
    assert all(0 < value <= 5 for value in request.extensions["timeout"].values())


def test_redirect_does_not_forward_credentials_to_another_host(settings):
    observed = []
    def handler(request):
        observed.append(request)
        return httpx.Response(302, headers={"Location": "http://other.test/users"})
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(ApiError) as failure:
            SourceClient(settings, client, "original-user-token").fetch("users")
    assert failure.value.status_code == 502
    assert len(observed) == 1
