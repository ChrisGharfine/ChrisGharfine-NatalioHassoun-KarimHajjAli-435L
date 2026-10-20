import pytest
from pydantic import ValidationError

from services.assets.schemas import AssetCreate, AssetUpdate
from services.threats.schemas import ThreatCreate, ThreatUpdate


@pytest.mark.parametrize("changes", [
    {"name": " "}, {"asset_type": "printer"}, {"ip_address": "999.1.2.3"},
    {"criticality": "urgent"}, {"status": "deleted"}, {"owner_id": 0},
    {"owner_id": True}, {"owner_id": "1"}, {"department": ""}, {"name": "bad\x00name"},
    {"unexpected": "field"}, {"ip_address": "fe80::1%eth0"}, {"name": "a" * 201},
    {"ip_address": 1},
])
def test_invalid_asset_input(asset_body, changes):
    with pytest.raises(ValidationError):
        AssetCreate.model_validate(asset_body | changes)


@pytest.mark.parametrize("field", ["name", "asset_type", "ip_address", "department", "owner_id", "criticality"])
def test_missing_asset_fields(asset_body, field):
    asset_body.pop(field)
    with pytest.raises(ValidationError):
        AssetCreate.model_validate(asset_body)


def test_asset_optional_fields_defaults_and_ipv6(asset_body):
    asset_body.pop("status")
    asset_body.pop("operating_system")
    asset_body.pop("location")
    asset_body["ip_address"] = "2001:0db8:0000:0000:0000:0000:0000:0001"
    asset_body["name"] = "  Lab Server  "
    data = AssetCreate.model_validate(asset_body).model_dump(mode="json")
    assert data["ip_address"] == "2001:db8::1"
    assert data["name"] == "Lab Server"
    assert data["status"] == "active" and data["location"] is None


@pytest.mark.parametrize("model,data", [
    (AssetUpdate, {}), (AssetUpdate, {"name": None}),
    (AssetUpdate, {"owner_id": None}), (AssetUpdate, {"status": "unknown"}),
    (ThreatUpdate, {}), (ThreatUpdate, {"source": None}),
    (ThreatUpdate, {"threat_value": "cannot-change.example"}),
])
def test_rejected_updates(model, data):
    with pytest.raises(ValidationError):
        model.model_validate(data)


def test_optional_asset_fields_can_be_cleared():
    assert AssetUpdate(location=None).model_dump(exclude_unset=True) == {"location": None}


@pytest.mark.parametrize("kind,value,normalized", [
    ("ip_address", "2001:0db8::1", "2001:db8::1"),
    ("domain", "EXAMPLE.COM.", "example.com"),
    ("domain", "bücher.example", "xn--bcher-kva.example"),
    ("file_hash", "A" * 32, "a" * 32),
    ("file_hash", "B" * 40, "b" * 40),
    ("file_hash", "C" * 64, "c" * 64),
    ("file_hash", "D" * 128, "d" * 128),
    ("malware_signature", "Rule_CaseSensitive", "Rule_CaseSensitive"),
    ("other", "  Custom Indicator ", "Custom Indicator"),
])
def test_indicator_normalization(threat_body, kind, value, normalized):
    model = ThreatCreate.model_validate(threat_body | {"threat_type": kind, "threat_value": value})
    assert model.threat_value == normalized


@pytest.mark.parametrize("kind,value", [
    ("ip_address", "999.1.2.3"), ("ip_address", "fe80::1%eth0"),
    ("domain", "https://example.com/path"), ("domain", "localhost"),
    ("domain", "bad_domain.example"), ("domain", "192.0.2.1"),
    ("domain", "-bad.example"), ("domain", "example.com.."), ("file_hash", "x" * 64),
    ("file_hash", "a" * 63), ("other", " "), ("unknown", "value"), ("other", "a" * 513),
])
def test_invalid_indicators(threat_body, kind, value):
    with pytest.raises(ValidationError):
        ThreatCreate.model_validate(threat_body | {"threat_type": kind, "threat_value": value})


@pytest.mark.parametrize("field", ["threat_type", "threat_value", "description", "severity", "source"])
def test_missing_threat_fields(threat_body, field):
    threat_body.pop(field)
    with pytest.raises(ValidationError):
        ThreatCreate.model_validate(threat_body)
