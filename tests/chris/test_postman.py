import json
import re
from pathlib import Path

from services.assets.schemas import AssetCreate, AssetUpdate
from services.threats.schemas import ThreatCreate, ThreatUpdate

COLLECTION = Path(__file__).resolve().parents[2] / "postman/chris-sprint1.postman_collection.json"


def test_collection_covers_prescribed_18_and_scoped_internal_endpoint():
    collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
    assert collection["info"]["schema"] == "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    requests = [item for folder in collection["item"] for item in folder["item"]]
    assert len(requests) == 31
    expected = {
        (method, f"/{resource}" + suffix)
        for resource in ("assets", "threats")
        for method, suffix in (("POST", ""), ("GET", ""), ("GET", "/{id}"),
                               ("GET", "/search"), ("PUT", "/{id}"), ("DELETE", "/{id}"))
    } | {("GET", "/reports/" + name) for name in (
        "summary", "incidents", "assets", "threats", "vulnerabilities", "activity",
    )}
    actual = set()
    for item in requests:
        request = item["request"]
        path = re.sub(r"^\{\{\w+_base_url\}\}", "", request["url"]).split("?")[0]
        path = re.sub(r"\{\{(?:asset|threat|missing_asset)_id\}\}", "{id}", path)
        actual.add((request["method"], path))
        assert "Chris Gharfine" in request["description"]
        assert item["event"] and "response" not in item
    assert actual == expected | {("GET", "/internal/assets/{id}")}
    assert all(not variable["value"] for variable in collection["variable"]
               if variable["key"].endswith(("_token", "_service_key")))


def test_internal_collection_requests_use_service_credentials_without_role_bypass():
    collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
    requests = [item for folder in collection["item"] for item in folder["item"]]
    for name, caller in (("Incident service asset lookup", "incidents"),
                         ("Vulnerability service asset lookup", "vulnerabilities")):
        request = next(item["request"] for item in requests if item["name"] == name)
        headers = {header["key"]: header["value"] for header in request["header"]}
        assert request["auth"]["type"] == "noauth"
        assert headers["X-Service-Name"] == caller
        assert headers["X-Service-Key"] == "{{" + caller + "_service_key}}"


def test_positive_postman_bodies_match_implemented_contracts():
    collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
    schemas = {
        "Create asset": AssetCreate, "Update asset": AssetUpdate,
        "Create threat": ThreatCreate, "Update threat": ThreatUpdate,
    }
    for folder in collection["item"]:
        for item in folder["item"]:
            if item["name"] not in schemas:
                continue
            body = item["request"]["body"]["raw"].replace("{{asset_owner_id}}", "1").replace("{{threat_value}}", "indicator.example")
            schemas[item["name"]].model_validate(json.loads(body))
