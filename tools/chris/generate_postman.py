"""Generate request definitions, never fabricated execution results or tokens."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def request(name, service, method, path, *, expected=200, body=None,
            role="admin", capture=None, description=""):
    tests = [f'pm.test("HTTP {expected}", () => pm.response.to.have.status({expected}));']
    if capture:
        tests += [
            'pm.test("Created record has an integer ID", () => pm.expect(pm.response.json().id).to.be.a("number"));',
            f'if (pm.response.code === {expected}) pm.collectionVariables.set("{capture}", pm.response.json().id);',
        ]
    if expected >= 400:
        tests.append('pm.test("Consistent error", () => { const data = pm.response.json(); pm.expect(data.status).to.eql("error"); pm.expect(data.message).to.be.a("string"); });')
    auth = {"type": "noauth"} if role is None else {
        "type": "bearer", "bearer": [{"key": "token", "value": "{{" + role + "_token}}", "type": "string"}],
    }
    definition = {
        "name": name,
        "request": {
            "method": method, "auth": auth,
            "header": [{"key": "Accept", "value": "application/json"}],
            "url": "{{" + service + "_base_url}}" + path,
            "description": "Chris Gharfine — " + description,
        },
        "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": tests}}],
    }
    if body is not None:
        definition["request"]["header"].append({"key": "Content-Type", "value": "application/json"})
        definition["request"]["body"] = {"mode": "raw", "raw": body, "options": {"raw": {"language": "json"}}}
    return definition


asset = json.dumps({
    "name": "Lab Server", "asset_type": "server", "ip_address": "192.0.2.10",
    "department": "Security", "owner_id": "{{asset_owner_id}}", "criticality": "high",
    "operating_system": "Linux", "location": "Lab 1", "status": "active",
}, indent=2).replace('"{{asset_owner_id}}"', '{{asset_owner_id}}')
threat = json.dumps({
    "threat_type": "domain", "threat_value": "{{threat_value}}", "description": "Investigation indicator",
    "severity": "critical", "source": "Student lab",
}, indent=2)


def main():
    assets = [
        request("Create asset", "assets", "POST", "/assets", expected=201, body=asset, capture="asset_id",
                description="Create an asset owned by an existing Users ID. Capture the actual ID for subsequent calls."),
        request("List assets", "assets", "GET", "/assets", description="Administrator/auditor list with criticality and status."),
        request("Get asset", "assets", "GET", "/assets/{{asset_id}}", description="Retrieve the created asset; analysts may also use this endpoint."),
        request("Search assets", "assets", "GET", "/assets/search?department=Security&criticality=high", description="Combine department and criticality filters. Try name/type/IP filters too."),
        request("Update asset", "assets", "PUT", "/assets/{{asset_id}}", body='{"status":"under_maintenance","criticality":"critical"}', description="Change status and criticality; compare persisted state."),
        request("Denied employee asset deletion", "assets", "DELETE", "/assets/{{asset_id}}", expected=403, role="employee", description="Negative test: employee cannot delete; original record remains."),
        request("Invalid asset input", "assets", "POST", "/assets", expected=422, body='{"name":"","ip_address":"invalid"}', description="Negative test: missing required information and invalid IP."),
        request("Delete asset", "assets", "DELETE", "/assets/{{asset_id}}", expected=204, description="Delete the unreferenced lab asset after capturing its evidence. Referenced assets return 409."),
    ]
    threats = [
        request("Create threat", "threats", "POST", "/threats", expected=201, body=threat, capture="threat_id", description="Create a domain indicator; normalized type/value must be unique. Change threat_value for a fresh run."),
        request("Reject duplicate threat", "threats", "POST", "/threats", expected=409, body=threat, description="Negative test: repeat the previous insertion before deleting it."),
        request("List threats", "threats", "GET", "/threats", description="List indicators, severities, sources, and creation times."),
        request("Get threat", "threats", "GET", "/threats/{{threat_id}}", description="Retrieve the actual created indicator."),
        request("Search threats", "threats", "GET", "/threats/search?threat_type=domain&severity=critical", description="Filter by type and severity; also test value/source filters."),
        request("Update threat", "threats", "PUT", "/threats/{{threat_id}}", body='{"description":"Reviewed investigation indicator","severity":"high","source":"Chris Gharfine lab"}', description="Update description, severity, and source; type/value are immutable."),
        request("Invalid file hash", "threats", "POST", "/threats", expected=422, body='{"threat_type":"file_hash","threat_value":"not-a-hash","description":"Validation test","severity":"low","source":"Lab"}', description="Negative test: reject a malformed hash without insertion."),
        request("Denied analyst threat deletion", "threats", "DELETE", "/threats/{{threat_id}}", expected=403, role="analyst", description="Negative test: analyst cannot delete threat intelligence."),
        request("Delete threat", "threats", "DELETE", "/threats/{{threat_id}}", expected=204, description="Delete the lab indicator after capturing its evidence."),
    ]
    reports = [request(
        f"{name.title()} report", "reports", "GET", f"/reports/{name}",
        description=f"Generate the {name} report from live source services. Requires all relevant contracts and services; reconcile with real source records.",
    ) for name in ("summary", "incidents", "assets", "threats", "vulnerabilities", "activity")]
    reports += [
        request("Denied analyst report", "reports", "GET", "/reports/summary", role="analyst", expected=403, description="Negative test: analyst has no report access."),
        request("Missing authentication", "reports", "GET", "/reports/summary", role=None, expected=401, description="Negative test: missing credentials; a durable authentication-denial event is queued."),
    ]
    variables = {
        "assets_base_url": "http://localhost:8002", "threats_base_url": "http://localhost:8004",
        "reports_base_url": "http://localhost:8006", "asset_owner_id": "1", "asset_id": "0",
        "threat_id": "0", "threat_value": "investigation.example",
        "admin_token": "", "analyst_token": "", "auditor_token": "", "employee_token": "",
    }
    collection = {
        "info": {
            "name": "Chris Gharfine - Sprint I Assets, Threats and Reports",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": "18 prescribed endpoints plus negative requests. Request templates only: no saved responses or execution evidence. Set real shared-identity tokens locally; never export them. Run writes only against a disposable lab dataset. Obtain an existing owner ID first. Report tests need the real source services. Capture report evidence before deleting the demonstration records, or create additional fixtures through the real APIs.",
        },
        "variable": [{"key": key, "value": value, "type": "string"} for key, value in variables.items()],
        "item": [
            {"name": "Assets (Chris Gharfine)", "item": assets},
            {"name": "Threat Intelligence (Chris Gharfine)", "item": threats},
            {"name": "Security Reports (Chris Gharfine)", "item": reports},
        ],
    }
    output = ROOT / "postman/chris-sprint1.postman_collection.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(collection, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {sum(len(folder['item']) for folder in collection['item'])} requests to {output}")


if __name__ == "__main__":
    main()
