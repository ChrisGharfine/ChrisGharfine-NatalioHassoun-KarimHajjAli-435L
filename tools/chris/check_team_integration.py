"""Read-only checks of team-integration-v1.0.0 against real configured services.

Python 3.10+, standard library only. Never print tokens or response bodies.
Passing is evidence for these reads, not for all workflow/security release gates.
"""

import base64
from collections import Counter
from datetime import datetime, timezone
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler, ProxyHandler, Request, build_opener,
)


SERVICES = (
    "users", "assets", "incidents", "threats", "logs", "reports",
    "vulnerabilities", "notifications", "playbooks",
)
NATALIO = {"users", "logs", "playbooks"}
CHRIS = {"assets", "threats", "reports"}
DEFAULT_URLS = {
    name: f"http://127.0.0.1:{8001 + index}"
    + ("/api/natalio-hassoun" if name in NATALIO else "/api/chris-gharfine" if name in CHRIS else "/api/karim-hajj-ali")
    for index, name in enumerate(SERVICES)
}
SOURCES = {
    "users": "/users", "assets": "/assets", "incidents": "/incidents",
    "threats": "/threats", "logs": "/logs", "vulnerabilities": "/vulnerabilities",
}
SEVERITIES = ("low", "medium", "high", "critical")
ASSET_TYPES = ("server", "workstation", "database", "application", "network_device", "cloud_resource")
THREAT_TYPES = ("ip_address", "domain", "file_hash", "malware_signature", "other")
INCIDENT_STATES = {
    "Open": "open", "Under Investigation": "under_investigation",
    "Mitigated": "mitigated", "Resolved": "resolved", "Closed": "closed",
}
VULNERABILITY_STATES = {
    "Open": "open", "Under Investigation": "under_investigation",
    "In Progress": "in_progress", "Resolved": "resolved", "Closed": "closed",
}
SEVERITY_MAP = {value.title(): value for value in SEVERITIES}
LOG_SEVERITIES = {value.title(): value for value in ("information", "warning", "error", "critical")}
MAX_BYTES = 5_000_000
MAX_RECORDS = 50_000


class CheckError(Exception):
    """A safe diagnostic containing no response data or credential values."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_configuration(environ):
    token = environ.get("TEAM_ADMIN_TOKEN", "").strip()
    key = environ.get("TEAM_REPORTS_SERVICE_KEY", "").strip()
    if not token or len(key) < 32 or any(c in token + key for c in "\r\n"):
        raise CheckError("Set TEAM_ADMIN_TOKEN and TEAM_REPORTS_SERVICE_KEY locally (key: at least 32 characters).")
    urls = {}
    for name, default in DEFAULT_URLS.items():
        value = environ.get(f"TEAM_{name.upper()}_URL", default).rstrip("/")
        try:
            parsed = urlsplit(value)
            valid = (
                parsed.scheme in {"http", "https"} and parsed.hostname
                and not parsed.username and not parsed.password
                and not parsed.query and not parsed.fragment
                and not any(c.isspace() for c in value)
            )
            parsed.port  # Validate any explicit port, without displaying it.
        except ValueError:
            valid = False
        if not valid:
            raise CheckError(f"Invalid TEAM_{name.upper()}_URL; use an HTTP(S) base URL including its prefix, without credentials/query/fragment.")
        urls[name] = value
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        subject = payload["sub"]
        if not isinstance(subject, str) or not subject.isascii() or not subject.isdecimal():
            raise ValueError
        subject_id = int(subject)
        if not 0 < subject_id <= 2147483647:
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CheckError("TEAM_ADMIN_TOKEN must be a Users-issued JWT with a positive integer-text subject.") from None
    # Decoding above only supplies an ID for consistency checking. It does not
    # verify a signature. The real Users endpoint authenticates this token.
    return urls, token, key, subject_id


class LiveAPI:
    def __init__(self, urls, token, key):
        self.urls, self.token, self.key = urls, token, key
        self.opener = build_opener(ProxyHandler({}), NoRedirects())

    def request(self, service, path, *, method="GET", protected=True):
        headers = {"Accept": "application/json"}
        if protected:
            headers.update({
                "Authorization": "Bearer " + self.token,
                "X-Service-Name": "reports", "X-Service-Key": self.key,
            })
        req = Request(self.urls[service] + path, headers=headers, method=method)
        label = f"{service} {method} {path}"
        try:
            with self.opener.open(req, timeout=5) as response:
                if response.status != 200:
                    raise CheckError(f"{label}: expected HTTP 200.")
                if response.headers.get_content_type() != "application/json":
                    raise CheckError(f"{label}: expected application/json.")
                raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise CheckError(f"{label}: response exceeds byte bound.")
        except HTTPError as error:
            code = error.code
            error.close()
            raise CheckError(f"{label}: HTTP {code}; response body suppressed.") from None
        except (URLError, OSError, ValueError):
            raise CheckError(f"{label}: request failed; verify address, availability and local configuration.") from None
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise CheckError(f"{label}: invalid JSON; response body suppressed.") from None


def require(condition, message):
    if not condition:
        raise CheckError(message)


def positive_id(value, label):
    require(type(value) is int and 0 < value <= 9223372036854775807,
            f"{label}: expected a positive integer ID.")
    return value


def text_field(row, field, label):
    value = row.get(field)
    require(isinstance(value, str) and bool(value.strip()), f"{label}: invalid {field}.")
    return value


def enum_field(row, field, allowed, label):
    value = row.get(field)
    require(isinstance(value, str) and value in allowed, f"{label}: unknown {field} value.")
    return allowed[value] if isinstance(allowed, dict) else value


def utc_string(value):
    require(isinstance(value, str), "Timestamp must be timezone-aware ISO 8601 text.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise CheckError("Timestamp must be timezone-aware ISO 8601 text.") from None


def normalize_source(source, body):
    if source in {"users", "logs", "incidents", "vulnerabilities"}:
        require(isinstance(body, dict) and body.get("status") == "success",
                f"{source}: invalid success envelope.")
        pagination_fields = {"next", "next_page", "page", "pages", "total_pages", "offset", "limit", "cursor", "pagination", "has_more"}
        require(not pagination_fields.intersection(body), f"{source}: pagination is not part of v1 complete-list responses.")
        array_key = source if source in {"incidents", "vulnerabilities"} else "data"
        rows = body.get(array_key)
    else:
        rows = body
    require(isinstance(rows, list), f"{source}: expected the complete array at the v1 location.")
    require(len(rows) <= MAX_RECORDS, f"{source}: record bound exceeded.")
    if source in {"incidents", "vulnerabilities"}:
        require(type(body.get("count")) is int and body["count"] == len(rows),
                f"{source}: count must equal the complete array length.")
    result, seen = [], set()
    id_key = {"incidents": "incident_id", "vulnerabilities": "vulnerability_id"}.get(source, "id")
    for row in rows:
        require(isinstance(row, dict), f"{source}: record must be an object.")
        record_id = positive_id(row.get(id_key), source)
        require(record_id not in seen, f"{source}: duplicate record ID.")
        seen.add(record_id)
        record = {"id": record_id}
        if source == "users":
            require(record_id <= 2147483647, "users: ID exceeds the Users contract range.")
        elif source == "assets":
            record.update(
                asset_type=enum_field(row, "asset_type", ASSET_TYPES, source),
                criticality=enum_field(row, "criticality", SEVERITIES, source),
                status=enum_field(row, "status", ("active", "inactive", "under_maintenance"), source),
            )
        elif source in {"incidents", "vulnerabilities"}:
            record.update(
                severity=enum_field(row, "severity" if source == "incidents" else "severity_level", SEVERITY_MAP, source),
                status=enum_field(row, "status", INCIDENT_STATES if source == "incidents" else VULNERABILITY_STATES, source),
            )
        elif source == "threats":
            record.update(
                threat_type=enum_field(row, "threat_type", THREAT_TYPES, source),
                severity=enum_field(row, "severity", SEVERITIES, source),
                date_added=utc_string(row.get("date_added")),
            )
            for field in ("threat_value", "description", "source"):
                record[field] = text_field(row, field, source)
        elif source == "logs":
            require("user_id" in row, "logs: user_id must be present (nullable).")
            actor = row["user_id"]
            if actor is not None:
                positive_id(actor, "logs user_id")
            record.update(
                user_id=actor, action=text_field(row, "action", source),
                timestamp=utc_string(row.get("timestamp")),
                severity=enum_field(row, "severity", LOG_SEVERITIES, source),
                related_service=text_field(row, "related_service", source),
            )
        else:
            raise CheckError("Unknown report source.")
        result.append(record)
    return sorted(result, key=lambda item: item["id"])


def grouped(rows, field, values):
    counts = Counter(row[field] for row in rows)
    return {value: counts[value] for value in values}


def recent(rows, field):
    return sorted(rows, key=lambda row: (
        datetime.fromisoformat(utc_string(row[field]).replace("Z", "+00:00")), row["id"],
    ), reverse=True)[:10]


def expected_reports(sources):
    users, assets, incidents, threats, logs, vulnerabilities = (
        sources[name] for name in ("users", "assets", "incidents", "threats", "logs", "vulnerabilities")
    )
    actions = Counter(row["action"] for row in logs)
    return {
        "summary": {"users": len(users), "assets": len(assets),
                    "open_incidents": sum(row["status"] == "open" for row in incidents),
                    "critical_threats": sum(row["severity"] == "critical" for row in threats)},
        "incidents": {"total_incidents": len(incidents),
                      "incidents_by_severity": grouped(incidents, "severity", SEVERITIES),
                      "incidents_by_status": grouped(incidents, "status", INCIDENT_STATES.values())},
        "assets": {"total_assets": len(assets),
                   "critical_assets": sum(row["criticality"] == "critical" for row in assets),
                   "assets_by_type": grouped(assets, "asset_type", ASSET_TYPES)},
        "threats": {"total_threats": len(threats),
                    "threats_by_severity": grouped(threats, "severity", SEVERITIES),
                    "threats_by_type": grouped(threats, "threat_type", THREAT_TYPES),
                    "recent_threats": recent(threats, "date_added")},
        "vulnerabilities": {"total_vulnerabilities": len(vulnerabilities),
                            "vulnerabilities_by_severity": grouped(vulnerabilities, "severity", SEVERITIES),
                            "vulnerabilities_by_status": grouped(vulnerabilities, "status", VULNERABILITY_STATES.values()),
                            "critical_vulnerabilities": sum(row["severity"] == "critical" for row in vulnerabilities)},
        "activity": {"total_user_activities": len(logs),
                     "login_attempts": actions["login_success"] + actions["login_failed"],
                     "failed_login_attempts": actions["login_failed"],
                     "most_performed_actions": [{"action": action, "count": count} for action, count in
                                                sorted(actions.items(), key=lambda item: (-item[1], item[0]))[:10]],
                     "recent_activities": recent(logs, "timestamp")},
    }


def canonical_report(body):
    # Normalize serialization only; never normalize unknown enums or envelopes.
    if isinstance(body, dict):
        return {key: utc_string(value) if key in {"timestamp", "date_added"}
                else canonical_report(value) for key, value in body.items()}
    if isinstance(body, list):
        return [canonical_report(value) for value in body]
    return body


def strict_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(strict_equal(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(strict_equal(a, e) for a, e in zip(actual, expected))
    return actual == expected


def run_checks(api, subject_id, progress=print):
    for name in SERVICES:
        path = "/ready" if name in CHRIS else "/health"
        body = api.request(name, path, protected=False)
        if name in NATALIO:
            valid = (isinstance(body, dict) and body.get("status") == "success"
                     and isinstance(body.get("data"), dict) and body["data"].get("service") == name)
        else:
            valid = (isinstance(body, dict) and body.get("status") == ("ready" if name in CHRIS else "ok")
                     and body.get("service") == name)
        require(valid, f"{name}: unexpected readiness/health response.")
        progress(f"PASS {name} readiness/health")

    body = api.request("users", "/internal/identity/verify", method="POST")
    identity = body.get("data") if isinstance(body, dict) else None
    require(isinstance(body, dict) and body.get("status") == "success"
            and isinstance(identity, dict) and type(identity.get("id")) is int
            and identity["id"] == subject_id and identity.get("role") == "security_administrator"
            and identity.get("account_status") == "active",
            "Users identity must confirm the same active administrator subject.")
    progress("PASS current identity and subject consistency")

    sources = {name: normalize_source(name, api.request(name, path)) for name, path in SOURCES.items()}
    progress("PASS six complete report-source schemas")
    for suffix, expected in expected_reports(sources).items():
        actual = canonical_report(api.request("reports", "/reports/" + suffix))
        require(strict_equal(actual, expected), f"reports/{suffix}: result differs from source records or v1 response schema; data suppressed.")
        progress(f"PASS reports/{suffix} reconciliation")

    after = {name: normalize_source(name, api.request(name, path)) for name, path in SOURCES.items()}
    require(strict_equal(after, sources), "Source data changed during verification; drain queues, pause writes and retry.")
    progress("PASS source stability across report reads")


def main(environ=None):
    try:
        urls, token, key, subject_id = load_configuration(os.environ if environ is None else environ)
    except CheckError as error:
        print("CONFIGURATION: " + str(error))
        return 2
    try:
        run_checks(LiveAPI(urls, token, key), subject_id)
    except CheckError as error:
        print("FAILED: " + str(error))
        return 1
    print("PASS configured live reads/reconciliation. Workflow, role, outage and database release gates still require separate execution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
