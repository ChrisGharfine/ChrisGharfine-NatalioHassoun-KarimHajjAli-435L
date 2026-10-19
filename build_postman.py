"""Generate the Postman collections for services 3, 7 and 8.

Rather than typing the saved examples by hand, this script resets the
database, fires every request at the running Flask app and stores whatever
comes back as the example for that request. The examples in the collections
are therefore real responses from a real run, which is exactly what the
sprint asks for as evidence.

Start the server first, then run this::

    python app.py          (in one terminal)
    python build_postman.py (in another)

It writes one collection per service plus a shared environment file.

:author: Karim Hajj Ali
"""

import json
import os
import urllib.error
import urllib.request
import uuid

BASE_URL = "http://127.0.0.1:5000"

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "postman")

#: Tokens collected during the run, keyed by role.
TOKENS = {}


# ---------------------------------------------------------------------------
# Talking to the server
# ---------------------------------------------------------------------------

def call(method, path, body=None, token=None):
    """Send one HTTP request to the running app and return the result.

    :param method: HTTP method.
    :type method: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param body: JSON body to send, defaults to None.
    :type body: dict, optional
    :param token: Bearer token to send, defaults to None.
    :type token: str, optional
    :return: ``(status code, reason, response body as text)``.
    :rtype: tuple
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(BASE_URL + path, data=data,
                                     method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer %s" % token)

    try:
        with urllib.request.urlopen(request) as response:
            return (response.status, response.reason,
                    response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, error.reason, error.read().decode("utf-8")


# ---------------------------------------------------------------------------
# Building collection pieces
# ---------------------------------------------------------------------------

def build_url(path):
    """Turn a path into the URL object Postman expects.

    :param path: Path beginning with ``/``, possibly with a query string.
    :type path: str
    :return: The URL object.
    :rtype: dict
    """
    path_part, _, query_part = path.partition("?")
    url = {
        "raw": "{{base_url}}" + path,
        "host": ["{{base_url}}"],
        "path": [segment for segment in path_part.split("/") if segment],
    }
    if query_part:
        url["query"] = []
        for pair in query_part.split("&"):
            key, _, value = pair.partition("=")
            url["query"].append({
                "key": key,
                "value": urllib.request.unquote(value),
            })
    return url


def build_request(method, path, body=None, token_variable=None,
                  description=""):
    """Build the request half of a Postman item.

    :param method: HTTP method.
    :type method: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param body: JSON body, defaults to None.
    :type body: dict, optional
    :param token_variable: Name of the Postman variable holding the token,
        defaults to None for unauthenticated requests.
    :type token_variable: str, optional
    :param description: What the request does, shown in Postman.
    :type description: str
    :return: The request object.
    :rtype: dict
    """
    headers = []
    if body is not None:
        headers.append({"key": "Content-Type", "value": "application/json"})
    if token_variable:
        headers.append({"key": "Authorization",
                        "value": "Bearer {{%s}}" % token_variable})

    request = {
        "method": method,
        "header": headers,
        "url": build_url(path),
        "description": description,
    }
    if body is not None:
        request["body"] = {
            "mode": "raw",
            "raw": json.dumps(body, indent=2),
            "options": {"raw": {"language": "json"}},
        }
    return request


def build_example(name, request, status_code, reason, body_text):
    """Build one saved example from a real response.

    :param name: Example name, e.g. ``"201 Created"``.
    :type name: str
    :param request: The request object the example belongs to.
    :type request: dict
    :param status_code: HTTP status code that came back.
    :type status_code: int
    :param reason: HTTP reason phrase.
    :type reason: str
    :param body_text: Raw response body.
    :type body_text: str
    :return: The saved example.
    :rtype: dict
    """
    try:
        pretty = json.dumps(json.loads(body_text), indent=2)
    except ValueError:
        pretty = body_text

    return {
        "name": name,
        "originalRequest": request,
        "status": reason,
        "code": status_code,
        "_postman_previewlanguage": "json",
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "cookie": [],
        "body": pretty,
    }


def make_item(name, method, path, description, token_role=None, body=None,
              extra_cases=()):
    """Build a complete Postman item, executing it to capture examples.

    :param name: Request name as it appears in Postman.
    :type name: str
    :param method: HTTP method.
    :type method: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param description: What the request does and who may call it.
    :type description: str
    :param token_role: Which seeded role to authenticate as, defaults to None.
    :type token_role: str, optional
    :param body: JSON body for the primary request, defaults to None.
    :type body: dict, optional
    :param extra_cases: Further ``(example name, method, path, role, body)``
        tuples to run and attach as additional examples, such as the error
        cases, defaults to ``()``.
    :type extra_cases: tuple, optional
    :return: The finished item.
    :rtype: dict
    """
    token_variable = ("%s_token" % token_role) if token_role else None
    request = build_request(method, path, body, token_variable, description)

    status, reason, text = call(method, path, body,
                                TOKENS.get(token_role) if token_role else None)
    examples = [build_example("%d %s" % (status, reason), request,
                              status, reason, text)]

    for case_name, case_method, case_path, case_role, case_body in extra_cases:
        case_token_variable = ("%s_token" % case_role) if case_role else None
        case_request = build_request(case_method, case_path, case_body,
                                     case_token_variable, description)
        case_status, case_reason, case_text = call(
            case_method, case_path, case_body,
            TOKENS.get(case_role) if case_role else None)
        examples.append(build_example(case_name, case_request, case_status,
                                      case_reason, case_text))

    return {"name": name, "request": request, "response": examples}


def login_folder():
    """Build the login folder that every collection starts with.

    Each login carries a small test script that writes the returned token
    into the environment, so the rest of the collection can be run without
    copying tokens by hand.

    :return: The folder.
    :rtype: dict
    """
    accounts = [
        ("Login as Security Administrator", "karim.admin", "Admin#2026",
         "admin"),
        ("Login as Security Analyst", "rana.analyst", "Analyst#2026",
         "analyst"),
        ("Login as Regular Employee", "lina.employee", "Employee#2026",
         "employee"),
        ("Login as Auditor", "samir.auditor", "Auditor#2026", "auditor"),
    ]

    items = []
    for name, username, password, role in accounts:
        body = {"username": username, "password": password}
        request = build_request(
            "POST", "/auth/login", body, None,
            "Authenticates and stores the token in the '%s_token' "
            "environment variable. Run this before the other requests."
            % role)

        status, reason, text = call("POST", "/auth/login", body)
        examples = [build_example("%d %s" % (status, reason), request,
                                  status, reason, text)]

        if role == "admin":
            bad_body = {"username": username, "password": "wrong-password"}
            bad_request = build_request("POST", "/auth/login", bad_body, None,
                                        "Authentication failure case.")
            bad_status, bad_reason, bad_text = call("POST", "/auth/login",
                                                    bad_body)
            examples.append(build_example(
                "%d %s (wrong password)" % (bad_status, bad_reason),
                bad_request, bad_status, bad_reason, bad_text))

        items.append({
            "name": name,
            "event": [{
                "listen": "test",
                "script": {
                    "type": "text/javascript",
                    "exec": [
                        "if (pm.response.code === 200) {",
                        "    pm.environment.set(\"%s_token\", "
                        "pm.response.json().token);" % role,
                        "}",
                    ],
                },
            }],
            "request": request,
            "response": examples,
        })

    return {
        "name": "0. Authentication (run first)",
        "description": "Logs in as each role and saves the tokens. "
                       "Authentication belongs to Service 1 and is included "
                       "here only so this collection can be run on its own.",
        "item": items,
    }


def write_collection(filename, name, description, items):
    """Write one collection file to the ``postman`` folder.

    :param filename: File name to write.
    :type filename: str
    :param name: Collection name as shown in Postman.
    :type name: str
    :param description: Collection description.
    :type description: str
    :param items: The folders and requests it contains.
    :type items: list
    :return: ``None``
    :rtype: NoneType
    """
    collection = {
        "info": {
            "_postman_id": str(uuid.uuid4()),
            "name": name,
            "description": description,
            "schema": "https://schema.getpostman.com/json/collection/"
                      "v2.1.0/collection.json",
        },
        "item": items,
        "variable": [{"key": "base_url", "value": BASE_URL, "type": "string"}],
    }

    path = os.path.join(OUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(collection, handle, indent=2)

    examples = sum(len(entry.get("response", []))
                   for folder in items
                   for entry in folder.get("item", [folder]))
    print("  %-52s %2d requests, %2d saved examples"
          % (filename,
             sum(len(folder.get("item", [folder])) for folder in items),
             examples))


def write_environment():
    """Write the shared Postman environment file.

    Holds ``base_url`` plus a slot for each role's token, which the login
    requests fill in automatically.

    :return: ``None``
    :rtype: NoneType
    """
    values = [{"key": "base_url", "value": BASE_URL, "enabled": True,
               "type": "default"}]
    for role in ("admin", "analyst", "employee", "auditor"):
        values.append({"key": "%s_token" % role, "value": "",
                       "enabled": True, "type": "default"})

    environment = {
        "id": str(uuid.uuid4()),
        "name": "SIRMS Local",
        "values": values,
        "_postman_variable_scope": "environment",
    }

    path = os.path.join(OUT_DIR, "SIRMS Local.postman_environment.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(environment, handle, indent=2)
    print("  %-52s base_url + 4 token slots"
          % "SIRMS Local.postman_environment.json")


# ---------------------------------------------------------------------------
# The three collections
# ---------------------------------------------------------------------------

def build_incidents():
    """Build the Service 3 collection.

    :return: The collection items.
    :rtype: list
    """
    items = [
        make_item(
            "1. Create Incident", "POST", "/incidents",
            "Reports a new cybersecurity incident. Allowed for the Security "
            "Administrator and the Regular Employee. A new incident always "
            "starts at status 'Open'.",
            token_role="admin",
            body={
                "title": "Ransomware detected on domain controller",
                "description": "Endpoint protection flagged file encryption "
                               "activity on the primary domain controller.",
                "category": "Malware Infection",
                "severity": "Critical",
                "affected_asset": 1,
            },
            extra_cases=[
                ("201 Created (reported by an employee)", "POST",
                 "/incidents", "employee",
                 {"title": "Suspicious email requesting credentials",
                  "description": "Received an email impersonating the IT "
                                 "helpdesk and asking for my password.",
                  "category": "Phishing Attack",
                  "severity": "Medium",
                  "affected_asset": 3}),
                ("400 Bad Request (invalid severity)", "POST", "/incidents",
                 "admin",
                 {"title": "Test incident", "description": "Test",
                  "category": "Unauthorized Access",
                  "severity": "Catastrophic"}),
                ("400 Bad Request (missing title)", "POST", "/incidents",
                 "admin",
                 {"description": "No title supplied",
                  "category": "Data Leakage", "severity": "Low"}),
                ("403 Forbidden (analyst may not create)", "POST",
                 "/incidents", "analyst",
                 {"title": "Test", "description": "Test",
                  "category": "Test", "severity": "Low"}),
            ]),

        make_item(
            "2. Retrieve All Incidents", "GET", "/incidents",
            "Returns every incident with its status and assigned analyst. "
            "Allowed for the Security Administrator and the Auditor.",
            token_role="admin",
            extra_cases=[
                ("200 OK (auditor)", "GET", "/incidents", "auditor", None),
                ("403 Forbidden (employee)", "GET", "/incidents",
                 "employee", None),
                ("401 Unauthorized (no token)", "GET", "/incidents",
                 None, None),
            ]),

        make_item(
            "3. Retrieve Specific Incident", "GET", "/incidents/1",
            "Returns one incident together with all of its investigation "
            "notes. A Regular Employee may only read incidents they "
            "reported themselves.",
            token_role="admin",
            extra_cases=[
                ("404 Not Found (unknown id)", "GET", "/incidents/9999",
                 "admin", None),
                ("200 OK (employee reading their own report)", "GET",
                 "/incidents/2", "employee", None),
                ("403 Forbidden (employee reading another report)", "GET",
                 "/incidents/1", "employee", None),
            ]),

        make_item(
            "4. Assign Incident to Analyst", "PUT", "/incidents/1/assign",
            "Assigns an incident to a Security Analyst. Verifies the "
            "incident exists and that the target user really holds the "
            "Security Analyst role, writes the assignment to the audit log, "
            "and raises an 'Incident Assignment' notification in Service 8.",
            token_role="admin", body={"analyst_id": 2},
            extra_cases=[
                ("400 Bad Request (target is not an analyst)", "PUT",
                 "/incidents/1/assign", "admin", {"analyst_id": 4}),
                ("404 Not Found (unknown user)", "PUT",
                 "/incidents/1/assign", "admin", {"analyst_id": 9999}),
                ("403 Forbidden (analyst may not assign)", "PUT",
                 "/incidents/1/assign", "analyst", {"analyst_id": 3}),
            ]),

        make_item(
            "5a. Update Status - rejected shortcut", "PUT",
            "/incidents/1/status",
            "Demonstrates the lifecycle rule. An incident at 'Open' cannot "
            "jump straight to 'Closed'; the response names the only status "
            "that would have been accepted.",
            token_role="analyst", body={"status": "Closed"}),

        make_item(
            "5b. Update Status - Open to Under Investigation", "PUT",
            "/incidents/1/status",
            "First legal step of the lifecycle "
            "Open -> Under Investigation -> Mitigated -> Resolved -> Closed.",
            token_role="analyst", body={"status": "Under Investigation"},
            extra_cases=[
                ("200 OK (-> Mitigated)", "PUT", "/incidents/1/status",
                 "analyst", {"status": "Mitigated"}),
                ("200 OK (-> Resolved, stamps resolution date)", "PUT",
                 "/incidents/1/status", "analyst", {"status": "Resolved"}),
                ("200 OK (-> Closed)", "PUT", "/incidents/1/status",
                 "analyst", {"status": "Closed"}),
                ("400 Bad Request (closed incident, no further changes)",
                 "PUT", "/incidents/1/status", "analyst",
                 {"status": "Open"}),
            ]),

        make_item(
            "6. Add Investigation Note", "POST", "/incidents/1/notes",
            "Adds an investigation note to an incident. The note records "
            "which analyst wrote it and when, and is returned as part of "
            "GET /incidents/{id}.",
            token_role="analyst",
            body={"note_content": "Isolated the host from the network and "
                                  "captured a memory image for analysis."},
            extra_cases=[
                ("201 Created (second note)", "POST", "/incidents/1/notes",
                 "analyst",
                 {"note_content": "Confirmed the encryption routine matches "
                                  "a known ransomware family."}),
                ("400 Bad Request (empty note)", "POST",
                 "/incidents/1/notes", "analyst", {"note_content": "   "}),
                ("404 Not Found (unknown incident)", "POST",
                 "/incidents/9999/notes", "analyst",
                 {"note_content": "orphan note"}),
            ]),
    ]
    return [login_folder(), {"name": "Service 3 - Incident Management",
                             "item": items}]


def build_vulnerabilities():
    """Build the Service 7 collection.

    :return: The collection items.
    :rtype: list
    """
    items = [
        make_item(
            "1. Add New Vulnerability", "POST", "/vulnerabilities",
            "Registers a vulnerability against an asset. Administrators "
            "only. A High or Critical finding also raises a 'Vulnerability "
            "Alert' notification for the owner of the affected asset.",
            token_role="admin",
            body={
                "title": "Remote code execution in XZ Utils",
                "description": "A backdoor in the upstream package allows "
                               "unauthenticated remote code execution.",
                "severity": "Critical",
                "affected_asset": 2,
                "cve_identifier": "CVE-2024-3094",
                "cvss_score": 10.0,
                "discovery_source": "Vendor advisory",
            },
            extra_cases=[
                ("201 Created (High)", "POST", "/vulnerabilities", "admin",
                 {"title": "Unpatched SMB signing on file server",
                  "description": "SMB signing is not enforced, allowing "
                                 "relay attacks.",
                  "severity": "High", "affected_asset": 2,
                  "cve_identifier": "CVE-2024-21345", "cvss_score": 8.1,
                  "discovery_source": "Penetration test"}),
                ("201 Created (Medium)", "POST", "/vulnerabilities", "admin",
                 {"title": "Outdated TLS configuration",
                  "description": "The payroll application still negotiates "
                                 "TLS 1.0.",
                  "severity": "Medium", "affected_asset": 6,
                  "cve_identifier": "CVE-2023-11111", "cvss_score": 5.3,
                  "discovery_source": "Internal scan"}),
                ("400 Bad Request (malformed CVE)", "POST",
                 "/vulnerabilities", "admin",
                 {"title": "Test", "description": "Test", "severity": "Low",
                  "affected_asset": 1, "cve_identifier": "CVE-BAD"}),
                ("400 Bad Request (CVSS out of range)", "POST",
                 "/vulnerabilities", "admin",
                 {"title": "Test", "description": "Test", "severity": "Low",
                  "affected_asset": 1, "cvss_score": 44}),
                ("404 Not Found (unknown asset)", "POST",
                 "/vulnerabilities", "admin",
                 {"title": "Test", "description": "Test", "severity": "Low",
                  "affected_asset": 9999}),
            ]),

        make_item(
            "2. Retrieve All Vulnerabilities", "GET", "/vulnerabilities",
            "Returns every vulnerability with its severity, affected asset "
            "and current status. Administrator, Analyst and Auditor.",
            token_role="analyst",
            extra_cases=[
                ("403 Forbidden (employee has no access)", "GET",
                 "/vulnerabilities", "employee", None),
            ]),

        make_item(
            "3. Retrieve Specific Vulnerability", "GET",
            "/vulnerabilities/1",
            "Returns one vulnerability by id.",
            token_role="auditor",
            extra_cases=[
                ("404 Not Found (unknown id)", "GET",
                 "/vulnerabilities/9999", "admin", None),
            ]),

        make_item(
            "4. Update Vulnerability", "PUT", "/vulnerabilities/3",
            "Updates a vulnerability. Any of description, severity, status, "
            "cvss_score and resolution_date may be sent; anything omitted "
            "is left unchanged. Administrator and Analyst.",
            token_role="analyst",
            body={"description": "Confirmed on the staging instance as well.",
                  "cvss_score": 6.5},
            extra_cases=[
                ("400 Bad Request (non-numeric CVSS)", "PUT",
                 "/vulnerabilities/3", "analyst",
                 {"cvss_score": "not-a-number"}),
                ("400 Bad Request (nothing to update)", "PUT",
                 "/vulnerabilities/3", "analyst", {}),
            ]),

        make_item(
            "4b. Update Status - lifecycle", "PUT", "/vulnerabilities/1",
            "The vulnerability lifecycle is Open -> Under Investigation -> "
            "In Progress -> Resolved -> Closed. Note the extra 'In "
            "Progress' step compared with incidents. Skipping a step is "
            "rejected.",
            token_role="analyst", body={"status": "Resolved"},
            extra_cases=[
                ("200 OK (-> Under Investigation)", "PUT",
                 "/vulnerabilities/1", "analyst",
                 {"status": "Under Investigation"}),
                ("200 OK (-> In Progress)", "PUT", "/vulnerabilities/1",
                 "analyst", {"status": "In Progress"}),
                ("200 OK (-> Resolved, stamps resolution date)", "PUT",
                 "/vulnerabilities/1", "analyst", {"status": "Resolved"}),
            ]),

        make_item(
            "5. Search Vulnerabilities", "GET",
            "/vulnerabilities/search?severity=High",
            "Searches by CVE, severity, asset and status. Filters combine "
            "with AND. The CVE filter matches partially, so ?cve=2024 "
            "returns every CVE issued that year.",
            token_role="analyst",
            extra_cases=[
                ("200 OK (by status)", "GET",
                 "/vulnerabilities/search?status=Open", "analyst", None),
                ("200 OK (partial CVE match)", "GET",
                 "/vulnerabilities/search?cve=2024", "analyst", None),
                ("200 OK (by asset)", "GET",
                 "/vulnerabilities/search?asset_id=2", "analyst", None),
                ("200 OK (two filters combined)", "GET",
                 "/vulnerabilities/search?severity=High&status=Open",
                 "analyst", None),
                ("200 OK (no matches)", "GET",
                 "/vulnerabilities/search?severity=Low", "analyst", None),
                ("400 Bad Request (invalid filter value)", "GET",
                 "/vulnerabilities/search?severity=Extreme", "analyst",
                 None),
            ]),

        make_item(
            "6. Delete Vulnerability", "DELETE", "/vulnerabilities/3",
            "Removes a vulnerability record. Administrators only; an "
            "analyst attempting this is refused and the attempt is written "
            "to the audit log.",
            token_role="analyst",
            extra_cases=[
                ("200 OK (administrator)", "DELETE", "/vulnerabilities/3",
                 "admin", None),
                ("404 Not Found (already deleted)", "DELETE",
                 "/vulnerabilities/3", "admin", None),
            ]),
    ]
    return [login_folder(), {"name": "Service 7 - Vulnerability Management",
                             "item": items}]


def build_notifications():
    """Build the Service 8 collection.

    :return: The collection items.
    :rtype: list
    """
    items = [
        make_item(
            "1. Create Notification", "POST", "/notifications",
            "Creates a notification for a user. Administrators only. "
            "Notifications are also generated automatically by Service 3 "
            "when an incident is assigned, and by Service 7 when a High or "
            "Critical vulnerability is registered.",
            token_role="admin",
            body={
                "user_id": 3,
                "title": "Quarterly access review due",
                "message": "Please review the access rights for the systems "
                           "you administer.",
                "notification_type": "System Notification",
                "severity": "Low",
            },
            extra_cases=[
                ("400 Bad Request (invalid type)", "POST", "/notifications",
                 "admin",
                 {"user_id": 3, "title": "Test", "message": "Test",
                  "notification_type": "Carrier Pigeon", "severity": "Low"}),
                ("404 Not Found (unknown recipient)", "POST",
                 "/notifications", "admin",
                 {"user_id": 9999, "title": "Test", "message": "Test",
                  "notification_type": "Security Alert", "severity": "Low"}),
                ("403 Forbidden (analyst may not create)", "POST",
                 "/notifications", "analyst",
                 {"user_id": 3, "title": "Test", "message": "Test",
                  "notification_type": "Security Alert", "severity": "Low"}),
            ]),

        make_item(
            "2. Retrieve User Notifications", "GET", "/notifications/user/2",
            "Returns one user's notifications, newest first, with a count "
            "of how many are unread. Analysts and employees may only read "
            "their own inbox; administrators and auditors may read any.",
            token_role="admin",
            extra_cases=[
                ("200 OK (empty inbox)", "GET", "/notifications/user/5",
                 "admin", None),
                ("404 Not Found (unknown user)", "GET",
                 "/notifications/user/9999", "admin", None),
                ("403 Forbidden (analyst reading another inbox)", "GET",
                 "/notifications/user/4", "analyst", None),
            ]),

        make_item(
            "3. Retrieve Specific Notification", "GET", "/notifications/1",
            "Returns one notification by id.",
            token_role="admin",
            extra_cases=[
                ("404 Not Found (unknown id)", "GET", "/notifications/9999",
                 "admin", None),
                ("403 Forbidden (not the recipient)", "GET",
                 "/notifications/1", "employee", None),
            ]),

        make_item(
            "4. Mark Notification as Read", "PUT", "/notifications/1/read",
            "Marks a notification as read and stamps the read date. "
            "Marking an already-read notification again leaves the original "
            "date alone. Auditors are read-only and cannot call this.",
            token_role="analyst",
            extra_cases=[
                ("200 OK (already read, date unchanged)", "PUT",
                 "/notifications/1/read", "analyst", None),
                ("403 Forbidden (auditor is read-only)", "PUT",
                 "/notifications/1/read", "auditor", None),
            ]),

        make_item(
            "5. Search Notifications", "GET",
            "/notifications/search?status=Unread",
            "Searches by user, type, severity and status. An analyst's "
            "search is silently restricted to their own inbox, so the "
            "filter cannot be used to read somebody else's notifications.",
            token_role="admin",
            extra_cases=[
                ("200 OK (by type)", "GET",
                 "/notifications/search?notification_type=Incident%20"
                 "Assignment", "admin", None),
                ("200 OK (by severity)", "GET",
                 "/notifications/search?severity=Critical", "admin", None),
                ("200 OK (analyst search, scoped to own inbox)", "GET",
                 "/notifications/search?user_id=4", "analyst", None),
                ("400 Bad Request (invalid status filter)", "GET",
                 "/notifications/search?status=Archived", "admin", None),
            ]),

        make_item(
            "6. Delete Notification", "DELETE", "/notifications/2",
            "Removes a notification. Administrators only.",
            token_role="analyst",
            extra_cases=[
                ("200 OK (administrator)", "DELETE", "/notifications/2",
                 "admin", None),
                ("404 Not Found (already deleted)", "DELETE",
                 "/notifications/2", "admin", None),
            ]),
    ]
    return [login_folder(),
            {"name": "Service 8 - Notification and Alert Management",
             "item": items}]


def main():
    """Reset the data, run every request and write the collection files.

    :return: ``None``
    :rtype: NoneType
    """
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)

    print("Resetting the database")
    from database import create_db_tables
    from seed import clear_tables, seed_assets, seed_users
    create_db_tables()
    clear_tables()
    seed_users()
    seed_assets()

    print("Logging in")
    for role, username, password in (
            ("admin", "karim.admin", "Admin#2026"),
            ("analyst", "rana.analyst", "Analyst#2026"),
            ("employee", "lina.employee", "Employee#2026"),
            ("auditor", "samir.auditor", "Auditor#2026")):
        _, _, text = call("POST", "/auth/login",
                          {"username": username, "password": password})
        TOKENS[role] = json.loads(text)["token"]
    print("  got %d tokens" % len(TOKENS))

    print("\nExecuting requests and capturing responses")
    write_collection(
        "Service 3 - Incident Management.postman_collection.json",
        "SIRMS - Service 3 - Incident Management (Karim Hajj Ali)",
        "Incident Management Service for the Security Incident Detection "
        "and Response Management System. Implemented by Karim Hajj Ali. "
        "Run the Authentication folder first to populate the tokens.",
        build_incidents())

    write_collection(
        "Service 7 - Vulnerability Management.postman_collection.json",
        "SIRMS - Service 7 - Vulnerability Management (Karim Hajj Ali)",
        "Vulnerability Management Service for the Security Incident "
        "Detection and Response Management System. Implemented by Karim "
        "Hajj Ali. Run the Authentication folder first to populate the "
        "tokens.",
        build_vulnerabilities())

    write_collection(
        "Service 8 - Notification Management.postman_collection.json",
        "SIRMS - Service 8 - Notification and Alert Management "
        "(Karim Hajj Ali)",
        "Notification and Alert Management Service for the Security "
        "Incident Detection and Response Management System. Implemented by "
        "Karim Hajj Ali. Run the Authentication folder first to populate "
        "the tokens.",
        build_notifications())

    write_environment()
    print("\nWritten to %s" % OUT_DIR)


if __name__ == "__main__":
    main()
