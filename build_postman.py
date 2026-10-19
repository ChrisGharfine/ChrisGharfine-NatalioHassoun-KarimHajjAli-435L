"""Generate the Postman collections for services 3, 7 and 8.

Rewritten for team-integration-v1.0.0. Differences from the Sprint I
version:

* Three separate base URLs, one per service, on ports 8003, 8007 and 8008.
* No login request. Users is Natalio's service and issues the token; the
  collection reads it from an environment variable you paste in.
* A collection for the internal delivery endpoint, authenticated by
  service name and key rather than a user token.
* The environment file ships **empty** token and key values. Section 9
  forbids committing credentials.

Saved examples are captured by firing each request at running services.
If a service is not reachable the example records that fact rather than a
fabricated response -- an unreachable dependency is pending integration,
not something to invent.

Start the three services, then run::

    python build_postman.py

:author: Karim Hajj Ali
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid

import config

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "postman")

#: Which variable holds each service's base URL.
BASE_VARIABLE = {
    config.SERVICE_INCIDENTS: "incidents_url",
    config.SERVICE_VULNERABILITIES: "vulnerabilities_url",
    config.SERVICE_NOTIFICATIONS: "notifications_url",
}

BASE_URL = {
    config.SERVICE_INCIDENTS: "http://127.0.0.1:8003",
    config.SERVICE_VULNERABILITIES: "http://127.0.0.1:8007",
    config.SERVICE_NOTIFICATIONS: "http://127.0.0.1:8008",
}

#: A real token, supplied locally, used only to capture examples. Never
#: written into the collection or the environment file.
ADMIN_TOKEN = os.environ.get("POSTMAN_CAPTURE_ADMIN_TOKEN", "")
ANALYST_TOKEN = os.environ.get("POSTMAN_CAPTURE_ANALYST_TOKEN", "")


def call(service, method, path, body=None, token=None, service_headers=None):
    """Send a request to a running service and return the outcome.

    :param service: Which service to call.
    :type service: str
    :param method: HTTP method.
    :type method: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param body: JSON body, defaults to None.
    :type body: dict, optional
    :param token: Bearer token, defaults to None.
    :type token: str, optional
    :param service_headers: Service name/key headers, defaults to None.
    :type service_headers: dict, optional
    :return: ``(status, reason, text)``; status is ``None`` when the
        service could not be reached.
    :rtype: tuple
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(BASE_URL[service] + path, data=data,
                                     method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer %s" % token)
    for key, value in (service_headers or {}).items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return (response.status, response.reason,
                    response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, error.reason, error.read().decode("utf-8")
    except Exception as failure:
        return None, "unreachable", str(failure)


def build_url(service, path):
    """Turn a path into Postman's URL object.

    :param service: Which service the path belongs to.
    :type service: str
    :param path: Path beginning with ``/``, possibly with a query string.
    :type path: str
    :return: The URL object.
    :rtype: dict
    """
    variable = "{{%s}}" % BASE_VARIABLE[service]
    path_part, _, query_part = path.partition("?")
    url = {
        "raw": variable + path,
        "host": [variable],
        "path": [segment for segment in path_part.split("/") if segment],
    }
    if query_part:
        url["query"] = [
            {"key": pair.partition("=")[0],
             "value": urllib.parse.unquote(pair.partition("=")[2])}
            for pair in query_part.split("&")]
    return url


def build_request(service, method, path, body=None, token_variable=None,
                  service_name=None, description="", idempotency=False):
    """Build the request half of a Postman item.

    :param service: Which service it targets.
    :type service: str
    :param method: HTTP method.
    :type method: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param body: JSON body, defaults to None.
    :type body: dict, optional
    :param token_variable: Environment variable holding a user token,
        defaults to None.
    :type token_variable: str, optional
    :param service_name: Service identity to present instead of a user
        token, defaults to None.
    :type service_name: str, optional
    :param description: Shown in Postman.
    :type description: str
    :param idempotency: Add an ``Idempotency-Key`` header, defaults to False.
    :type idempotency: bool, optional
    :return: The request object.
    :rtype: dict
    """
    headers = []
    if body is not None:
        headers.append({"key": "Content-Type", "value": "application/json"})
    if token_variable:
        headers.append({"key": "Authorization",
                        "value": "Bearer {{%s}}" % token_variable})
    if service_name:
        headers.append({"key": "X-Service-Name", "value": service_name})
        headers.append({"key": "X-Service-Key",
                        "value": "{{%s_service_key}}" % service_name})
    if idempotency:
        headers.append({"key": "Idempotency-Key", "value": "{{$guid}}"})

    request = {"method": method, "header": headers,
               "url": build_url(service, path), "description": description}
    if body is not None:
        request["body"] = {"mode": "raw",
                           "raw": json.dumps(body, indent=2),
                           "options": {"raw": {"language": "json"}}}
    return request


def build_example(name, request, status, reason, text):
    """Build one saved example from a captured response.

    :param name: Example name.
    :type name: str
    :param request: The request it belongs to.
    :type request: dict
    :param status: HTTP status, or ``None`` when unreachable.
    :type status: int or NoneType
    :param reason: Reason phrase.
    :type reason: str
    :param text: Raw response body.
    :type text: str
    :return: The saved example.
    :rtype: dict
    """
    if status is None:
        pretty = json.dumps({
            "_note": "The service was not running when this collection was "
                     "generated, so no response was captured. Start the "
                     "service and regenerate to record a real example.",
        }, indent=2)
        label = "not captured"
        code = 0
    else:
        try:
            pretty = json.dumps(json.loads(text), indent=2)
        except ValueError:
            pretty = text
        label = name
        code = status

    return {"name": label, "originalRequest": request,
            "status": reason, "code": code,
            "_postman_previewlanguage": "json",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "cookie": [], "body": pretty}


def make_item(name, service, method, path, description, token_variable=None,
              service_name=None, body=None, idempotency=False,
              capture_token=None, capture_service_headers=None):
    """Build a Postman item, capturing a real response as its example.

    :param name: Request name.
    :type name: str
    :param service: Target service.
    :type service: str
    :param method: HTTP method.
    :type method: str
    :param path: Path beginning with ``/``.
    :type path: str
    :param description: What it does and who may call it.
    :type description: str
    :param token_variable: Variable holding the user token, defaults to None.
    :type token_variable: str, optional
    :param service_name: Service identity, defaults to None.
    :type service_name: str, optional
    :param body: JSON body, defaults to None.
    :type body: dict, optional
    :param idempotency: Add an idempotency header, defaults to False.
    :type idempotency: bool, optional
    :param capture_token: Real token used only while capturing.
    :type capture_token: str, optional
    :param capture_service_headers: Real service headers used only while
        capturing.
    :type capture_service_headers: dict, optional
    :return: The finished item.
    :rtype: dict
    """
    request = build_request(service, method, path, body, token_variable,
                            service_name, description, idempotency)

    headers = dict(capture_service_headers or {})
    if idempotency:
        headers["Idempotency-Key"] = str(uuid.uuid4())

    status, reason, text = call(service, method, path, body, capture_token,
                                headers)
    example = build_example("%s %s" % (status, reason) if status else "",
                            request, status, reason, text)
    return {"name": name, "request": request, "response": [example]}


def write_collection(filename, name, description, items):
    """Write one collection file.

    :param filename: File name inside ``postman/``.
    :type filename: str
    :param name: Collection name.
    :type name: str
    :param description: Collection description.
    :type description: str
    :param items: Folders and requests.
    :type items: list
    :return: ``None``
    :rtype: NoneType
    """
    collection = {
        "info": {"_postman_id": str(uuid.uuid4()), "name": name,
                 "description": description + CAPTURE_NOTE,
                 "schema": "https://schema.getpostman.com/json/collection/"
                           "v2.1.0/collection.json"},
        "item": items,
    }
    with open(os.path.join(OUT_DIR, filename), "w", encoding="utf-8") as out:
        json.dump(collection, out, indent=2)

    captured = sum(1 for entry in items
                   for example in entry.get("response", [])
                   if example["code"])
    print("  %-56s %2d requests, %2d captured"
          % (filename, len(items), captured))


def write_environment():
    """Write the environment file, with every secret left blank.

    :return: ``None``
    :rtype: NoneType
    """
    values = [
        {"key": "incidents_url", "value": BASE_URL[config.SERVICE_INCIDENTS],
         "enabled": True, "type": "default"},
        {"key": "vulnerabilities_url",
         "value": BASE_URL[config.SERVICE_VULNERABILITIES],
         "enabled": True, "type": "default"},
        {"key": "notifications_url",
         "value": BASE_URL[config.SERVICE_NOTIFICATIONS],
         "enabled": True, "type": "default"},
        {"key": "users_url", "value": config.USERS_BASE_URL,
         "enabled": True, "type": "default"},
    ]
    # Blank on purpose. Section 9: no credentials in committed environments.
    for key in ("admin_token", "analyst_token", "employee_token",
                "auditor_token", "incidents_service_key",
                "vulnerabilities_service_key"):
        values.append({"key": key, "value": "", "enabled": True,
                       "type": "secret"})

    environment = {"id": str(uuid.uuid4()), "name": "SIRMS v1 Local",
                   "values": values,
                   "_postman_variable_scope": "environment"}
    path = os.path.join(OUT_DIR, "SIRMS v1 Local.postman_environment.json")
    with open(path, "w", encoding="utf-8") as out:
        json.dump(environment, out, indent=2)
    print("  %-56s secrets left blank" % os.path.basename(path))


#: Stamped into every collection description so nobody mistakes an example
#: captured against a test double for evidence of live integration.
CAPTURE_NOTE = os.environ.get("POSTMAN_CAPTURE_NOTE", "") or """
How the saved examples were captured
------------------------------------
Not stated. Regenerate with POSTMAN_CAPTURE_NOTE set to record whether the
upstream Users, Assets and Logs services were the real ones or test
doubles. Examples captured against doubles are not evidence of live team
integration.
"""

HOW_TO_AUTHENTICATE = """
Authentication under team-integration-v1.0.0
--------------------------------------------
There is no login request in these collections. Natalio's Users service is
the only token issuer:

    POST {{users_url}}/users/login
    {"identifier": "your.username", "password": "..."}

Take `data.access_token` from his response and paste it into the
`admin_token` / `analyst_token` environment variable. Tokens last 1800
seconds. Never commit a filled-in environment.

The internal collection uses service credentials instead, not a user
token: `X-Service-Name` plus `X-Service-Key`, with a fresh
`Idempotency-Key` per delivery (Postman's {{$guid}} generates one).
"""


def incidents_items():
    """Build the Service 3 requests.

    :return: Items.
    :rtype: list
    """
    s = config.SERVICE_INCIDENTS
    return [
        make_item("1. Create Incident", s, "POST", "/incidents",
                  "Report an incident. Administrator or Regular Employee. "
                  "An employee is always recorded as their own reporter.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN,
                  body={"title": "Ransomware detected on domain controller",
                        "description": "Encryption activity flagged on the "
                                       "domain controller.",
                        "category": "Malware Infection",
                        "severity": "Critical", "affected_asset": 1}),
        make_item("2. Retrieve All Incidents", s, "GET", "/incidents",
                  "Complete list. Administrator or Auditor. This is the "
                  "shape Chris's Reports consumes: body.incidents with a "
                  "success status and count.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("3. Retrieve Specific Incident", s, "GET", "/incidents/1",
                  "One incident with its investigation notes. An employee "
                  "may only read an incident they reported.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("4. Assign Incident to Analyst", s, "PUT",
                  "/incidents/1/assign",
                  "Administrator only. The target's role is checked against "
                  "Users over HTTP, so a demoted account is refused. Queues "
                  "an Incident Assignment notification.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN,
                  body={"analyst_id": 2}),
        make_item("5. Update Incident Status", s, "PUT",
                  "/incidents/1/status",
                  "One step along Open -> Under Investigation -> Mitigated "
                  "-> Resolved -> Closed. Skipping a step is refused with "
                  "400 naming the only allowed next status.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN,
                  body={"status": "Under Investigation"}),
        make_item("6. Add Investigation Note", s, "POST",
                  "/incidents/1/notes",
                  "Administrator or Analyst. Returned as part of "
                  "GET /incidents/{id}.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN,
                  body={"note_content": "Isolated the host and captured a "
                                        "memory image."}),
        make_item("Health", s, "GET", "/health",
                  "Readiness of this service, including whether its own "
                  "tables can be queried."),
    ]


def vulnerabilities_items():
    """Build the Service 7 requests.

    :return: Items.
    :rtype: list
    """
    s = config.SERVICE_VULNERABILITIES
    return [
        make_item("1. Add New Vulnerability", s, "POST", "/vulnerabilities",
                  "Administrator only. The asset is resolved through "
                  "Chris's internal lookup, which also supplies the owner "
                  "notified for High and Critical findings.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN,
                  body={"title": "Remote code execution in XZ Utils",
                        "description": "A backdoor allows unauthenticated "
                                       "remote code execution.",
                        "severity": "Critical", "affected_asset": 2,
                        "cve_identifier": "CVE-2024-3094",
                        "cvss_score": 10.0,
                        "discovery_source": "Vendor advisory"}),
        make_item("2. Retrieve All Vulnerabilities", s, "GET",
                  "/vulnerabilities",
                  "Complete list. Administrator, Analyst or Auditor. The "
                  "shape Reports consumes: body.vulnerabilities with a "
                  "success status and count.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN),
        make_item("3. Retrieve Specific Vulnerability", s, "GET",
                  "/vulnerabilities/1", "One vulnerability by id.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN),
        make_item("4. Update Vulnerability", s, "PUT",
                  "/vulnerabilities/1",
                  "Administrator or Analyst. Status changes follow "
                  "Open -> Under Investigation -> In Progress -> Resolved "
                  "-> Closed, one step at a time.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN,
                  body={"description": "Confirmed on staging as well.",
                        "cvss_score": 9.8}),
        make_item("5. Search Vulnerabilities", s, "GET",
                  "/vulnerabilities/search?severity=Critical&status=Open",
                  "Filters combine with AND. The CVE filter matches "
                  "partially, so ?cve=2024 returns every CVE from 2024.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN),
        make_item("6. Delete Vulnerability", s, "DELETE",
                  "/vulnerabilities/9999",
                  "Administrator only. Pointed at a non-existent id so "
                  "regenerating this collection does not destroy data.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("Health", s, "GET", "/health",
                  "Readiness of this service."),
    ]


def notifications_items():
    """Build the Service 8 requests, public and internal.

    :return: Items.
    :rtype: list
    """
    s = config.SERVICE_NOTIFICATIONS
    return [
        make_item("1. Create Notification", s, "POST", "/notifications",
                  "Administrator only. Notifications are also generated "
                  "automatically by Incidents and Vulnerabilities through "
                  "the internal endpoint below.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN,
                  body={"user_id": 2, "title": "Quarterly access review",
                        "message": "Please review the access rights for "
                                   "the systems you administer.",
                        "notification_type": "System Notification",
                        "severity": "Low"}),
        make_item("2. Retrieve User Notifications", s, "GET",
                  "/notifications/user/2",
                  "Analysts and employees may only read their own inbox; "
                  "administrators and auditors may read any.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("3. Retrieve Specific Notification", s, "GET",
                  "/notifications/1", "One notification by id.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("4. Mark Notification as Read", s, "PUT",
                  "/notifications/1/read",
                  "Marks read and stamps read_date. Marking an "
                  "already-read notification keeps the original date. "
                  "Auditors are read-only.",
                  token_variable="analyst_token",
                  capture_token=ANALYST_TOKEN),
        make_item("5. Search Notifications", s, "GET",
                  "/notifications/search?status=Unread",
                  "By user, type, severity and status. An analyst's search "
                  "is silently scoped to their own inbox.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("6. Delete Notification", s, "DELETE",
                  "/notifications/9999",
                  "Administrator only. Pointed at a non-existent id so "
                  "regenerating does not destroy data. The delivery "
                  "receipt survives a real deletion.",
                  token_variable="admin_token", capture_token=ADMIN_TOKEN),
        make_item("7. Internal delivery (service credential)", s, "POST",
                  "/internal/notifications",
                  "Section 7. Called by another service, not by a user. "
                  "Authenticated by X-Service-Name and X-Service-Key, with "
                  "a fresh Idempotency-Key per alert. An identical retry "
                  "returns 200 with duplicate=true and creates nothing; a "
                  "changed payload under the same key returns 409 "
                  "IDEMPOTENCY_CONFLICT.",
                  service_name="incidents", idempotency=True,
                  capture_service_headers={
                      "X-Service-Name": "incidents",
                      "X-Service-Key": os.environ.get(
                          "KARIM_INCIDENTS_SERVICE_KEY", "")},
                  body={"user_id": 2, "actor_user_id": 1,
                        "title": "Incident assigned",
                        "message": "Incident 1 was assigned to you.",
                        "notification_type": "Incident Assignment",
                        "severity_level": "High"}),
        make_item("Health", s, "GET", "/health",
                  "Readiness of this service."),
    ]


def main():
    """Generate all three collections and the environment.

    :return: ``None``
    :rtype: NoneType
    """
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)

    if not ADMIN_TOKEN:
        print("No POSTMAN_CAPTURE_ADMIN_TOKEN set. Requests will still be")
        print("written, but examples will record that nothing was captured")
        print("rather than inventing a response.\n")

    print("Generating collections")
    write_collection(
        "Service 3 - Incident Management.postman_collection.json",
        "SIRMS v1 - Service 3 - Incident Management (Karim Hajj Ali)",
        "Incident Management under team-integration-v1.0.0, on port 8003."
        + HOW_TO_AUTHENTICATE,
        incidents_items())

    write_collection(
        "Service 7 - Vulnerability Management.postman_collection.json",
        "SIRMS v1 - Service 7 - Vulnerability Management (Karim Hajj Ali)",
        "Vulnerability Management under team-integration-v1.0.0, on port "
        "8007." + HOW_TO_AUTHENTICATE,
        vulnerabilities_items())

    write_collection(
        "Service 8 - Notification Management.postman_collection.json",
        "SIRMS v1 - Service 8 - Notification and Alert Management "
        "(Karim Hajj Ali)",
        "Notification and Alert Management under team-integration-v1.0.0, "
        "on port 8008, including the internal delivery endpoint."
        + HOW_TO_AUTHENTICATE,
        notifications_items())

    write_environment()
    print("\nWritten to %s" % OUT_DIR)


if __name__ == "__main__":
    main()
