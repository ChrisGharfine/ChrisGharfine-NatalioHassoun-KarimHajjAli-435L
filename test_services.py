"""End-to-end checks for services 3, 7 and 8.

Walks every endpoint through Flask's test client, covering the happy path,
the permission rules, the validation rules and the lifecycle rules. Each
check prints a line so a failure is easy to locate.

This is a development aid, not a substitute for the Postman evidence the
sprint asks for -- it is here so a change can be verified in one command
before the screenshots are taken.

Run it with::

    python test_services.py

:author: Karim Hajj Ali
"""

import sys

from app import app
from database import create_db_tables
from seed import clear_tables, seed_assets, seed_users

#: Counters so the run ends with a summary.
_RESULTS = {"passed": 0, "failed": 0}

#: Tokens for each role, filled in by :func:`log_in_everyone`.
TOKENS = {}


def check(description, condition, detail=""):
    """Record one assertion and print the outcome.

    :param description: What was being checked.
    :type description: str
    :param condition: ``True`` if the check passed.
    :type condition: bool
    :param detail: Extra context printed when the check fails.
    :type detail: str
    :return: ``None``
    :rtype: NoneType
    """
    if condition:
        _RESULTS["passed"] += 1
        print("  PASS  %s" % description)
    else:
        _RESULTS["failed"] += 1
        print("  FAIL  %s" % description)
        if detail:
            print("        %s" % detail)


def auth_header(role):
    """Build an Authorization header for one of the seeded roles.

    :param role: ``admin``, ``analyst``, ``analyst2``, ``employee`` or
        ``auditor``.
    :type role: str
    :return: Headers ready to pass to the test client.
    :rtype: dict
    """
    return {"Authorization": "Bearer %s" % TOKENS[role]}


def section(title):
    """Print a heading between groups of checks.

    :param title: The heading text.
    :type title: str
    :return: ``None``
    :rtype: NoneType
    """
    print("\n" + title)
    print("-" * len(title))


# ---------------------------------------------------------------------------

def log_in_everyone(client):
    """Log in one account per role and stash the tokens.

    :param client: The Flask test client.
    :type client: flask.testing.FlaskClient
    :return: ``None``
    :rtype: NoneType
    """
    section("Authentication")

    accounts = {
        "admin": ("karim.admin", "Admin#2026"),
        "analyst": ("rana.analyst", "Analyst#2026"),
        "analyst2": ("omar.analyst", "Analyst#2026"),
        "employee": ("lina.employee", "Employee#2026"),
        "auditor": ("samir.auditor", "Auditor#2026"),
    }

    for key, (username, password) in accounts.items():
        response = client.post("/auth/login",
                               json={"username": username,
                                     "password": password})
        body = response.get_json()
        check("login as %s" % username,
              response.status_code == 200 and "token" in body,
              str(body))
        TOKENS[key] = body.get("token")

    bad = client.post("/auth/login",
                      json={"username": "karim.admin",
                            "password": "wrong-password"})
    check("login with a wrong password is rejected with 401",
          bad.status_code == 401, str(bad.get_json()))

    missing = client.post("/auth/login", json={"username": "karim.admin"})
    check("login without a password is rejected with 400",
          missing.status_code == 400, str(missing.get_json()))

    no_token = client.get("/incidents")
    check("a protected route without a token returns 401",
          no_token.status_code == 401, str(no_token.get_json()))

    bad_token = client.get("/incidents",
                           headers={"Authorization": "Bearer not-a-token"})
    check("a protected route with a bad token returns 401",
          bad_token.status_code == 401, str(bad_token.get_json()))


def test_incidents(client):
    """Exercise Service 3.

    :param client: The Flask test client.
    :type client: flask.testing.FlaskClient
    :return: The id of an incident left at ``Open`` for later checks.
    :rtype: int
    """
    section("Service 3 -- Incident Management")

    # --- create ---------------------------------------------------------
    critical = client.post("/incidents", headers=auth_header("admin"), json={
        "title": "Ransomware detected on domain controller",
        "description": "Endpoint protection flagged file encryption "
                       "activity on the primary domain controller.",
        "category": "Malware Infection",
        "severity": "Critical",
        "affected_asset": 1,
    })
    check("admin creates a Critical incident",
          critical.status_code == 201, str(critical.get_json()))
    critical_id = critical.get_json()["incident"]["incident_id"]

    medium = client.post("/incidents", headers=auth_header("employee"), json={
        "title": "Suspicious email requesting credentials",
        "description": "Received an email impersonating the IT helpdesk "
                       "and asking for my password.",
        "category": "Phishing Attack",
        "severity": "Medium",
        "affected_asset": 3,
    })
    check("employee reports a Medium incident",
          medium.status_code == 201, str(medium.get_json()))
    employee_incident_id = medium.get_json()["incident"]["incident_id"]

    low = client.post("/incidents", headers=auth_header("admin"), json={
        "title": "Repeated failed logins on branch router",
        "description": "Twelve failed SSH attempts from a single address "
                       "overnight.",
        "category": "Unauthorized Access",
        "severity": "Low",
        "affected_asset": 5,
    })
    check("admin creates a Low incident",
          low.status_code == 201, str(low.get_json()))

    check("a new incident starts at status Open",
          critical.get_json()["incident"]["status"] == "Open")

    # --- create: permissions and validation -----------------------------
    analyst_create = client.post("/incidents",
                                 headers=auth_header("analyst"), json={
                                     "title": "x", "description": "y",
                                     "category": "z", "severity": "Low"})
    check("analyst cannot create an incident (403)",
          analyst_create.status_code == 403, str(analyst_create.get_json()))

    bad_severity = client.post("/incidents", headers=auth_header("admin"),
                               json={"title": "Test",
                                     "description": "Test",
                                     "category": "Test",
                                     "severity": "Catastrophic"})
    check("an invalid severity is rejected with 400",
          bad_severity.status_code == 400, str(bad_severity.get_json()))

    missing_title = client.post("/incidents", headers=auth_header("admin"),
                                json={"description": "No title given",
                                      "category": "Test",
                                      "severity": "Low"})
    check("a missing title is rejected with 400",
          missing_title.status_code == 400, str(missing_title.get_json()))

    bad_asset = client.post("/incidents", headers=auth_header("admin"),
                            json={"title": "Test",
                                  "description": "Test",
                                  "category": "Test",
                                  "severity": "Low",
                                  "affected_asset": 9999})
    check("an unknown affected asset is rejected with 404",
          bad_asset.status_code == 404, str(bad_asset.get_json()))

    # --- retrieve all ---------------------------------------------------
    all_incidents = client.get("/incidents", headers=auth_header("admin"))
    check("admin retrieves all incidents",
          all_incidents.status_code == 200
          and all_incidents.get_json()["count"] == 3,
          str(all_incidents.get_json()))

    auditor_all = client.get("/incidents", headers=auth_header("auditor"))
    check("auditor retrieves all incidents",
          auditor_all.status_code == 200, str(auditor_all.get_json()))

    employee_all = client.get("/incidents", headers=auth_header("employee"))
    check("employee cannot list all incidents (403)",
          employee_all.status_code == 403, str(employee_all.get_json()))

    # --- retrieve one ---------------------------------------------------
    one = client.get("/incidents/%d" % critical_id,
                     headers=auth_header("admin"))
    check("admin retrieves a specific incident",
          one.status_code == 200, str(one.get_json()))

    missing = client.get("/incidents/9999", headers=auth_header("admin"))
    check("an unknown incident id returns 404",
          missing.status_code == 404, str(missing.get_json()))

    non_numeric = client.get("/incidents/abc", headers=auth_header("admin"))
    check("a non-numeric incident id returns JSON 404",
          non_numeric.status_code == 404
          and non_numeric.get_json()["status"] == "error",
          str(non_numeric.get_json()))

    own = client.get("/incidents/%d" % employee_incident_id,
                     headers=auth_header("employee"))
    check("employee can read the incident they reported",
          own.status_code == 200, str(own.get_json()))

    other = client.get("/incidents/%d" % critical_id,
                       headers=auth_header("employee"))
    check("employee cannot read somebody else's incident (403)",
          other.status_code == 403, str(other.get_json()))

    # --- assign ---------------------------------------------------------
    assign = client.put("/incidents/%d/assign" % critical_id,
                        headers=auth_header("admin"),
                        json={"analyst_id": 2})
    check("admin assigns the incident to an analyst",
          assign.status_code == 200
          and assign.get_json()["incident"]["assigned_analyst_id"] == 2,
          str(assign.get_json()))

    assign_non_analyst = client.put("/incidents/%d/assign" % critical_id,
                                    headers=auth_header("admin"),
                                    json={"analyst_id": 4})
    check("assigning to a non-analyst is rejected with 400",
          assign_non_analyst.status_code == 400,
          str(assign_non_analyst.get_json()))

    assign_unknown = client.put("/incidents/%d/assign" % critical_id,
                                headers=auth_header("admin"),
                                json={"analyst_id": 9999})
    check("assigning to an unknown user is rejected with 404",
          assign_unknown.status_code == 404,
          str(assign_unknown.get_json()))

    assign_by_analyst = client.put("/incidents/%d/assign" % critical_id,
                                   headers=auth_header("analyst"),
                                   json={"analyst_id": 3})
    check("analyst cannot assign incidents (403)",
          assign_by_analyst.status_code == 403,
          str(assign_by_analyst.get_json()))

    # --- status lifecycle ------------------------------------------------
    skip = client.put("/incidents/%d/status" % critical_id,
                      headers=auth_header("analyst"),
                      json={"status": "Closed"})
    check("jumping Open -> Closed is rejected with 400",
          skip.status_code == 400, str(skip.get_json()))

    for expected in ("Under Investigation", "Mitigated", "Resolved",
                     "Closed"):
        step = client.put("/incidents/%d/status" % critical_id,
                          headers=auth_header("analyst"),
                          json={"status": expected})
        check("status moves to '%s'" % expected,
              step.status_code == 200
              and step.get_json()["incident"]["status"] == expected,
              str(step.get_json()))

    resolved = client.get("/incidents/%d" % critical_id,
                          headers=auth_header("admin")).get_json()
    check("resolution date was stamped when the incident was resolved",
          resolved["incident"]["resolution_date"] is not None,
          str(resolved["incident"]))

    past_end = client.put("/incidents/%d/status" % critical_id,
                          headers=auth_header("analyst"),
                          json={"status": "Open"})
    check("a closed incident refuses further transitions (400)",
          past_end.status_code == 400, str(past_end.get_json()))

    bad_status = client.put("/incidents/%d/status" % employee_incident_id,
                            headers=auth_header("analyst"),
                            json={"status": "Pending"})
    check("an unknown status value is rejected with 400",
          bad_status.status_code == 400, str(bad_status.get_json()))

    employee_status = client.put(
        "/incidents/%d/status" % employee_incident_id,
        headers=auth_header("employee"),
        json={"status": "Under Investigation"})
    check("employee cannot change incident status (403)",
          employee_status.status_code == 403,
          str(employee_status.get_json()))

    # --- investigation notes ---------------------------------------------
    note1 = client.post("/incidents/%d/notes" % critical_id,
                        headers=auth_header("analyst"),
                        json={"note_content": "Isolated the host from the "
                                              "network and captured a memory "
                                              "image."})
    check("analyst adds an investigation note",
          note1.status_code == 201, str(note1.get_json()))

    note2 = client.post("/incidents/%d/notes" % critical_id,
                        headers=auth_header("analyst"),
                        json={"note_content": "Confirmed the encryption "
                                              "routine matches a known "
                                              "ransomware family."})
    check("a second note is added to the same incident",
          note2.status_code == 201, str(note2.get_json()))

    empty_note = client.post("/incidents/%d/notes" % critical_id,
                             headers=auth_header("analyst"),
                             json={"note_content": "   "})
    check("an empty note is rejected with 400",
          empty_note.status_code == 400, str(empty_note.get_json()))

    note_unknown = client.post("/incidents/9999/notes",
                               headers=auth_header("analyst"),
                               json={"note_content": "orphan"})
    check("a note on an unknown incident returns 404",
          note_unknown.status_code == 404, str(note_unknown.get_json()))

    with_notes = client.get("/incidents/%d" % critical_id,
                            headers=auth_header("admin")).get_json()
    check("the incident returns both of its notes, oldest first",
          len(with_notes["incident"]["investigation_notes"]) == 2,
          str(with_notes["incident"].get("investigation_notes")))

    employee_note = client.post("/incidents/%d/notes" % employee_incident_id,
                                headers=auth_header("employee"),
                                json={"note_content": "not allowed"})
    check("employee cannot add investigation notes (403)",
          employee_note.status_code == 403, str(employee_note.get_json()))

    return employee_incident_id


def test_vulnerabilities(client):
    """Exercise Service 7.

    :param client: The Flask test client.
    :type client: flask.testing.FlaskClient
    :return: ``None``
    :rtype: NoneType
    """
    section("Service 7 -- Vulnerability Management")

    critical = client.post("/vulnerabilities", headers=auth_header("admin"),
                           json={
                               "title": "Remote code execution in XZ Utils",
                               "description": "A backdoor in the upstream "
                                              "package allows unauthenticated "
                                              "remote code execution.",
                               "severity": "Critical",
                               "affected_asset": 2,
                               "cve_identifier": "CVE-2024-3094",
                               "cvss_score": 10.0,
                               "discovery_source": "Vendor advisory",
                           })
    check("admin registers a Critical vulnerability",
          critical.status_code == 201, str(critical.get_json()))
    critical_id = critical.get_json()["vulnerability"]["vulnerability_id"]

    medium = client.post("/vulnerabilities", headers=auth_header("admin"),
                         json={
                             "title": "Outdated TLS configuration",
                             "description": "The payroll application still "
                                            "negotiates TLS 1.0.",
                             "severity": "Medium",
                             "affected_asset": 6,
                             "cve_identifier": "CVE-2023-11111",
                             "cvss_score": 5.3,
                             "discovery_source": "Internal scan",
                         })
    check("admin registers a Medium vulnerability",
          medium.status_code == 201, str(medium.get_json()))
    medium_id = medium.get_json()["vulnerability"]["vulnerability_id"]

    high = client.post("/vulnerabilities", headers=auth_header("admin"),
                       json={
                           "title": "Unpatched SMB signing on file server",
                           "description": "SMB signing is not enforced, "
                                          "allowing relay attacks.",
                           "severity": "High",
                           "affected_asset": 2,
                           "cve_identifier": "CVE-2024-21345",
                           "cvss_score": 8.1,
                           "discovery_source": "Penetration test",
                       })
    check("admin registers a High vulnerability",
          high.status_code == 201, str(high.get_json()))

    check("a new vulnerability starts at status Open",
          critical.get_json()["vulnerability"]["status"] == "Open")

    # --- validation -------------------------------------------------------
    bad_cve = client.post("/vulnerabilities", headers=auth_header("admin"),
                          json={"title": "Test", "description": "Test",
                                "severity": "Low", "affected_asset": 1,
                                "cve_identifier": "CVE-BAD"})
    check("a malformed CVE identifier is rejected with 400",
          bad_cve.status_code == 400, str(bad_cve.get_json()))

    bad_score = client.post("/vulnerabilities", headers=auth_header("admin"),
                            json={"title": "Test", "description": "Test",
                                  "severity": "Low", "affected_asset": 1,
                                  "cvss_score": 44})
    check("a CVSS score above 10.0 is rejected with 400",
          bad_score.status_code == 400, str(bad_score.get_json()))

    no_asset = client.post("/vulnerabilities", headers=auth_header("admin"),
                           json={"title": "Test", "description": "Test",
                                 "severity": "Low"})
    check("a vulnerability without an affected asset is rejected with 400",
          no_asset.status_code == 400, str(no_asset.get_json()))

    unknown_asset = client.post("/vulnerabilities",
                                headers=auth_header("admin"),
                                json={"title": "Test", "description": "Test",
                                      "severity": "Low",
                                      "affected_asset": 9999})
    check("an unknown affected asset is rejected with 404",
          unknown_asset.status_code == 404, str(unknown_asset.get_json()))

    analyst_create = client.post("/vulnerabilities",
                                 headers=auth_header("analyst"),
                                 json={"title": "Test", "description": "Test",
                                       "severity": "Low",
                                       "affected_asset": 1})
    check("analyst cannot create a vulnerability (403)",
          analyst_create.status_code == 403, str(analyst_create.get_json()))

    # --- retrieve ---------------------------------------------------------
    all_vulns = client.get("/vulnerabilities", headers=auth_header("analyst"))
    check("analyst retrieves all vulnerabilities",
          all_vulns.status_code == 200
          and all_vulns.get_json()["count"] == 3,
          str(all_vulns.get_json()))

    employee_list = client.get("/vulnerabilities",
                               headers=auth_header("employee"))
    check("employee has no access to vulnerabilities (403)",
          employee_list.status_code == 403, str(employee_list.get_json()))

    one = client.get("/vulnerabilities/%d" % critical_id,
                     headers=auth_header("auditor"))
    check("auditor retrieves a specific vulnerability",
          one.status_code == 200, str(one.get_json()))

    missing = client.get("/vulnerabilities/9999",
                         headers=auth_header("admin"))
    check("an unknown vulnerability id returns 404",
          missing.status_code == 404, str(missing.get_json()))

    # --- update -----------------------------------------------------------
    update = client.put("/vulnerabilities/%d" % medium_id,
                        headers=auth_header("analyst"),
                        json={"description": "Confirmed on the staging "
                                             "instance as well.",
                              "cvss_score": 6.5})
    check("analyst updates description and CVSS score",
          update.status_code == 200
          and update.get_json()["vulnerability"]["cvss_score"] == 6.5,
          str(update.get_json()))

    bad_update = client.put("/vulnerabilities/%d" % medium_id,
                            headers=auth_header("analyst"),
                            json={"cvss_score": "not-a-number"})
    check("a non-numeric CVSS score on update is rejected with 400",
          bad_update.status_code == 400, str(bad_update.get_json()))

    empty_update = client.put("/vulnerabilities/%d" % medium_id,
                              headers=auth_header("analyst"), json={})
    check("an update with no recognised fields is rejected with 400",
          empty_update.status_code == 400, str(empty_update.get_json()))

    # --- lifecycle ---------------------------------------------------------
    skip = client.put("/vulnerabilities/%d" % critical_id,
                      headers=auth_header("analyst"),
                      json={"status": "Resolved"})
    check("jumping Open -> Resolved is rejected with 400",
          skip.status_code == 400, str(skip.get_json()))

    for expected in ("Under Investigation", "In Progress", "Resolved",
                     "Closed"):
        step = client.put("/vulnerabilities/%d" % critical_id,
                          headers=auth_header("analyst"),
                          json={"status": expected})
        check("vulnerability status moves to '%s'" % expected,
              step.status_code == 200
              and step.get_json()["vulnerability"]["status"] == expected,
              str(step.get_json()))

    closed = client.get("/vulnerabilities/%d" % critical_id,
                        headers=auth_header("admin")).get_json()
    check("resolution date was stamped on the vulnerability",
          closed["vulnerability"]["resolution_date"] is not None,
          str(closed["vulnerability"]))

    # --- search -------------------------------------------------------------
    by_severity = client.get("/vulnerabilities/search?severity=High",
                             headers=auth_header("analyst"))
    check("search by severity returns only High findings",
          by_severity.status_code == 200
          and by_severity.get_json()["count"] == 1,
          str(by_severity.get_json()))

    by_status = client.get("/vulnerabilities/search?status=Open",
                           headers=auth_header("analyst"))
    check("search by status returns only Open findings",
          by_status.status_code == 200
          and by_status.get_json()["count"] == 2,
          str(by_status.get_json()))

    by_cve = client.get("/vulnerabilities/search?cve=2024",
                        headers=auth_header("analyst"))
    check("partial CVE search matches every 2024 CVE",
          by_cve.status_code == 200 and by_cve.get_json()["count"] == 2,
          str(by_cve.get_json()))

    by_asset = client.get("/vulnerabilities/search?asset_id=2",
                          headers=auth_header("analyst"))
    check("search by asset returns that asset's findings",
          by_asset.status_code == 200 and by_asset.get_json()["count"] == 2,
          str(by_asset.get_json()))

    combined = client.get(
        "/vulnerabilities/search?severity=High&status=Open",
        headers=auth_header("analyst"))
    check("two filters combine with AND",
          combined.status_code == 200 and combined.get_json()["count"] == 1,
          str(combined.get_json()))

    no_match = client.get("/vulnerabilities/search?severity=Low",
                          headers=auth_header("analyst"))
    check("a search with no matches returns an empty list, not an error",
          no_match.status_code == 200 and no_match.get_json()["count"] == 0,
          str(no_match.get_json()))

    bad_filter = client.get("/vulnerabilities/search?severity=Extreme",
                            headers=auth_header("analyst"))
    check("an invalid search filter is rejected with 400",
          bad_filter.status_code == 400, str(bad_filter.get_json()))

    # --- delete --------------------------------------------------------------
    analyst_delete = client.delete("/vulnerabilities/%d" % medium_id,
                                   headers=auth_header("analyst"))
    check("analyst cannot delete a vulnerability (403)",
          analyst_delete.status_code == 403, str(analyst_delete.get_json()))

    admin_delete = client.delete("/vulnerabilities/%d" % medium_id,
                                 headers=auth_header("admin"))
    check("admin deletes a vulnerability",
          admin_delete.status_code == 200, str(admin_delete.get_json()))

    gone = client.get("/vulnerabilities/%d" % medium_id,
                      headers=auth_header("admin"))
    check("the deleted vulnerability is really gone (404)",
          gone.status_code == 404, str(gone.get_json()))

    delete_missing = client.delete("/vulnerabilities/9999",
                                   headers=auth_header("admin"))
    check("deleting an unknown vulnerability returns 404",
          delete_missing.status_code == 404,
          str(delete_missing.get_json()))


def test_notifications(client):
    """Exercise Service 8.

    :param client: The Flask test client.
    :type client: flask.testing.FlaskClient
    :return: ``None``
    :rtype: NoneType
    """
    section("Service 8 -- Notification and Alert Management")

    # The analyst should already have an "Incident Assignment" notification
    # from the assignment in the incident tests, and the finance manager
    # (user 4) should have vulnerability alerts for their assets.
    analyst_inbox = client.get("/notifications/user/2",
                               headers=auth_header("analyst"))
    body = analyst_inbox.get_json()
    check("assigning an incident generated a notification for the analyst",
          analyst_inbox.status_code == 200 and body["count"] >= 1
          and any(n["notification_type"] == "Incident Assignment"
                  for n in body["notifications"]),
          str(body))

    owner_inbox = client.get("/notifications/user/4",
                             headers=auth_header("admin")).get_json()
    check("a Critical vulnerability alerted the asset owner",
          any(n["notification_type"] == "Vulnerability Alert"
              for n in owner_inbox["notifications"]),
          str(owner_inbox))

    # --- create -----------------------------------------------------------
    created = client.post("/notifications", headers=auth_header("admin"),
                          json={
                              "user_id": 3,
                              "title": "Quarterly access review due",
                              "message": "Please review the access rights "
                                         "for the systems you administer.",
                              "notification_type": "System Notification",
                              "severity": "Low",
                          })
    check("admin creates a notification",
          created.status_code == 201, str(created.get_json()))
    created_id = created.get_json()["notification"]["notification_id"]

    check("a new notification starts Unread",
          created.get_json()["notification"]["status"] == "Unread")

    bad_type = client.post("/notifications", headers=auth_header("admin"),
                           json={"user_id": 3, "title": "T", "message": "M",
                                 "notification_type": "Carrier Pigeon",
                                 "severity": "Low"})
    check("an invalid notification type is rejected with 400",
          bad_type.status_code == 400, str(bad_type.get_json()))

    unknown_user = client.post("/notifications", headers=auth_header("admin"),
                               json={"user_id": 9999, "title": "T",
                                     "message": "M",
                                     "notification_type": "Security Alert",
                                     "severity": "Low"})
    check("a notification for an unknown user is rejected with 404",
          unknown_user.status_code == 404, str(unknown_user.get_json()))

    analyst_create = client.post("/notifications",
                                 headers=auth_header("analyst"),
                                 json={"user_id": 3, "title": "T",
                                       "message": "M",
                                       "notification_type": "Security Alert",
                                       "severity": "Low"})
    check("analyst cannot create notifications (403)",
          analyst_create.status_code == 403, str(analyst_create.get_json()))

    # --- retrieve -----------------------------------------------------------
    empty = client.get("/notifications/user/5", headers=auth_header("admin"))
    check("a user with no notifications gets 200 and an empty list",
          empty.status_code == 200 and empty.get_json()["count"] == 0,
          str(empty.get_json()))

    unknown_inbox = client.get("/notifications/user/9999",
                               headers=auth_header("admin"))
    check("an unknown user's inbox returns 404",
          unknown_inbox.status_code == 404, str(unknown_inbox.get_json()))

    own = client.get("/notifications/user/2", headers=auth_header("analyst"))
    check("analyst can read their own inbox",
          own.status_code == 200, str(own.get_json()))

    someone_else = client.get("/notifications/user/4",
                              headers=auth_header("analyst"))
    check("analyst cannot read another user's inbox (403)",
          someone_else.status_code == 403, str(someone_else.get_json()))

    employee_other = client.get("/notifications/user/2",
                                headers=auth_header("employee"))
    check("employee cannot read another user's inbox (403)",
          employee_other.status_code == 403, str(employee_other.get_json()))

    auditor_any = client.get("/notifications/user/2",
                             headers=auth_header("auditor"))
    check("auditor may read any inbox",
          auditor_any.status_code == 200, str(auditor_any.get_json()))

    one = client.get("/notifications/%d" % created_id,
                     headers=auth_header("admin"))
    check("admin retrieves a specific notification",
          one.status_code == 200, str(one.get_json()))

    missing = client.get("/notifications/9999", headers=auth_header("admin"))
    check("an unknown notification id returns 404",
          missing.status_code == 404, str(missing.get_json()))

    not_mine = client.get("/notifications/%d" % created_id,
                          headers=auth_header("employee"))
    check("employee cannot read a notification addressed to someone else",
          not_mine.status_code == 403, str(not_mine.get_json()))

    # --- mark as read -------------------------------------------------------
    before = client.get("/notifications/%d" % created_id,
                        headers=auth_header("admin")).get_json()
    check("the notification is Unread with no read date before marking",
          before["notification"]["status"] == "Unread"
          and before["notification"]["read_date"] is None,
          str(before["notification"]))

    mark = client.put("/notifications/%d/read" % created_id,
                      headers=auth_header("analyst2"))
    check("the recipient marks their notification as read",
          mark.status_code == 200
          and mark.get_json()["notification"]["status"] == "Read"
          and mark.get_json()["notification"]["read_date"] is not None,
          str(mark.get_json()))

    first_read_date = mark.get_json()["notification"]["read_date"]
    again = client.put("/notifications/%d/read" % created_id,
                       headers=auth_header("analyst2"))
    check("marking an already-read notification keeps the original date",
          again.status_code == 200
          and again.get_json()["notification"]["read_date"]
          == first_read_date,
          str(again.get_json()))

    mark_other = client.put("/notifications/%d/read" % created_id,
                            headers=auth_header("employee"))
    check("employee cannot mark someone else's notification read (403)",
          mark_other.status_code == 403, str(mark_other.get_json()))

    auditor_mark = client.put("/notifications/%d/read" % created_id,
                              headers=auth_header("auditor"))
    check("auditor is read-only and cannot mark notifications (403)",
          auditor_mark.status_code == 403, str(auditor_mark.get_json()))

    # --- search --------------------------------------------------------------
    by_status = client.get("/notifications/search?status=Unread",
                           headers=auth_header("admin"))
    check("search by status returns only unread notifications",
          by_status.status_code == 200
          and all(n["status"] == "Unread"
                  for n in by_status.get_json()["notifications"]),
          str(by_status.get_json()))

    by_type = client.get(
        "/notifications/search?notification_type=Incident%20Assignment",
        headers=auth_header("admin"))
    check("search by type returns only incident assignments",
          by_type.status_code == 200 and by_type.get_json()["count"] >= 1,
          str(by_type.get_json()))

    by_severity = client.get("/notifications/search?severity=Critical",
                             headers=auth_header("admin"))
    check("search by severity works",
          by_severity.status_code == 200, str(by_severity.get_json()))

    scoped = client.get("/notifications/search?user_id=4",
                        headers=auth_header("analyst"))
    check("an analyst's search is silently scoped to their own inbox",
          scoped.status_code == 200
          and scoped.get_json()["filters_applied"]["user_id"] == 2,
          str(scoped.get_json()))

    bad_filter = client.get("/notifications/search?status=Archived",
                            headers=auth_header("admin"))
    check("an invalid search filter is rejected with 400",
          bad_filter.status_code == 400, str(bad_filter.get_json()))

    employee_search = client.get("/notifications/search",
                                 headers=auth_header("employee"))
    check("employee has no search endpoint access (403)",
          employee_search.status_code == 403,
          str(employee_search.get_json()))

    # --- delete ---------------------------------------------------------------
    analyst_delete = client.delete("/notifications/%d" % created_id,
                                   headers=auth_header("analyst"))
    check("analyst cannot delete a notification (403)",
          analyst_delete.status_code == 403, str(analyst_delete.get_json()))

    admin_delete = client.delete("/notifications/%d" % created_id,
                                 headers=auth_header("admin"))
    check("admin deletes a notification",
          admin_delete.status_code == 200, str(admin_delete.get_json()))

    gone = client.get("/notifications/%d" % created_id,
                      headers=auth_header("admin"))
    check("the deleted notification is really gone (404)",
          gone.status_code == 404, str(gone.get_json()))


def test_audit_trail(client):
    """Confirm the services wrote to the audit log as they went.

    :param client: The Flask test client.
    :type client: flask.testing.FlaskClient
    :return: ``None``
    :rtype: NoneType
    """
    section("Audit trail (written by services 3, 7 and 8)")

    from database import connect_to_db

    conn = connect_to_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT action_performed, COUNT(*) AS n FROM logs "
                    "GROUP BY action_performed ORDER BY n DESC")
        rows = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

    actions = {row["action_performed"]: row["n"] for row in rows}

    for action in ("Incident created", "Incident assigned",
                   "Incident status updated", "Investigation note added",
                   "Vulnerability created", "Vulnerability updated",
                   "Vulnerability deleted", "Notification created",
                   "Notification deleted", "Unauthorized access attempt"):
        check("audit log contains '%s'" % action,
              actions.get(action, 0) > 0, str(actions))

    print("\n  Audit log summary:")
    for row in rows:
        print("    %-32s %d" % (row["action_performed"], row["n"]))


def main():
    """Reset the database, run every check and report the totals.

    :return: Process exit code -- ``0`` if everything passed.
    :rtype: int
    """
    print("Resetting the database to a known state")
    # create_db_tables() first, so this works on a fresh checkout where
    # database.db does not exist yet and there is nothing to clear.
    create_db_tables()
    clear_tables()
    seed_users()
    seed_assets()

    client = app.test_client()

    log_in_everyone(client)
    test_incidents(client)
    test_vulnerabilities(client)
    test_notifications(client)
    test_audit_trail(client)

    print("\n" + "=" * 62)
    print("passed: %d    failed: %d"
          % (_RESULTS["passed"], _RESULTS["failed"]))
    print("=" * 62)
    return 1 if _RESULTS["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
