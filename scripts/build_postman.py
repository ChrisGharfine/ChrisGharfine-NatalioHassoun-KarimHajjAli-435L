"""Build a runnable collection with real requests and assertions, never saved fake responses."""

import json
from pathlib import Path


def main():
    folders = []

    def folder(name):
        items = []
        folders.append({"name": name, "item": items})
        return items

    def add(items, name, service, method, path, expected=200, body=None, token="admin_token", save=(), description="", extra_headers=()):
        request = {"method": method, "header": [{"key": "Content-Type", "value": "application/json"}, *extra_headers],
                   "url": "{{" + service + "_url}}{{prefix}}" + path,
                   "description": description + "\nCapture the actual request, response and status. Owner: Natalio Hassoun."}
        request["auth"] = ({"type": "bearer", "bearer": [{"key": "token", "value": "{{" + token + "}}", "type": "string"}]}
                           if token else {"type": "noauth"})
        if body is not None:
            request["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2), "options": {"raw": {"language": "json"}}}
        script = [f"pm.test('HTTP {expected}', () => pm.response.to.have.status({expected}));",
                  "pm.test('JSON response', () => pm.response.to.be.json);"]
        if save:
            script += ["if (pm.response.code < 300) { const d = pm.response.json().data;"]
            script += [f"pm.collectionVariables.set('{variable}', d.{field});" for variable, field in save]
            script += ["}"]
        item = {"name": name, "request": request, "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": script}}]}
        items.append(item)
        return item

    setup = folder("01 - Accounts and authentication")
    first = add(setup, "Administrator login", "users", "POST", "/users/login", body={"identifier": "{{admin_username}}", "password": "{{admin_password}}"},
                token=None, save=(("admin_token", "access_token"), ("admin_id", "user.id")), description="Authenticate the administrator created with create-admin.")
    first["event"].insert(0, {"listen": "prerequest", "script": {"type": "text/javascript", "exec": ["pm.collectionVariables.set('run_suffix', Date.now().toString());"]}})
    for service in ("users", "logs", "playbooks"):
        add(setup, service.title() + " health", service, "GET", "/health", token=None,
            description="Confirm the service and database are reachable.")
    for label, role in (("employee", "regular_employee"), ("analyst", "security_analyst"), ("auditor", "auditor")):
        payload = {"full_name": "Postman " + label, "username": "pm." + label + ".{{run_suffix}}",
                   "email": "pm." + label + ".{{run_suffix}}@example.edu", "password": "{{demo_password}}",
                   "department": "Security", "role": role}
        add(setup, "Register " + label, "users", "POST", "/users/register", 201, payload,
            token=None if label == "employee" else "admin_token", save=((label + "_id", "id"),),
            description="Create an account. Elevated roles require administrator authentication.")
        add(setup, "Login " + label, "users", "POST", "/users/login", body={"identifier": payload["username"], "password": "{{demo_password}}"},
            token=None, save=((label + "_token", "access_token"),), description="Obtain this role's token for permission checks.")
    add(setup, "Incorrect password", "users", "POST", "/users/login", 401,
        {"identifier": "{{admin_username}}", "password": "Intentionally-Wrong-435!"}, token=None, description="Failed authentication must be logged.")
    add(setup, "Duplicate username", "users", "POST", "/users/register", 409,
        {"full_name": "Duplicate", "username": "pm.employee.{{run_suffix}}", "email": "different.{{run_suffix}}@example.edu",
         "password": "{{demo_password}}", "department": "IT", "role": "regular_employee"}, token=None)
    add(setup, "Invalid email", "users", "POST", "/users/register", 400,
        {"full_name": "Invalid", "username": "pm.invalid.{{run_suffix}}", "email": "bad", "password": "{{demo_password}}",
         "department": "IT", "role": "regular_employee"}, token=None)
    add(setup, "Missing registration fields", "users", "POST", "/users/register", 400, {"full_name": "Missing"}, token=None)
    add(setup, "Public administrator escalation rejected", "users", "POST", "/users/register", 403,
        {"full_name": "Escalation", "username": "pm.escalate.{{run_suffix}}", "email": "escalate.{{run_suffix}}@example.edu",
         "password": "{{demo_password}}", "department": "IT", "role": "security_administrator"}, token=None)

    users = folder("02 - User profiles and live permissions")
    add(users, "List users - administrator", "users", "GET", "/users")
    add(users, "List users - auditor", "users", "GET", "/users", token="auditor_token")
    add(users, "List users - analyst denied", "users", "GET", "/users", 403, token="analyst_token")
    add(users, "List users - missing token", "users", "GET", "/users", 401, token=None)
    add(users, "Retrieve own profile", "users", "GET", "/users/pm.employee.{{run_suffix}}", token="employee_token")
    add(users, "Retrieve another profile denied", "users", "GET", "/users/pm.auditor.{{run_suffix}}", 403, token="employee_token")
    add(users, "Retrieve nonexistent user", "users", "GET", "/users/not-a-user-{{run_suffix}}", 404)
    add(users, "Update own profile", "users", "PUT", "/users/{{employee_id}}", body={"department": "Updated Security"}, token="employee_token")
    add(users, "Profile privilege injection rejected", "users", "PUT", "/users/{{employee_id}}", 400, {"role": "security_administrator"}, token="employee_token")
    add(users, "Suspend employee - supporting endpoint", "users", "PUT", "/users/{{employee_id}}/status", body={"account_status": "suspended"})
    add(users, "Suspended account token rejected", "users", "GET", "/users/pm.employee.{{run_suffix}}", 401, token="employee_token")
    add(users, "Reactivate employee", "users", "PUT", "/users/{{employee_id}}/status", body={"account_status": "active"})
    add(users, "Change analyst to employee - supporting endpoint", "users", "PUT", "/users/{{analyst_id}}/role", body={"role": "regular_employee"})
    add(users, "Existing token uses updated role", "playbooks", "GET", "/playbooks", 403, token="analyst_token")
    add(users, "Restore analyst role", "users", "PUT", "/users/{{analyst_id}}/role", body={"role": "security_analyst"})

    logs = folder("03 - Audit logging")
    add(logs, "Create manual audit record", "logs", "POST", "/logs", 201,
        {"user_id": "{{admin_id}}", "action": "postman_check", "description": "Administrative test record.",
         "severity": "Information", "related_service": "logs"}, save=(("log_id", "id"),))
    # IDs in JSON must be numeric, not quoted variables.
    logs[-1]["request"]["body"]["raw"] = logs[-1]["request"]["body"]["raw"].replace('"{{admin_id}}"', '{{admin_id}}')
    add(logs, "List audit records", "logs", "GET", "/logs")
    add(logs, "Retrieve audit record - analyst", "logs", "GET", "/logs/{{log_id}}", token="analyst_token")
    add(logs, "Missing audit record", "logs", "GET", "/logs/2147483647", 404)
    for name, query in (("user", "user_id={{admin_id}}"), ("action", "action=postman_check"),
                        ("severity", "severity=Information"), ("service", "related_service=users"),
                        ("date", "date={{utc_date}}")):
        add(logs, "Search logs by " + name, "logs", "GET", "/logs/search?" + query, token="auditor_token")
    add(logs, "Logs by user", "logs", "GET", "/logs/user/{{employee_id}}")
    add(logs, "Empty user log result", "logs", "GET", "/logs/user/2147483647")
    add(logs, "Employee audit access rejected", "logs", "GET", "/logs/{{log_id}}", 403, token="employee_token")
    add(logs, "Log editing unavailable", "logs", "PUT", "/logs/{{log_id}}", 405, {"description": "Rejected"})
    add(logs, "Unauthorized audit deletion", "logs", "DELETE", "/logs/{{log_id}}", 403, token="analyst_token")
    add(logs, "Administrator audit deletion", "logs", "DELETE", "/logs/{{log_id}}")

    books = folder("04 - Playbooks and ordered actions")
    for index, severity in enumerate(("High", "Critical"), 1):
        add(books, "Create playbook " + str(index), "playbooks", "POST", "/playbooks", 201,
            {"name": "Postman response " + str(index), "description": "Response workflow", "incident_category": "Phishing", "severity": severity},
            save=(("playbook_id" if index == 1 else "second_playbook_id", "id"),))
    add(books, "List playbooks - auditor", "playbooks", "GET", "/playbooks", token="auditor_token")
    for step in (2, 1):
        add(books, "Analyst adds step " + str(step), "playbooks", "POST", "/playbooks/{{playbook_id}}/actions", 201,
            {"description": "Response step " + str(step), "step_number": step}, token="analyst_token", save=(("action_id", "id"),))
    add(books, "Retrieve playbook and ordered steps", "playbooks", "GET", "/playbooks/{{playbook_id}}")
    add(books, "Duplicate step rejected", "playbooks", "POST", "/playbooks/{{playbook_id}}/actions", 409,
        {"description": "Duplicate", "step_number": 1}, token="analyst_token")
    add(books, "Invalid step rejected", "playbooks", "POST", "/playbooks/{{playbook_id}}/actions", 400,
        {"description": "Invalid", "step_number": 0}, token="analyst_token")
    add(books, "Assign action to analyst", "playbooks", "PUT", "/actions/{{action_id}}/status",
        body={"assigned_user_id": "{{analyst_id}}"}, token="analyst_token")
    books[-1]["request"]["body"]["raw"] = books[-1]["request"]["body"]["raw"].replace('"{{analyst_id}}"', '{{analyst_id}}')
    for status in ("In Progress", "Completed", "Pending"):
        add(books, "Action becomes " + status, "playbooks", "PUT", "/actions/{{action_id}}/status", body={"status": status}, token="analyst_token")
    add(books, "Retrieve execution history", "playbooks", "GET", "/playbooks/{{playbook_id}}")
    add(books, "Invalid action status", "playbooks", "PUT", "/actions/{{action_id}}/status", 400, {"status": "Closed"}, token="analyst_token")
    add(books, "Missing playbook", "playbooks", "GET", "/playbooks/2147483647", 404)
    add(books, "Employee playbook access denied", "playbooks", "GET", "/playbooks", 403, token="employee_token")
    add(books, "Auditor action mutation denied", "playbooks", "PUT", "/actions/{{action_id}}/status", 403, {"status": "Completed"}, token="auditor_token")
    add(books, "Analyst playbook deletion denied", "playbooks", "DELETE", "/playbooks/{{playbook_id}}", 403, token="analyst_token")
    add(books, "Administrator playbook deletion", "playbooks", "DELETE", "/playbooks/{{playbook_id}}")
    add(books, "Deleted playbook unavailable", "playbooks", "GET", "/playbooks/{{playbook_id}}", 404)

    internal = folder("05 - Protected service integration")
    headers = [{"key": "X-Service-Name", "value": "playbooks"}, {"key": "X-Service-Key", "value": "{{playbooks_service_key}}"}]
    add(internal, "Verify current identity - service only", "users", "POST", "/internal/identity/verify", extra_headers=headers)
    add(internal, "Validate user reference - service only", "users", "GET", "/internal/users/{{analyst_id}}", token=None, extra_headers=headers)
    add(internal, "Ingest automatic event", "logs", "POST", "/internal/logs", 201,
        {"user_id": None, "action": "postman_internal_check", "description": "Service integration check.",
         "severity": "Information", "related_service": "playbooks"}, token=None,
        extra_headers=[*headers, {"key": "Idempotency-Key", "value": "{{event_id}}"}])
    add(internal, "Retry identical event without duplicate", "logs", "POST", "/internal/logs", 200,
        {"user_id": None, "action": "postman_internal_check", "description": "Service integration check.",
         "severity": "Information", "related_service": "playbooks"}, token=None,
        extra_headers=[*headers, {"key": "Idempotency-Key", "value": "{{event_id}}"}])
    cleanup = folder("06 - User deletion evidence")
    add(cleanup, "Employee cannot delete users", "users", "DELETE", "/users/{{employee_id}}", 403, token="employee_token")
    add(cleanup, "Administrator deletes employee", "users", "DELETE", "/users/{{employee_id}}")
    add(cleanup, "Deleted employee missing", "users", "GET", "/users/pm.employee.{{run_suffix}}", 404)
    add(cleanup, "Historical logs still available", "logs", "GET", "/logs/user/{{employee_id}}")

    collection = {"info": {"name": "Student 1 - Natalio Hassoun", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                            "description": "Run folders in order against your own running services. Creates real demo data. No saved example responses or credentials."},
                  "event": [{"listen": "prerequest", "script": {"type": "text/javascript", "exec": [
                      "pm.collectionVariables.set('utc_date', new Date().toISOString().slice(0,10));",
                      "if (pm.info.requestName === 'Ingest automatic event') pm.collectionVariables.set('event_id', pm.variables.replaceIn('{{$guid}}'));"
                  ]}}], "item": folders}
    values = {"users_url": "http://127.0.0.1:8001", "logs_url": "http://127.0.0.1:8005", "playbooks_url": "http://127.0.0.1:8009",
              "prefix": "/api/natalio-hassoun", "admin_username": "", "admin_password": "", "demo_password": "", "playbooks_service_key": ""}
    environment = {"name": "Student 1 - local template", "_postman_variable_scope": "environment", "values": [
        {"key": key, "value": value, "enabled": True, "type": "secret" if "password" in key or "key" in key else "default"}
        for key, value in values.items()]}
    Path("postman").mkdir(exist_ok=True)
    Path("postman/Student1.postman_collection.json").write_text(json.dumps(collection, indent=2), encoding="utf-8")
    Path("postman/Local.postman_environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
    print(f"Generated {sum(len(folder['item']) for folder in folders)} requests; no saved credentials or simulated responses.")


if __name__ == "__main__":
    main()
