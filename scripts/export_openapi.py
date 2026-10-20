"""Export the three owned OpenAPI contracts; examples are not execution evidence."""

import copy
import json
from pathlib import Path

from security_backend.shared.constants import ACCOUNT_STATUSES, ACTION_STATUSES, LOG_SEVERITIES, ROLES, SEVERITIES


def string(limit=None, enum=None, **extra):
    result = {"type": "string", **extra}
    if limit:
        result.setdefault("minLength", 1)
        result["maxLength"] = limit
    if enum: result["enum"] = list(enum)
    return result


def obj(properties, required=(), **extra):
    return {"type": "object", "properties": properties, "required": list(required), **extra}


def ref(name):
    return {"$ref": "#/components/schemas/" + name}


ID = {"type": "integer", "minimum": 1, "maximum": 2147483647}
TIME = {"type": "string", "format": "date-time"}
SCHEMAS = {
    "Error": obj({"status": {"type": "string", "enum": ["error"]}, "code": string(), "message": string()}, ("status", "code", "message")),
    "User": obj({"id": ID, "full_name": string(255), "username": string(64), "email": string(254, format="email"),
                 "department": string(255), "role": string(enum=ROLES), "account_status": string(enum=ACCOUNT_STATUSES),
                 "created_date": TIME, "last_login_date": {**TIME, "nullable": True}}),
    "Identity": obj({"id": ID, "role": string(enum=ROLES), "account_status": string(enum=("active",))}, ("id", "role", "account_status")),
    "UserReference": obj({"id": ID, "role": string(enum=ROLES), "account_status": string(enum=ACCOUNT_STATUSES),
                          "deleted": {"type": "boolean"}}, ("id", "role", "account_status", "deleted")),
    "Registration": obj({"full_name": string(255), "username": string(64), "email": string(254, format="email"),
                         "password": string(128, minLength=12, format="password"), "department": string(255), "role": string(enum=ROLES)},
                        ("full_name", "username", "email", "password", "department", "role"), additionalProperties=False),
    "Login": obj({"identifier": string(254), "password": string(128, format="password")}, ("identifier", "password"), additionalProperties=False),
    "LoginResult": obj({"access_token": string(), "token_type": {"type": "string", "enum": ["Bearer"]},
                        "expires_in": {"type": "integer", "enum": [1800]}, "user": ref("User")}),
    "ProfileUpdate": obj({"full_name": string(255), "email": string(254, format="email"), "department": string(255)}, minProperties=1, additionalProperties=False),
    "RoleUpdate": obj({"role": string(enum=ROLES)}, ("role",), additionalProperties=False),
    "StatusUpdate": obj({"account_status": string(enum=ACCOUNT_STATUSES)}, ("account_status",), additionalProperties=False),
    "LogInput": obj({"user_id": {**ID, "nullable": True}, "action": string(100, pattern="^[a-z][a-z0-9_]*$"),
                     "description": string(2000), "severity": string(enum=LOG_SEVERITIES), "related_service": string(64)},
                    ("user_id", "action", "description", "severity", "related_service"), additionalProperties=False),
    "PlaybookInput": obj({"name": string(255), "description": string(4000), "incident_category": string(100), "severity": string(enum=SEVERITIES)},
                         ("name", "description", "incident_category", "severity"), additionalProperties=False),
    "ActionInput": obj({"description": string(4000), "step_number": {"type": "integer", "minimum": 1}, "assigned_user_id": {**ID, "nullable": True}},
                       ("description", "step_number"), additionalProperties=False),
    "ActionUpdate": obj({"status": string(enum=ACTION_STATUSES), "assigned_user_id": {**ID, "nullable": True}, "completion_date": {**TIME, "nullable": True}},
                        minProperties=1, additionalProperties=False),
    "Deletion": obj({"id": ID, "deleted": {"type": "boolean"}, "deletion_mode": string()}),
}
SCHEMAS["Log"] = obj({**SCHEMAS["LogInput"]["properties"], "id": ID, "timestamp": TIME, "event_id": string(format="uuid"), "source_service": string()})
SCHEMAS["Playbook"] = obj({**SCHEMAS["PlaybookInput"]["properties"], "id": ID, "created_by": ID, "creation_date": TIME})
SCHEMAS["Action"] = obj({**SCHEMAS["ActionInput"]["properties"], "id": ID, "playbook_id": ID,
                         "status": string(enum=ACTION_STATUSES), "completion_date": {**TIME, "nullable": True}})
SCHEMAS["History"] = obj({"id": ID, "action_id": ID, "changed_by": ID, "previous": {"type": "object", "nullable": True},
                          "current": {"type": "object"}, "timestamp": TIME})
SCHEMAS["PlaybookDetail"] = copy.deepcopy(SCHEMAS["Playbook"])
SCHEMAS["PlaybookDetail"]["properties"]["actions"] = {"type": "array", "items": {"allOf": [ref("Action"), obj({"history": {"type": "array", "items": ref("History")}})]}}
SCHEMAS["LogReceipt"] = obj({"event_id": string(format="uuid"), "duplicate": {"type": "boolean"},
                             "log": {"allOf": [ref("Log")], "type": "object", "nullable": True}}, ("event_id", "duplicate", "log"))


def build(service, port):
    document = {"openapi": "3.0.3", "info": {"title": f"Natalio Hassoun — {service.title()}", "version": "team-integration-v1.0.0",
                 "description": "Owned API contract. See API.md and INTEGRATION.md for permissions, workflow and retry semantics. Examples are not captured execution evidence."},
                "servers": [{"url": f"http://127.0.0.1:{port}/api/natalio-hassoun"}], "paths": {},
                "components": {"schemas": SCHEMAS, "securitySchemes": {
                    "Bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                    "ServiceName": {"type": "apiKey", "in": "header", "name": "X-Service-Name"},
                    "ServiceKey": {"type": "apiKey", "in": "header", "name": "X-Service-Key"}}}}

    def add(method, path, description, response, body=None, code=200, auth="user", many=False, query=()):
        schema = {"type": "array", "items": ref(response)} if many else ref(response)
        envelope = obj({"status": {"type": "string", "enum": ["success"]}, "data": schema,
                        "audit_delivery": {"type": "object"}}, ("status", "data"))
        operation = {"summary": description, "security": [{"Bearer": []}] if auth == "user" else [], "responses": {
            str(code): {"description": "Success", "content": {"application/json": {"schema": envelope}}}}}
        for error in (400, 401, 403, 404, 409, 500, 503):
            operation["responses"][str(error)] = {"description": "See API.md for applicable error codes.", "content": {"application/json": {"schema": ref("Error")}}}
        if auth.startswith("service"):
            security = {"ServiceName": [], "ServiceKey": []}
            if auth == "service_user": security["Bearer"] = []
            operation["security"] = [security]
        if auth == "optional": operation["security"] = [{}, {"Bearer": []}]
        parameters = [{"name": name, "in": "path", "required": True, "schema": string() if name == "username" else ID}
                      for name in ("id", "username", "user_id") if "{" + name + "}" in path]
        parameters += [{"name": name, "in": "query", "schema": ID if name == "user_id" else string()} for name in query]
        if path == "/internal/logs":
            parameters.append({"name": "Idempotency-Key", "in": "header", "required": True, "schema": string(format="uuid")})
            operation["responses"]["200"] = copy.deepcopy(operation["responses"][str(code)])
            operation["responses"]["200"]["description"] = "Identical retry, including log=null after deletion."
        if parameters: operation["parameters"] = parameters
        if body: operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": ref(body)}}}
        document["paths"].setdefault(path, {})[method.lower()] = operation

    SCHEMAS["Health"] = obj({"service": string()})
    add("GET", "/health", "Public service/database health", "Health", auth="public")
    if service == "users":
        add("POST", "/users/register", "Public employee registration; elevated roles require administrator", "User", "Registration", 201, "optional")
        add("POST", "/users/login", "Login with username or email; active accounts only", "LoginResult", "Login", auth="public")
        add("GET", "/users", "Administrator/auditor list nondeleted users", "User", many=True)
        add("GET", "/users/{username}", "Administrator/auditor any profile; employee own profile", "User")
        add("PUT", "/users/{id}", "Administrator any profile; employee own profile", "User", "ProfileUpdate")
        add("DELETE", "/users/{id}", "Administrator soft-delete; cannot delete self", "Deletion")
        add("PUT", "/users/{id}/role", "Administrator role change (supporting addition)", "User", "RoleUpdate")
        add("PUT", "/users/{id}/status", "Administrator account-state change (supporting addition)", "User", "StatusUpdate")
        add("POST", "/internal/identity/verify", "Service-authenticated live identity; user JWT required", "Identity", auth="service_user")
        add("GET", "/internal/users/{id}", "Service-authenticated minimal reference, including retained deleted users", "UserReference", auth="service")
    elif service == "logs":
        add("POST", "/logs", "Administrator manual record; actor must be authenticated administrator", "Log", "LogInput", 201)
        add("GET", "/logs", "Administrator/auditor complete list", "Log", many=True)
        add("GET", "/logs/{id}", "Administrator/analyst/auditor detail", "Log")
        add("DELETE", "/logs/{id}", "Administrator deletion; durable receipt retained", "Deletion")
        add("GET", "/logs/search", "Administrator/analyst/auditor exact-match search", "Log", many=True,
            query=("user_id", "date", "action", "severity", "related_service"))
        add("GET", "/logs/user/{user_id}", "Administrator/auditor logs by actor; empty array allowed", "Log", many=True)
        add("POST", "/internal/logs", "Service-authenticated ingestion; source must match related_service", "LogReceipt", "LogInput", 201, "service")
    else:
        add("POST", "/playbooks", "Administrator create", "Playbook", "PlaybookInput", 201)
        add("GET", "/playbooks", "Administrator/analyst/auditor list", "Playbook", many=True)
        add("GET", "/playbooks/{id}", "Administrator/analyst/auditor ordered actions and history", "PlaybookDetail")
        add("DELETE", "/playbooks/{id}", "Administrator soft-delete preserving execution history", "Deletion")
        add("POST", "/playbooks/{id}/actions", "Administrator/analyst add positive unique step", "Action", "ActionInput", 201)
        add("PUT", "/actions/{id}/status", "Administrator/analyst status, assignment and completion update", "Action", "ActionUpdate")
    return document


def main():
    for service, port in (("users", 8001), ("logs", 8005), ("playbooks", 8009)):
        Path(f"docs/openapi-{service}.json").write_text(json.dumps(build(service, port), indent=2), encoding="utf-8")
    print("Exported three secret-free OpenAPI contracts.")


if __name__ == "__main__":
    main()
