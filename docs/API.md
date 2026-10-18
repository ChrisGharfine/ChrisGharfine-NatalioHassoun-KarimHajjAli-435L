# API reference (Natalio Hassoun)

All paths below follow `/api/natalio-hassoun` on their service URL.
U = Users :8001; L = Logs :8005; P = Playbooks :8009.
Roles: A administrator, S analyst, E employee, R auditor.
Authentication is `Authorization: Bearer <access_token>`, unless specified.

Successful responses have `{"status":"success","data":...}`. Mutations with
audit events additionally report `audit_delivery`. Errors use
`{"status":"error","code":"...","message":"..."}`. JSON examples below
describe contracts; they are not execution evidence.

Common errors for every protected route: 401 missing/invalid/expired token or
unavailable account; 403 disallowed role/ownership; 503 identity/database unavailable.
Mutation input errors use 400; conflicting unique fields or concurrent changes use
409. Unknown IDs/resources use 404. Unimplemented methods use 405. Request bodies
must be non-empty JSON objects, at most 64 KiB, with only documented fields.

## Users

| Method/path | Purpose and permission | Input | Success | Additional errors |
|---|---|---|---|---|
| POST /users/register | Public/employee: regular employee; A: any role | full_name, username, email, password, department, role | 201, User | 400 validation; 403 elevated public role; 409 duplicate username/email |
| POST /users/login | Authenticate an active account; public | identifier (username/email), password | 200, token + User | 400 invalid body; 401 incorrect credentials/inactive/suspended/deleted |
| PUT /users/{id} | A any user; E own profile | any of full_name, email, department | 200, User | 400 unexpected field; 404 missing; 409 duplicate email |
| DELETE /users/{id} | A, soft delete | no body | 200, id/deleted/deletion_mode | 404 missing; 409 self deletion |
| GET /users | A/R, list non-deleted users | none | 200, User array | common errors |
| GET /users/{username} | A/R any; E own | username path string | 200, User | 404 missing (A/R); 403 other/missing username for E |
| PUT /users/{id}/role | A, supporting addition | role | 200, User | 400 role; 404 missing; 409 self demotion |
| PUT /users/{id}/status | A, supporting addition | account_status | 200, User | 400 status; 404 missing; 409 self disable |

IDs in paths are positive integers. DELETE retains the user record and FKs,
hides it from list/detail, sets inactive, and blocks login/current-token use.
Username and email remain reserved. Auditor cannot mutate; analyst cannot access
public user management. Email and usernames are normalized to lowercase; usernames
are 3–64 characters, start with alphanumeric, and contain only letters, digits,
dot, underscore or hyphen. Email maximum is 254; name/department maximum is 255.

Registration example:

```json
{
  "full_name": "Example Employee",
  "username": "example.employee",
  "email": "example.employee@example.edu",
  "password": "Replace-With-Own-435!",
  "department": "IT",
  "role": "regular_employee"
}
```

User response fields: id, full_name, username, email, department, role,
account_status, created_date, last_login_date. Password/hash are never returned.
Login returns `{access_token, token_type:"Bearer", expires_in:1800, user:User}`
inside data. Issuing this token is the intentional authentication response;
other APIs must not return or log tokens. Login failures return a generic message.

## Audit logs

| Method/path | Purpose and permission | Input | Success | Additional errors |
|---|---|---|---|---|
| POST /logs | A, manual activity record | user_id, action, description, severity, related_service | 201, Log | 400 validation; 403 actor differs from authenticated admin |
| GET /logs | A/R, all records | none | 200, Log array | common errors |
| GET /logs/{id} | A/S/R, one record | id | 200, Log | 404 missing |
| GET /logs/search | A/S/R, exact-match filters | optional user_id, date, action, severity, related_service | 200, Log array | 400 invalid/unknown filter |
| DELETE /logs/{id} | A, physical deletion | id | 200, id/deleted | 404 missing |
| GET /logs/user/{user_id} | A/R, activities by actor | user_id | 200, Log array; empty if none | common errors |

Search combines supplied filters with AND. Date is `YYYY-MM-DD` and selects the
UTC calendar day. Logs are ordered by ID. No edit endpoint exists and a database
trigger rejects UPDATE. Deleting a log creates another audit record in the same
transaction; the receipt of the deleted event remains.

Manual body example (use the actual authenticated administrator's ID):

```json
{"user_id":1,"action":"manual_check","description":"Reviewed system configuration.","severity":"Information","related_service":"logs"}
```

Action: lowercase letters/digits/underscores, starting with a letter, maximum
100 characters. Description: non-empty, maximum 2000. Related service maximum 64.
Severity: Information, Warning, Error, Critical.

Log response fields: id, user_id, action, description, timestamp, severity,
related_service, event_id, source_service. Credentials must never be included in
descriptions. Public manual logs bind user_id to the authenticated admin; automatic
service logs can identify a validated user or use null for an unknown actor.

## Playbooks

| Method/path | Purpose and permission | Input | Success | Additional errors |
|---|---|---|---|---|
| POST /playbooks | A, create | name, description, incident_category, severity | 201, Playbook | 400 validation |
| GET /playbooks | A/S/R, list non-deleted | none | 200, Playbook array | common errors |
| GET /playbooks/{id} | A/S/R, detail with ordered actions and history | id | 200, Playbook + actions | 404 missing/deleted |
| POST /playbooks/{id}/actions | A/S, add step | description, step_number; optional assigned_user_id | 201, Action | 400 invalid/unavailable user; 404 playbook; 409 duplicate step |
| PUT /actions/{id}/status | A/S, change status/assignment/completion | any of status, assigned_user_id, completion_date | 200, Action | 400 validation; 404 action/deleted playbook; 409 concurrent change |
| DELETE /playbooks/{id} | A, soft deletion preserving history | id | 200, id/deleted/deletion_mode | 404 missing/deleted |

Playbook name maximum 255; description 4000; category 100. Severity is Low,
Medium, High or Critical. Creator and creation date are server-derived.
Playbook response: id, name, description, incident_category, severity, created_by,
creation_date. Detail adds `actions`, sorted by positive unique step_number.

Action body:

```json
{"description":"Review incident evidence.","step_number":1,"assigned_user_id":12}
```

Action response: id, playbook_id, description, step_number, status,
assigned_user_id, completion_date. Status starts Pending. Null assignment is
allowed; a non-null assignee must exist and be active/non-deleted. Description
maximum 4000. Step numbers are immutable through these APIs.

Update example: `{"status":"Completed"}`. The server fills completion_date.
Explicit completion_date must include a timezone and cannot be in the future.
Non-completed actions cannot have a non-null completion_date; reopening clears it.
All transitions among Pending, In Progress, Completed are allowed by documented
policy. Every creation/update stores an immutable history snapshot.

Action history in playbook detail contains id, action_id, changed_by, previous,
current, timestamp. The initial previous value is null. Deleted playbooks/history
remain stored but are hidden by public APIs; execution history is not erased.

## Supporting internal and health APIs

| Service/method/path | Authentication | Purpose/result |
|---|---|---|
| U POST /internal/identity/verify | service name/key + original user JWT | current id/role/status; 401 invalid/inactive |
| U GET /internal/users/{id} | service name/key | minimal reference including deleted flag; 404 unknown |
| L POST /internal/logs | service name/key + Idempotency-Key UUID | 201 new or 200 duplicate; 400 input/reference/source, 409 payload conflict |
| U/L/P GET /health | public | 200 service name if database reachable; 503 otherwise |

See INTEGRATION.md for full headers and ingestion payload. A new ingestion returns
data `{event_id, log:Log, duplicate:false}`. A retry returns duplicate:true and the
same log, or log:null if that log was legitimately deleted. IDs/timestamps cannot
be supplied as body overrides. Source service must match related_service.

## Audit response and retry behavior

Business changes and their outbox events commit atomically. A normal mutation can
return 200/201 with `audit_delivery:{status:"pending",pending_events:1}` if Logging
is unavailable. This means the business operation succeeded; retain its result and
run `flush-audit` after recovery. Delivery errors never expose service secrets.
Pending events survive process restarts. The finite timeout prevents unbounded
HTTP waits. Database failure prevents committing both the mutation and its event.

401/403 requests also create an audit event; if its database storage fails, the
response is 503 AUDIT_STORAGE_UNAVAILABLE instead of claiming it was recorded.

## References used during implementation

- [Flask application factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/)
- [Flask-JWT-Extended basic usage](https://flask-jwt-extended.readthedocs.io/en/stable/basic_usage.html)
- [SQLAlchemy sessions](https://docs.sqlalchemy.org/en/20/orm/session_basics.html)
- [SQLAlchemy PostgreSQL dialect](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html)
- [Werkzeug password helpers](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security)

Consult the supplied assignment for grading requirements; these technical docs
support implementation choices rather than defining the course requirements.
