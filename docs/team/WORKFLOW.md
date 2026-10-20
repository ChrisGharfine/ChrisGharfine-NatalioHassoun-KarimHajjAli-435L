# API workflow and route index

The merged backend has nine independent HTTP services and 54 prescribed public
operations. This guide explains how their calls connect. Request examples are
templates to execute against disposable demonstration records, not captured
responses. The [evidence guide](EVIDENCE.md) describes actual execution records.

## Authentication and addresses

Use the complete bases in [the contract](INTEGRATION_V1_1.md#routes-and-service-addresses).
Every route includes the owning student's prefix. Postman variable conventions
differ: Natalio uses an origin plus `{{prefix}}`; Chris uses complete
`{{assets_base_url}}`, `{{threats_base_url}}` and `{{reports_base_url}}`; Karim's
`{{incidents_url}}`, `{{vulnerabilities_url}}` and `{{notifications_url}}` include
his prefix already. Do not append a prefix twice.

Send protected public requests with `Authorization: Bearer {{admin_token}}`
or the actual appropriate user's token. Users issues HS256 access tokens with
issuer `security-sprint1-users`, audience `security-sprint1-services`, a text
positive user ID in `sub`, numeric `iat`/`exp`, and `type=access`. Tokens expire
after 30 minutes. A resource service verifies the token locally, then checks
current identity over authenticated HTTP with Users. Live role/status changes
therefore apply to the same token. An unavailable identity provider fails closed.

Canonical roles are `security_administrator`, `security_analyst`,
`regular_employee` and `auditor`. Having a valid token does not grant every role
or permission to another recipient's notification inbox.

## End to end demonstration

1. **Prepare the system.** Apply owned migrations and start nine services plus
   workers using [setup](SETUP.md). Check `<complete-base>/health` for all nine.
2. **Sign in and obtain real user IDs.** Bootstrap an administrator only on a
   fresh installation, then sign in with its stored username or email. Use the
   administrator to register analyst/auditor accounts; public registration may
   create only employees. Retain each returned ID and token in local variables.
3. **Create an asset.** As administrator, add an asset referencing an existing
   active Users account. Assets validates that owner over HTTP. Retain its `id`.
4. **Record threat intelligence.** As administrator, register a valid indicator;
   use a domain such as `investigation.example`, a valid IP or a valid hash.
   Chris's API uses lowercase enums such as `domain` and `high`.
5. **Report an incident.** An administrator or employee creates an incident
   linked to the asset. Karim's input field is `affected_asset`; the response
   stores `asset_id` and identifies the record with `incident_id`.
6. **Assign and investigate it.** An administrator assigns an active analyst.
   Assignment stores durable notification work; the worker sends an
   `Incident Assignment` to Notifications. Add investigation notes and advance
   status through `Open → Under Investigation → Mitigated → Resolved → Closed`.
   Skipping a transition is invalid.
7. **Track a vulnerability.** As administrator, create a `High` or `Critical`
   vulnerability for the same asset with valid optional CVE/CVSS values. If its
   owner is active, a `Vulnerability Alert` is queued and delivered to that
   owner's inbox. Lower severities do not trigger this automatic alert.
8. **Read the inbox.** The recipient retrieves the notification and marks it
   read. A repeated read preserves the original read time and does not create
   a second mutation audit event. Administrators/auditors can inspect other
   inboxes; other callers are restricted to their own records.
9. **Use a response playbook.** An administrator creates a playbook. An
   administrator/analyst adds numbered actions and updates execution status.
   Detail returns actions in step order and includes immutable history.
10. **Check audit delivery and reports.** Drain queues, inspect Logs with
    appropriate filters, then read the six Reports endpoints. Reports obtains
    source data over HTTP rather than querying other services' tables. Run the
    read-only reconciliation checker while the dataset is stable.
11. **Capture negative cases and cleanup.** Demonstrate invalid input, unknown
    records and disallowed roles. Capture report totals before deleting any
    disposable records; cleanup changes those totals. Do not delete team data.

## Request examples

In Postman choose the stated method, paste the full URL, set raw JSON with
`Content-Type: application/json`, and use local variables for private values.
IDs below are placeholders populated from previous real responses.

### Sign in through Users

`POST http://127.0.0.1:8001/api/natalio-hassoun/users/login`

```json
{"identifier":"{{admin_username}}","password":"{{admin_password}}"}
```

Success is 200. The token is `data.access_token` and the signed-in user is
`data.user`. The identifier is the stored username/email, not `ADMIN_FULL_NAME`.
Store the token locally as `admin_token`. Chris's and Karim's collections need
their respective token variables populated; a variable set in one selected
environment is not automatically present in another environment.

### Create the shared asset

`POST http://127.0.0.1:8002/api/chris-gharfine/assets` with the administrator token:

```json
{
  "name":"Demonstration application server",
  "asset_type":"server",
  "ip_address":"192.0.2.10",
  "department":"Security",
  "owner_id":{{owner_id}},
  "criticality":"high"
}
```

Success is 201 with the asset object directly at the JSON root; save `id` as
`asset_id`. Asset severities are lowercase, while Karim's public severity values
are Title Case. Preserve each API's documented enum spelling.

### Create and assign an incident

`POST http://127.0.0.1:8003/api/karim-hajj-ali/incidents`

```json
{
  "title":"Suspicious login activity",
  "description":"A disposable incident for the team demonstration.",
  "category":"Unauthorized Access",
  "severity":"High",
  "affected_asset":{{asset_id}}
}
```

Success is 201 with `status`, `message` and `incident`; save
`incident.incident_id` as `incident_id`. Then, as administrator:

`PUT http://127.0.0.1:8003/api/karim-hajj-ali/incidents/{{incident_id}}/assign`

```json
{"analyst_id":{{analyst_id}}}
```

Success is 200. Run the delivery worker, then inspect
`GET http://127.0.0.1:8008/api/karim-hajj-ali/notifications/user/{{analyst_id}}`
using that recipient's token or an administrator/auditor token. Confirm an
`Incident Assignment`, not merely that some notification exists.

### Inspect reports and filters

As administrator or auditor:

```text
GET http://127.0.0.1:8006/api/chris-gharfine/reports/summary
GET http://127.0.0.1:8006/api/chris-gharfine/reports/incidents
GET http://127.0.0.1:8005/api/natalio-hassoun/logs/search?related_service=incidents
```

Success is 200 when dependencies are available and permissions are satisfied.
Use the [checker instructions](SETUP.md#6-postman-and-live-team-verification) to
compare all six reports with live source records. Avoid assuming a particular
total from an earlier screenshot or a different demonstration database.

## Core public API index

Paths below are relative to each service's complete base. `{id}` means the
appropriate positive record ID; `{username}` is a username string. Detailed
inputs, schemas and permissions are in the owner references linked below.

| Owner and service | Six prescribed operations |
|---|---|
| Natalio — Users 8001 | `POST /users/register`; `POST /users/login`; `PUT /users/{id}`; `DELETE /users/{id}`; `GET /users`; `GET /users/{username}` |
| Chris — Assets 8002 | `POST /assets`; `GET /assets`; `GET /assets/{id}`; `PUT /assets/{id}`; `GET /assets/search`; `DELETE /assets/{id}` |
| Karim — Incidents 8003 | `POST /incidents`; `GET /incidents`; `GET /incidents/{id}`; `PUT /incidents/{id}/assign`; `PUT /incidents/{id}/status`; `POST /incidents/{id}/notes` |
| Chris — Threats 8004 | `POST /threats`; `GET /threats`; `GET /threats/{id}`; `PUT /threats/{id}`; `GET /threats/search`; `DELETE /threats/{id}` |
| Natalio — Logs 8005 | `POST /logs`; `GET /logs`; `GET /logs/{id}`; `GET /logs/search`; `DELETE /logs/{id}`; `GET /logs/user/{user_id}` |
| Chris — Reports 8006 | `GET /reports/summary`; `GET /reports/incidents`; `GET /reports/assets`; `GET /reports/threats`; `GET /reports/vulnerabilities`; `GET /reports/activity` |
| Karim — Vulnerabilities 8007 | `POST /vulnerabilities`; `GET /vulnerabilities`; `GET /vulnerabilities/{id}`; `PUT /vulnerabilities/{id}`; `GET /vulnerabilities/search`; `DELETE /vulnerabilities/{id}` |
| Karim — Notifications 8008 | `POST /notifications`; `GET /notifications/user/{user_id}`; `GET /notifications/{id}`; `PUT /notifications/{id}/read`; `GET /notifications/search`; `DELETE /notifications/{id}` |
| Natalio — Playbooks 8009 | `POST /playbooks`; `GET /playbooks`; `GET /playbooks/{id}`; `POST /playbooks/{id}/actions`; `PUT /actions/{id}/status`; `DELETE /playbooks/{id}` |

Supporting role/status management, health, readiness, documentation and internal
reference/delivery routes are additional to those 54 operations.

- Natalio: [full API reference](../API.md), with request fields, result fields,
  validation, role rules and OpenAPI JSON exports.
- Chris: [service guide](../chris/service-guide.md), typed schemas in
  `services/assets/schemas.py`, `services/threats/schemas.py` and
  `services/reports/schemas.py`; each running service exposes its prefixed `/docs`
  and `/openapi.json`.
- Karim: [entry guide](../karim/START_HERE.md), current Postman request bodies,
  and documented modules under `docs/source/`. Build the optional Sphinx
  documentation using the command in the entry guide.

## Internal HTTP boundaries and durable delivery

| Provider | Route | Caller behavior |
|---|---|---|
| Users | `POST /internal/identity/verify` | Resource service sends its service name/key and the original user Bearer token; require matching current identity |
| Users | `GET /internal/users/{id}` | Authenticated service reference lookup for account existence, status and role |
| Assets | `GET /internal/assets/{id}` | Incidents/Vulnerabilities authenticate with their own service name/key and obtain the asset/owner reference |
| Logs | `POST /internal/logs` | Audit worker sends the persisted event with a stable UUID `Idempotency-Key` |
| Notifications | `POST /internal/notifications` | Authorized service worker sends its persisted recipient alert with a stable UUID `Idempotency-Key` |

An internal caller supplies `X-Service-Name` and `X-Service-Key`. Receiver policy
still limits which service may call which operation/type. A business mutation
and its outbox event commit together. On an outage the worker retries delivery,
not the business mutation. Receivers persist receipts: a new accepted delivery
returns 201/`duplicate:false`; an identical retry returns 200/`duplicate:true`.
The acknowledgement must match the event UUID and resource contract. Receipts
survive legitimate resource deletion and do not recreate a deleted record.

## Responses and failures

Success shapes are intentionally service-specific: Natalio uses `status/data`,
Chris returns typed objects/lists/reports, and Karim uses `status/message` plus
named entities or list/count fields. Do not force every success into one envelope.
Errors share `status:error`, `code` and `message`. Common statuses are 400 invalid
input, 401 invalid authentication, 403 permission denial, 404 missing record,
409 conflict and 503 unavailable dependency. Chris also returns 502 for malformed
source responses. Confirm the expected negative status and JSON instead of using
Postman's automatic repair suggestion during an intentional rejection test.
