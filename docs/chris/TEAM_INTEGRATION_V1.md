# Team integration v1 — implementation specification

Version: `team-integration-v1.0.0`, prepared 19 October 2026 at Chris's request.

**This file chooses the target; it does not claim the target is implemented or
tested.** Give this same file to all three members and their development
assistants. Each member implements the tasks assigned below in their own branch.
The assignment remains authoritative. Record any grading conflict explicitly;
do not silently invent an incompatible replacement contract.

## 1. Basis and fixed decisions

Source inspected:

- Chris: `feature/chris`, commit `f80e0a0eadeb29999a314ee862c9fbeca1e82ce4`.
- Natalio: `natalio/student1`, commit
  `cb2728cdfc52b9fc3bd314deccea0aea02c1f48d`. Actual factory, auth, HTTP clients,
  Users, Logs, models and API/setup documents were read using Git; not merged or
  executed here. Unlike the earlier draft, PostgreSQL, HS256, response envelopes,
  log acknowledgments and login action names are now established from his code.
  See the inspected [factory](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/blob/cb2728cdfc52b9fc3bd314deccea0aea02c1f48d/security_backend/app.py),
  [Users](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/blob/cb2728cdfc52b9fc3bd314deccea0aea02c1f48d/security_backend/users.py)
  and [Logs](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/blob/cb2728cdfc52b9fc3bd314deccea0aea02c1f48d/security_backend/logs.py).
- Karim: supplied `integration-contracts-karim.md`. His actual implementation
  was unavailable in the fetched branches; `origin/Karim` contained only README.
  Descriptions of his current behavior therefore come from that document.

Decisions for v1:

1. Shared PostgreSQL 17 database/schema; owned migrations and real foreign keys.
2. Keep each member's framework. Run nine independently addressable HTTP services.
3. Users issues HS256 access JWTs. Resource services check current account state
   over HTTP on every protected request, after local token verification.
4. Use Natalio's existing internal identity and logging interfaces.
5. Preserve provider-specific list envelopes and fields. Chris maps them in Reports.
6. HTTP calls replace cross-service imports and direct business-table queries.
7. Persistent outboxes and UUID receipts protect audit/notification delivery.
8. New timestamps represent UTC; wire timestamps are timezone-aware ISO 8601.

These are implementation decisions, not questions for each AI to independently
answer. If a member cannot implement one, report the specific conflict to the
team before changing this version. Adoption by the teammates is not implied by
Chris authoring this specification.

## 2. Service addresses and ownership

Every base URL below is configurable and includes its complete path prefix.
Append the resource path exactly once. These are host-run development defaults:

| Service name / owner | Base URL | Resource paths |
| --- | --- | --- |
| `users` / Natalio | `http://127.0.0.1:8001/api/natalio-hassoun` | `/users`, `/users/login`, `/users/register`, `/internal/identity/verify`, `/internal/users/{id}` |
| `assets` / Chris | `http://127.0.0.1:8002` | `/assets`, `/internal/assets/{id}` |
| `incidents` / Karim | `http://127.0.0.1:8003` | `/incidents` |
| `threats` / Chris | `http://127.0.0.1:8004` | `/threats` |
| `logs` / Natalio | `http://127.0.0.1:8005/api/natalio-hassoun` | `/logs`, `/internal/logs` |
| `reports` / Chris | `http://127.0.0.1:8006` | `/reports/summary`, `/reports/incidents`, `/reports/assets`, `/reports/threats`, `/reports/vulnerabilities`, `/reports/activity` |
| `vulnerabilities` / Karim | `http://127.0.0.1:8007` | `/vulnerabilities` |
| `notifications` / Karim | `http://127.0.0.1:8008` | `/notifications`, `/internal/notifications` |
| `playbooks` / Natalio | `http://127.0.0.1:8009/api/natalio-hassoun` | `/playbooks`, `/actions/{id}/status` |

All existing prescribed CRUD/search/status paths and public permission rules
remain applicable. This specification adds the two explicitly listed internal
reference/delivery paths; they do not replace or broaden public permissions.

Each service exposes `{BASE_URL}/health`. Natalio's existing shape is
`{"status":"success","data":{"service":"users"}}` (appropriate service name).
Chris/Karim use `{"status":"ok","service":"assets"}` (appropriate name).
Chris also exposes `/ready`; readiness must return `200` only when its required
tables can be queried. Karim's health must check its own required tables.

Inside containers, use the corresponding service DNS hostnames instead of
`127.0.0.1`; a container's loopback does not address another container. Preserve
the path prefix. URL configuration is allowed; different JSON contracts are not.

Configuration mapping matters: Natalio's existing `USERS_URL` and `LOGS_URL`
store the origin only, and his client appends `API_PREFIX` separately. Keep those
native settings separate, or update the client before passing a full base URL.
Never append Natalio's prefix twice. Chris's `CHRIS_USERS_URL` and
`CHRIS_AUDIT_URL`, and the checker's `TEAM_*_URL` overrides, take the full base
URL including the prefix shown above.

Route compliance exception: Chris's earlier explicit instruction preserves his
prescribed paths pending clarification of the assignment's full-name rule. This
v1 keeps the addresses above and does not claim that naming ambiguity is resolved.
If the professor requires prefixes everywhere, issue a route-only v1.1 update
with all URLs/Postman/checker configuration changed together. Do not rename the
repository to resolve the separate `430L`/`435L` ambiguity.

## 3. Shared database and migration order

- Natalio alone creates/migrates `users`, `logs`, `log_receipts`, Playbooks tables,
  his outboxes and `student1_schema_versions`.
- Chris alone creates/migrates `assets`, `threats`, `chris_audit_outbox` and
  `chris_alembic_version`.
- Karim alone creates/migrates `incidents`, `investigation_notes`,
  `vulnerabilities`, `notifications`, his delivery outboxes/receipts and his own
  migration history. Remove all-teammate-table creation from his integrated setup.
- Apply Natalio's owned migration first, Chris's owned migrations second, and
  Karim's owned migrations third. This establishes Users and Assets before
  creating references to them. Never call a metadata-wide `create_all` that
  creates placeholders for another owner's production tables.
- `users.id` is Natalio's integer PK; user identities are positive values through
  `2147483647`, matching his identity validator. `assets.id` is Chris's BIGINT PK.
  `assets.owner_id` references `users.id ON DELETE RESTRICT`.
- Karim's user references point to `users(id)`, not `users(user_id)`.
  His asset references point to `assets(id)`, not `assets(asset_id)`.
  Use compatible integer column types and test the actual database constraints.
- Both incident and vulnerability asset references use `ON DELETE RESTRICT`.
  Incidents retain their documented nullable asset field; Vulnerabilities require
  an asset. Notes cascade only with deletion of their own incident.
- Keep Karim's `incident_id`, `vulnerability_id`, `note_id`, `notification_id`
  primary key names; no global primary-key rename is required.
- Users uses Natalio's existing soft deletion: retain its row/PK, mark it inactive
  and deleted, hide it from public lists, reject its tokens, preserve history.
- Only an owner accesses their business tables from application code. Cross-owner
  FK constraints do not authorize direct queries or writes of those tables.

Use a newly named integration database for first assembly. Preserve existing
databases; no automatic reset/reseed/drop. Existing data transfers need reviewed
migrations, a backup and identifier preservation. Convert naive timestamps using
their actual original timezone; never relabel local times as UTC by appending Z.

## 4. Authentication and reference APIs

### 4.1 Token target

Users is the only user-token issuer. Keep Natalio's existing login request:

`POST {USERS_BASE_URL}/users/login`

```json
{"identifier":"actual.username.or.email","password":"supplied locally"}
```

The token is `data.access_token` inside Natalio's success envelope. Do not commit
or export it. Target lifetime is his existing 1800 seconds.

Required JWT claims for v1: `sub` (positive user ID encoded as text), numeric
`iat`, numeric `exp`, `iss="security-sprint1-users"`,
`aud="security-sprint1-services"`, and `type="access"`. If `nbf` is present,
validate it. Other Flask JWT claims may remain. `role` and `account_status`
are not required JWT claims and must not be used as the current authority.

HS256 is the only configured algorithm. Reject unsigned tokens, other algorithms,
missing/invalid required claims, expired/future-invalid tokens and wrong
issuer/audience. Configure a randomly generated shared secret of at least 32
bytes locally. Never select the algorithm from an untrusted token header.

Natalio must add explicit environment/config wiring for
`JWT_ENCODE_ISSUER`, `JWT_DECODE_ISSUER`, `JWT_ENCODE_AUDIENCE`, and
`JWT_DECODE_AUDIENCE`; his inspected factory currently does not set them.
Consumers must require their presence, not just validate a claim if supplied.
Start a new login session after introducing these claims; old tokens fail v1.

Chris configuration mapping after his implementation update:

| Setting | Value |
| --- | --- |
| `CHRIS_JWT_ALGORITHM` | `HS256` |
| `CHRIS_JWT_VERIFICATION_KEY` | same locally supplied JWT secret |
| `CHRIS_JWT_ISSUER` | `security-sprint1-users` |
| `CHRIS_JWT_AUDIENCE` | `security-sprint1-services` |
| `CHRIS_LOGIN_SUCCESS_ACTION` | `login_success` |
| `CHRIS_LOGIN_FAILURE_ACTION` | `login_failed` |

### 4.2 Current identity

After local token verification, call:

```text
POST {USERS_BASE_URL}/internal/identity/verify
Authorization: Bearer <original user JWT>
X-Service-Name: <actual caller service name>
X-Service-Key: <that service's key>
```

No body. Response:

```json
{"status":"success","data":{"id":12,"role":"security_analyst","account_status":"active"}}
```

Validate this response, including ID equality to token `sub`. Authorize using its
current role. No cache across requests: role/status changes must affect the next
protected request using the same JWT. Deleted/inactive/suspended accounts return
`401`. A healthy current identity with an insufficient role/ownership returns
`403`. An unreachable Users dependency returns `503`; never grant access on error.
Malformed upstream identity responses fail closed with `503` as well.

Canonical roles: `security_administrator`, `security_analyst`,
`regular_employee`, `auditor`. Account states: `active`, `inactive`, `suspended`.
Map old display strings explicitly to permission constants; do not maintain a
second token dictionary or authenticate against copied user rows.

Register nine distinct random keys, one for each service name in section 2,
in the local trusted `SERVICE_TOKENS` configuration. Keys are separate from the
JWT secret and each other. Each process sends only its own service identity.
Identity/Logs/Notifications validate service keys independently of user roles.
An original user JWT does not substitute for an internal service credential.

### 4.3 User and asset references

`GET {USERS_BASE_URL}/internal/users/{id}` uses service name/key, no user JWT:

```json
{"status":"success","data":{"id":12,"role":"security_analyst","account_status":"active","deleted":false}}
```

Unknown user: `404`. New ownership/assignment rejects `deleted=true` or inactive
accounts. Incident assignment also requires `role="security_analyst"`. Historical
audit actors may refer to retained deleted users; do not erase their history.
Caller-facing invalid-reference errors keep that service's documented `400` or
`404` convention; they must not become internal `500` errors.

Chris adds `GET {ASSETS_BASE_URL}/internal/assets/{id}` for registered
`incidents` and `vulnerabilities` callers only, using service name/key:

```json
{"status":"success","data":{"id":7,"name":"Example asset","criticality":"high","owner_id":12}}
```

Unknown asset: `404`. Invalid service credentials: `401`; a different valid
service identity: `403`. Do not expose this lookup through a role-check bypass on
the public Assets endpoint. Preserve public permission/ownership checks and FK
constraints to cover deletion races after successful HTTP lookup.

## 5. Report-source wire contracts

Reports forwards its original administrator/auditor Bearer token to the source
GETs below. It sends the `reports` service credentials when the provider uses
them; the provider still applies the caller's public read permissions.
Reports cannot obtain an administrator token on behalf of an analyst.

| Source | GET path after base URL | Array location | Consumed fields |
| --- | --- | --- | --- |
| Users | `/users` | `body.data`, with `status="success"` | `id` |
| Assets | `/assets` | bare array | `id`, `asset_type`, `criticality`, `status` |
| Incidents | `/incidents` | `body.incidents`, with success status and `count` | `incident_id`, `severity`, `status` |
| Threats | `/threats` | bare array | `id`, `threat_type`, `threat_value`, `description`, `severity`, `source`, `date_added` |
| Logs | `/logs` | `body.data`, with `status="success"` | `id`, nullable `user_id`, `action`, `timestamp`, `severity`, `related_service` |
| Vulnerabilities | `/vulnerabilities` | `body.vulnerabilities`, with success status and `count` | `vulnerability_id`, `severity_level`, `status` |

These lists contain all records visible to the authorized report caller. No
pagination in v1; `count` is the complete array length. No hidden role-based
subset for an administrator/auditor. Users excludes soft-deleted users. Logs
excludes physically deleted logs. Unknown extra record fields can be ignored;
consumed fields, envelopes, allowed enums, IDs and duplicate IDs must be validated.
No passwords, hashes or tokens in a profile/list response.

Consumer bounds: 50,000 records and 5,000,000 response bytes per source. Fail
explicitly on overflow; never silently truncate or use a first page. Changing
these sources to pagination requires a new contract version and full traversal.

Normalization inside Chris's Reports:

- `incident_id` / `vulnerability_id` become internal `id`.
- `severity_level` becomes internal `severity`.
- Karim severities `Low`, `Medium`, `High`, `Critical` map to lower-case values.
- Incident states map exactly: `Open` -> `open`, `Under Investigation` ->
  `under_investigation`, `Mitigated` -> `mitigated`, `Resolved` -> `resolved`,
  `Closed` -> `closed`.
- Vulnerability states map exactly: `Open` -> `open`, `Under Investigation` ->
  `under_investigation`, `In Progress` -> `in_progress`, `Resolved` -> `resolved`,
  `Closed` -> `closed`.
- Logs severities `Information`, `Warning`, `Error`, `Critical` map to
  `information`, `warning`, `error`, `critical`.
- Assets/Threats retain Chris's existing lower-case/snake_case enums.
- Timestamps must include a timezone and represent UTC on output. `Z` and
  equivalent `+00:00` are accepted; do not reject a valid timestamp only because
  the JSON serializer chooses one spelling.

Do not rename Karim's public fields or stored enum strings to achieve this.
Chris implements explicit per-source adapters. Unknown shapes/values fail with
`502`; unavailable dependencies/timeouts return `503`; source `401`/`403`
propagate. Set finite per-call HTTP timeouts, no more than five seconds; avoid
redirecting credentials to a different address. Do not report partial totals.

All six report responses remain Chris's existing bare JSON objects:

| Report suffix after `/reports` | Required result |
| --- | --- |
| `/summary` | `users`, `assets`, literal-Open `open_incidents`, Critical `critical_threats` |
| `/incidents` | `total_incidents`, `incidents_by_severity`, `incidents_by_status` |
| `/assets` | `total_assets`, `critical_assets`, `assets_by_type` |
| `/threats` | `total_threats`, `threats_by_severity`, `threats_by_type`, `recent_threats` |
| `/vulnerabilities` | `total_vulnerabilities`, `vulnerabilities_by_severity`, `vulnerabilities_by_status`, `critical_vulnerabilities` |
| `/activity` | `total_user_activities`, `login_attempts`, `failed_login_attempts`, `most_performed_actions`, `recent_activities` |

Include zero counts for every allowed enum. Asset types: `server`, `workstation`,
`database`, `application`, `network_device`, `cloud_resource`. Threat types:
`ip_address`, `domain`, `file_hash`, `malware_signature`, `other`. Severity buckets:
`low`, `medium`, `high`, `critical`.

Recent lists contain at most 10 records, ordered by UTC timestamp descending,
then ID descending. `recent_threats` contains complete Threat objects;
`recent_activities` contains just the consumed Logs fields above with normalized
severity. Action ranking contains at most 10 `{action,count}` objects, sorted
by count descending then action text ascending. Count login attempts as
`login_success + login_failed`; failures count only `login_failed`. These are
Natalio's actual action names, not Chris's previous dotted defaults.

## 6. Audit transport and durable retry

Use only this automatic ingestion path; public manual `/logs` keeps its existing
administrator-only permissions:

```text
POST {LOGS_BASE_URL}/internal/logs
X-Service-Name: incidents
X-Service-Key: <incidents key>
Idempotency-Key: <stable UUID for this one event>
Content-Type: application/json
```

```json
{"user_id":12,"action":"incident_assigned","description":"Incident 45 assigned to analyst 8.","severity":"Information","related_service":"incidents"}
```

All five body fields are required. `user_id` is a known positive user ID or null
for an unknown actor. `action` matches `[a-z][a-z0-9_]*`, at most 100 characters;
description is nonempty, at most 2000. Severity is exactly `Information`,
`Warning`, `Error`, or `Critical`. `related_service` equals the authenticated
service name. Do not send body `event_id`, `id` or `timestamp`: the UUID is in
the header and Logs creates the ID/ingestion timestamp.

**Concrete bug to fix:** Chris's dotted actions and Karim's human action labels
will be rejected by Natalio's existing regex. Use these transport action codes:

| Trigger | Action |
| --- | --- |
| Asset create/update/delete | `asset_created`, `asset_updated`, `asset_deleted` |
| Threat create/update/delete | `threat_created`, `threat_updated`, `threat_deleted` |
| Incident create/assign/status/note | `incident_created`, `incident_assigned`, `incident_status_updated`, `investigation_note_added` |
| Vulnerability create/update/delete | `vulnerability_created`, `vulnerability_updated`, `vulnerability_deleted` |
| Notification create/delete | `notification_created`, `notification_deleted` |
| Protected authentication/permission denial | `unauthorized_access` |

Natalio keeps his current other action codes, including `login_success` and
`login_failed`. Every required data modification/denial must create an event.
Use the authenticated actor, not a recipient/owner merely affected by the change.
Descriptions must not contain raw bodies, credentials or Authorization headers.

New event: `201` with this envelope (the real Log can contain more fields):

```json
{"status":"success","data":{"event_id":"00000000-0000-4000-8000-000000000001","log":{"id":1},"duplicate":false}}
```

Identical retry: `200`, same `event_id`, `duplicate=true`, same Log. Identical
retry after legitimate log deletion: `200`, `duplicate=true`, `log=null`.
Validate the UUID and receipt envelope; a deleted log does not invalidate its
persisted delivery receipt. Do not require a top-level `id`.

Different payload/source reusing a UUID: `409`, code `IDEMPOTENCY_CONFLICT`,
permanent delivery failure requiring correction. A concurrent identical request
can produce Natalio's generic `409 CONFLICT`; retain/retry the same UUID with
backoff and require the eventual persisted receipt. Do not loop a permanent
payload conflict forever. Credentials/input errors are visible failures, not
silently marked delivered; preserve the original payload for diagnosis.

Save mutation + event in one database transaction. Save denied-access events in
a separate durable transaction. If local event storage fails, fail the business
commit or return `503` for the denial. If only remote Logs is down, keep the
successful mutation and pending event. Never replay the entire business operation
to retry a log. Retry delivery in a worker or explicit flush command after
restart; use finite HTTP timeouts and exponential delays capped at 300 seconds.
Do not hold business transactions open waiting for remote services.

Chris's shared outbox can remain one table, but dispatch each event using its
own `assets`/`threats`/`reports` identity. Map existing pending action/severity
values at the transport boundary; a pending event retains its stable UUID and
identical normalized payload on every delivery attempt. Never change an event
already accepted by Logs under that UUID. Karim adds durable outboxes instead
of swallowing logging errors. Logs handles its own events locally to avoid
recursive ingestion; successful ingestion itself must not generate another log.

## 7. Notifications HTTP contract

Karim implements this additive internal endpoint; it is a new v1 target, not a
claim about his current code:

```text
POST {NOTIFICATIONS_BASE_URL}/internal/notifications
X-Service-Name: incidents
X-Service-Key: <incidents key>
Idempotency-Key: <stable UUID for this one alert>
Content-Type: application/json
```

```json
{"user_id":8,"actor_user_id":12,"title":"Incident assigned","message":"Incident 45 was assigned to you.","notification_type":"Incident Assignment","severity_level":"High"}
```

`user_id` is the recipient. `actor_user_id` is the initiating authenticated actor,
or null if none is known; it is audit metadata, not a new public notification
field. Match the existing Notification model's text validation; both strings must
be nonempty. Severity values are `Low`, `Medium`, `High`, `Critical`. Validate
recipient through Users; it must exist, be active and not deleted. Actor lookup
allows retained historical users. Initial notification status is Karim's
documented unread state; the owner documents its existing exact public spelling
without making Reports depend on that spelling.

Allowed caller/type pairs:

| Caller | Allowed type | v1 automatic trigger |
| --- | --- | --- |
| `incidents` | `Incident Assignment` | Successful assignment, recipient = assigned analyst |
| `vulnerabilities` | `Vulnerability Alert` | New High/Critical vulnerability, recipient = affected asset's owner |
| `threats` | `Threat Alert` | Reserved capability; no unspecified broadcast trigger is required |
| `users`, `playbooks` | `System Notification` | Reserved capability; implement only explicitly defined business triggers |

Other caller/type pairs return `403`; invalid credentials `401`; invalid fields
`400`; unknown recipient `404`; inactive/deleted recipient `409 RECIPIENT_UNAVAILABLE`;
Users outage `503`. Existing public Notifications permissions remain unchanged.

On a new request, atomically create the Notification, its durable receipt and
its audit outbox event; return `201`:

```json
{"status":"success","data":{"event_id":"00000000-0000-4000-8000-000000000002","notification":{"notification_id":1},"duplicate":false}}
```

The notification value may contain the full existing public Notification object.
An identical retry returns `200`, same ID, `duplicate=true`. Receipts persist after
deletion: an identical retry returns notification=null, without recreating it.
Different payload/source under that UUID returns `409 IDEMPOTENCY_CONFLICT`.
Only a first creation emits its creation audit event. Check existing receipts
before revalidating changed/deleted recipients so an exact retry stays safe.

The trigger owner saves notification work with the original business change and
delivers it using its own service key over HTTP, even for Karim's services.
Do not import `services.notifications_db` from another service. Temporary failure
leaves pending work that survives restart; permanent invalid-recipient/conflict
errors remain visible for intervention. Do not roll back/repeat an already
committed incident assignment just because notification delivery is pending.

## 8. Implementation order and exact owner tasks

First apply this specification on each owner's branch and publish the revision
being tested. Do not modify another member's code, merge into main, reset a
database or rename the repository as a side effect of these tasks.

**Natalio — Users, Logs, Playbooks:**

1. Keep the existing PostgreSQL schema, public envelopes, identity/reference
   paths, log receipts and login action names established above.
2. Add the issuer/audience config and required-claim/access-token validation in
   section 4. Register all service identities locally. Validate identity subject
   consistency in consumers; Users itself performs its existing live DB check.
3. Ensure shared clients/outbox delivery validate a successful receipt before
   marking delivered, including UUID match and the deletion retry case.
4. Execute his three-service tests after updates. Publish code/OpenAPI, exact
   launch/migration/flush commands and a secret-free configuration template.
   Do not attempt to implement Chris's/Karim's services in his factory.

**Chris — Assets, Threats, Reports:**

1. Add local v1 JWT validation, current-identity HTTP checks and canonical role
   mapping. Stop requiring JWT `role`/`account_status` claims. Validate new asset
   owners through Users in addition to the existing FK.
2. Add the scoped Assets internal lookup in section 4.3.
3. Implement section 5's source envelopes/field/enum adapters. Use Natalio's actual
   login action names and complete lists; keep existing report response fields.
4. Adapt audit service credentials/path, actions, severities, per-service dispatch
   and receipt validation. Add notification delivery only for a defined trigger;
   the reserved Threat Alert type does not itself specify one.
5. Update tests/Postman and run owned checks. Preserve existing public routes
   pending the stated naming clarification. Publish launch/migrate/flush commands.

**Karim — Incidents, Vulnerabilities, Notifications:**

1. Port SQLite code/DDL to shared PostgreSQL and owned migrations only. Correct
   external FK targets and restrictive asset deletion; preserve his own IDs.
2. Replace opaque in-memory tokens with section 4. Use Users/Assets reference
   APIs rather than cross-owner table queries. Keep public object-level checks.
3. Keep existing response envelopes and Title Case enums in section 5. Return
   complete lists to administrator/auditor. Produce zoned UTC timestamps.
4. Replace direct log-table writes with section 6's durable HTTP outboxes.
5. Implement section 7's internal Notifications endpoint, persistent receipts
   and durable HTTP delivery for both existing automatic triggers.
6. Run each of the three services on its own configured address; keep Flask
   implementation code if desired. Eliminate dependence on one process's token
   dictionary or direct cross-service Python calls.
7. Update tests/Postman. Publish actual code and exact launch/migrate/flush
   commands plus a secret-free configuration template.

Copyable instruction for each member's development assistant:

> Implement team-integration-v1.0.0 from this file for my owned services only.
> Inspect my actual code and the assignment, then execute the owner task list
> and preserve existing data. Use the exact URLs, schemas, action codes,
> authentication, foreign references and delivery semantics in this version.
> Update my tests and Postman requests, run the relevant checks, and report
> executed results and unresolved dependencies. Do not alter another owner's
> files, invent a competing contract, reset databases or merge branches. If an
> assignment requirement conflicts, identify the specific requirement and continue
> independent work. Treat unavailable real dependencies as pending integration;
> fixture responses are never real execution evidence.

## 9. Assembly and release gates

1. Have all owners adopt this exact version and implement section 8. Record each
   branch/commit and publish missing actual code before attempting assembly.
2. Use one new integration database, apply owned migrations in section 3's order,
   bootstrap Users' administrator locally, then start Users, Logs and the other
   seven services. Configure each URL/key consistently; start delivery workers.
3. Obtain real Users-issued administrator, analyst, employee and auditor tokens.
   Use separate test users for role changes/suspension/deletion. Do not include
   credentials/tokens in screenshots or committed Postman environments.
4. Create a nonempty dataset through APIs: several assets/threat types/severities,
   multiple incident/vulnerability statuses, and both successful/failed logins.
   Exercise all nine services' required endpoints and ownership/role rules.
5. Verify asset -> incident -> analyst assignment -> notification -> audit.
   Verify High/Critical vulnerability -> asset-owner notification. Complete both
   lifecycles, reject illegal transitions, nonexistent references and deletion
   of referenced assets. Query actual database constraints/rows as corroboration.
6. Reuse an existing JWT after role/status change and user deletion. Next requests
   must reflect current permissions. Verify missing/invalid/expired/wrong-issuer/
   wrong-audience tokens, invalid service keys and Users outage behavior.
7. Exercise Logs outage/restart and Notifications outage/restart: business changes
   occur once, work persists, recovery delivers once. Test identical retries,
   changed-payload UUID conflicts and exact retries after recipient/log deletion.
   Verify audit actor, service, action, severity and original queued payload.
8. Drain delivery queues and pause writes. Run the companion checker against
   real services. It checks nine readiness/health endpoints, identity, source
   schemas and all six report results. It is a read/reconciliation check, not a
   replacement for the workflow/security/database tests above.
9. Capture real Postman/database screenshots from the verified code/config and
   required full-name captions. If later integration/merging changes behavior,
   rerun affected checks and refresh corresponding evidence.

Checker: `tools/chris/check_team_integration.py` (Python 3.10+, standard library).
It uses a locally supplied `TEAM_ADMIN_TOKEN` and `TEAM_REPORTS_SERVICE_KEY`,
never a generated/fabricated token. Optional URL overrides:
`TEAM_USERS_URL`, `TEAM_ASSETS_URL`, `TEAM_INCIDENTS_URL`, `TEAM_THREATS_URL`,
`TEAM_LOGS_URL`, `TEAM_REPORTS_URL`, `TEAM_VULNERABILITIES_URL`,
`TEAM_NOTIFICATIONS_URL`, `TEAM_PLAYBOOKS_URL`. Include prefixes in the URLs.
Run from the repository root with an installed Python:

```powershell
python tools/chris/check_team_integration.py
```

Exit `0`: these configured live checks passed; `1`: a check failed;
`2`: required local configuration missing/invalid. The checker does not create
users, modify business data or print secrets/raw response bodies. Concurrent
source changes fail the run rather than producing trustworthy-looking totals.
Source and result data must remain unchanged throughout the reconciliation run.

No release gate is marked passed merely because this file exists. The target is
fully specified for the integration boundaries; implementation defects and the
remaining course ambiguities require actual verification rather than a guarantee.

### Verification of the companion tool (19 October 2026)

Executed locally:

```powershell
.\.venv-chris\Scripts\python.exe -m unittest discover -s tests/chris -p test_team_integration_checker.py -v
```

Result: 18 offline unit tests passed. They cover representative envelopes and
counts, unknown values, duplicate IDs, identity mismatch, timestamps/order,
changing sources, incorrect reports, configuration and sanitized HTTP failures.
These test the tool using explicit fixtures; they are not a live team check.
No all-nine-service run or workflow screenshot was produced by this verification.

## Technical references

The issuer/audience settings and HS256 configuration are supported by
[Flask-JWT-Extended configuration](https://flask-jwt-extended.readthedocs.io/en/stable/options.html).
Explicit algorithm allowlists and required-claim validation are described in
[PyJWT's API](https://pyjwt.readthedocs.io/en/stable/api.html).
Foreign-key/deletion behavior is documented in
[PostgreSQL 17 constraints](https://www.postgresql.org/docs/17/ddl-constraints.html).
