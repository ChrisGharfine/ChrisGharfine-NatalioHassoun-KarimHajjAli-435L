# Team integration contract (Natalio Hassoun)

Updated for team-integration-v1.0.0 on 19 October 2026. See TEAM_V1_ROLLOUT.md
for migration/startup steps and the boundary between verified local behavior and
pending nine-service integration. Provider-specific response envelopes are kept;
Chris maps them inside Reports. This package does not force teammates to rename
their public fields or rewrite their list envelopes.

## Ownership and service locations

| Service | Default URL | Owned tables |
|---|---|---|
| Users | http://127.0.0.1:8001 | users, users_audit_outbox |
| Logging | http://127.0.0.1:8005 | logs, log_receipts |
| Playbooks | http://127.0.0.1:8009 | playbooks, response_actions, response_action_history, playbooks_audit_outbox |

Prefix every route, including internal and health routes, with
`/api/natalio-hassoun`. Teammates' own public routes must use their own full names.
These ports are conventions, not assignment requirements.

USERS_URL and LOGS_URL contain only the destination origin; our client appends
API_PREFIX. Chris's full-base URL configuration must instead include Natalio's
prefix. Do not append it twice. Each destination owner's prefix is independent.

Use one shared database/schema design. Other services may reference `users.id`
with foreign keys, but must not query or modify user rows directly from their
application code. Get identity/reference information through these APIs. Do not
create or migrate teammate-owned tables from this package.

## Current identity

POST `http://127.0.0.1:8001/api/natalio-hassoun/internal/identity/verify`

Headers:

```text
Authorization: Bearer <original-user-access-token>
X-Service-Name: incidents
X-Service-Key: <incidents-service-key>
```

No JSON body. A success returns:

```json
{"status":"success","data":{"id":12,"role":"security_analyst","account_status":"active"}}
```

This block is a contract example, not captured execution evidence. Users validates
the JWT locally and loads the current account; deleted/inactive/suspended accounts
return 401. Missing/invalid service keys also return 401. Other services must
verify token signature/expiry first, then use this endpoint for current role and
status. Do not trust a role copied into an old token. If Users is unavailable,
reject protected operations with 503 rather than granting access.

JWT contract: HS256 only; string positive-integer sub through 2147483647;
numeric iat/exp, issuer `security-sprint1-users`, audience
`security-sprint1-services`, and an explicit `type=access`. All six claims are
required on the signed wire token. An optional nbf is also validated. Access
tokens last 1800 seconds. Configure JWT_ENCODE_ISSUER/JWT_DECODE_ISSUER and
JWT_ENCODE_AUDIENCE/JWT_DECODE_AUDIENCE consistently. Old tokens without the v1
claims are rejected; log in again after restarting the updated services.

Shared `verify_access_request()` performs the strict token checks. It deliberately
checks the original signed token as well as Flask-JWT-Extended's normalized
claims, because that library otherwise supplies a missing type claim. The HTTP
identity client validates the success envelope, integer ID equality with sub,
known role, and active status. It rejects malformed identity/reference replies
with 503. Signature validation alone is insufficient for current permissions.

Add each teammate service name and a distinct random key to the team's local
`SERVICE_TOKENS` configuration. Examples: assets, threats, reports, incidents,
vulnerabilities, notifications. Each service sends its own name/key. These keys
are distinct from JWT_SECRET_KEY. Development config currently contains the
trusted registry in each process; restrict per-process key distribution before
any production deployment. Use HTTPS when communicating beyond local development.

Reusable code is in `security_backend/shared/`: `protected`, `call_users`,
`service_auth`, `APIError`, constants, validation, and `log_event`. The complete
factory owns only three services; teammates can use the helpers in their own
factories by registering equivalent JWT callbacks, session lifecycle and error
handling. Set SERVICE_NAME to their actual service name, not users/logs/playbooks.
The supplied outbox helper is specific to these owned tables; teammates should
give each of their services its own outbox or equivalent persistent retry policy.

## User reference validation

GET `/api/natalio-hassoun/internal/users/{id}` on Users with service credentials.
Returns `id`, `role`, `account_status`, `deleted`. No user JWT is required for this
internal lookup. It deliberately includes deleted users so historical audit events
can be ingested after an account deletion. For new assignments/ownership links,
require `deleted=false`; check status/role as appropriate. For example, incident
assignment must verify role `security_analyst`. It returns 404 for an unknown ID.

## Logging

POST `/api/natalio-hassoun/internal/logs` on Logging, with service credentials and
`Idempotency-Key: <UUID retained for this logical event>`.

```json
{
  "user_id": 12,
  "action": "incident_assigned",
  "description": "Incident 45 assigned to analyst 8.",
  "severity": "Information",
  "related_service": "incidents"
}
```

`related_service` must equal the authenticated service name. Known user IDs are
validated through Users; use null if identity is unknown. The Logging Service
creates the ID/time. Success is 201 for a new event or 200 for an identical retry.
Changed payload/source with an existing UUID gives 409. Receipts persist after
log deletion, so an identical retry then returns duplicate=true and log=null.
Concurrent identical submissions may initially return 409 from the unique
constraint; retry with the SAME UUID to obtain the stored receipt.

Call `log_event(payload, event_id)` from the shared HTTP client with service app
configuration. It raises `AUDIT_UNAVAILABLE` on failure; it does not persist the
caller's event itself. Save the event transactionally with your own data and retry
using that UUID. Do not retry a whole non-idempotent business operation merely
because logging is unavailable. Use bounded network timeouts.

`log_event` acknowledges only a 201 new receipt or 200 duplicate receipt whose
success envelope, event UUID, duplicate boolean, and positive log ID are valid.
The explicit duplicate=true/log=null deletion case is acknowledged as delivered.
202, redirects and malformed/wrong-event receipts remain pending. Calls disable
redirects and ambient proxy configuration. SERVICE_TIMEOUT must be in (0,5].

Payload/credential rejection blocks the event with AUDIT_REJECTED; a permanent
409 IDEMPOTENCY_CONFLICT blocks it with AUDIT_IDEMPOTENCY_CONFLICT. Generic 409
concurrency conflicts, network failures and temporary service failures retry the
same UUID/payload. Retry delays are 2,4,8,... seconds capped at 300; next_attempt_at,
attempts and blocked state persist in the originating outbox. Permanently blocked
events do not stop other due work. Temporary dependency failure stops that batch
after scheduling the failed row, bounding outage latency; the next flush can
process other due rows. No timer/worker is installed automatically: mutations try
up to 10 due events, and `flush-audit` processes a due batch of up to 100.
Invoke it periodically for eventual delivery after recovery. Pending counts
include future-scheduled and blocked records, so exit 1 does not mean data loss.
After fixing a permanent failure, use `flush-audit <service> --retry-blocked` to
requeue the unchanged event. Never rewrite an accepted event's UUID/payload.

Required event sources: Users handles login/user/role events; every service must
record denied access and data modifications. Logging handles its own denied
access/deletion locally to avoid recursively calling itself. Do not log successful
internal log ingestion as another event. Do not pass raw request bodies, passwords
or Authorization headers to the logging client.

## Values and boundaries

Roles: security_administrator, security_analyst, regular_employee, auditor.
Account status: active, inactive, suspended.
Log severity: Information, Warning, Error, Critical.
Playbook severity: Low, Medium, High, Critical.
Action status: Pending, In Progress, Completed.
All timestamps use zoned ISO 8601 UTC strings ending in Z. User IDs are integers;
JWT subject identities are their string representation. Username/email comparison
is normalized to lowercase. Successful login is the only endpoint that deliberately
returns an access token; profile APIs never return passwords/hashes/tokens.

Regular employees' ownership restrictions belong in each resource service in
addition to role checks. For example, an employee must not retrieve someone else's
incident just because both have the same role.

Reports can use administrator/auditor JWTs with GET /users and GET /logs for their
user/activity sources. No report-generation endpoints are implemented here.

## Integration acceptance checks

1. Login once through Users and use that token on a teammate service.
2. Change the role/status and verify the existing token's permissions change.
3. Trigger a mutation/denial in that service; verify the audit log via Logging.
4. Make Logging unreachable, confirm events persist, restore it and retry once.
5. Delete a referenced user through Users; preserve historical FKs and deny access.
6. Run the full team incident-assignment/notification workflow separately; it is
   not implemented or claimed as tested in this Student 1 package.
