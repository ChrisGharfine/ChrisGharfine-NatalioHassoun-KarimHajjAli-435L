# Team integration contract (Natalio Hassoun)

## Ownership and service locations

| Service | Default URL | Owned tables |
|---|---|---|
| Users | http://127.0.0.1:8001 | users, users_audit_outbox |
| Logging | http://127.0.0.1:8005 | logs, log_receipts |
| Playbooks | http://127.0.0.1:8009 | playbooks, response_actions, response_action_history, playbooks_audit_outbox |

Prefix every route, including internal and health routes, with
`/api/natalio-hassoun`. Teammates' own public routes must use their own full names.
These ports are conventions, not assignment requirements.

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
