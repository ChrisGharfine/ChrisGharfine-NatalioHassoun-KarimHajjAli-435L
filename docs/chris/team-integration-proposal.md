# Team integration proposal for review

**Superseded: use [TEAM_INTEGRATION_V1.md](TEAM_INTEGRATION_V1.md).** Chris asked
for a concrete implementation target; that version makes the decisions and
includes exact schemas, owner instructions and a companion verification tool.
The draft below is retained as history. Its missing-Natalio-information items
were subsequently resolved by inspecting his published source code.

**Status: DRAFT — not an approved team contract. Prepared 19 October 2026.**

Chris, Natalio and Karim should approve the decisions below together before
changing shared interfaces. Approval of Chris's earlier baseline covered Chris's
work; it did not establish agreement by the other two members.

This proposal compares Chris's [current integration contract](integration-contracts.md),
Natalio's `INTEGRATION.md`, and Karim's `integration-contracts-karim.md`.
Descriptions of Natalio's and Karim's implementations come from their documents;
their source code and execution have not been independently checked here.
No application code, database, existing contract or Git branch was changed to
adopt these proposals.

## Decisions for all three members

| Decision | Recommended agreement | Work required / unresolved detail |
| --- | --- | --- |
| D1. Database | One shared PostgreSQL database, with migrations owned by the owner of each table. | Chris already targets PostgreSQL. Karim must port SQLite SQL/storage. Natalio must confirm his actual engine and migration setup. The assignment does not itself establish PostgreSQL as the required engine. |
| D2. Identity | Natalio issues JWTs. Every resource service verifies the token locally, then obtains the current account/role through Natalio's identity API. | Karim replaces in-memory tokens. Chris adds live identity verification and reconciles claim requirements. Natalio supplies the exact JWT algorithm, verification configuration, issuer, audience, required claims and working examples. |
| D3. Foreign references | Use `users.id` and `assets.id` as the referenced keys. Karim's own incident/vulnerability primary key names can remain unchanged. Use `ON DELETE RESTRICT` for both asset references. | Karim changes references currently targeting `users.user_id` / `assets.asset_id`. Confirm compatible integer types. An incident's nullable `asset_id` does not require deleting its asset to clear it; vulnerability `asset_id` remains required. Confirm the incident-nullability interpretation against the assignment. |
| D4. Routing | Publish exact URLs for each service and settle the full-student-name prefix requirement once. | Natalio currently uses `/api/natalio-hassoun`; Chris and Karim currently document unprefixed resource paths. Full-name prefixes with the prescribed resource suffixes are a candidate, pending the team's assignment clarification. Do not silently change routes. |
| D5. Response formats | Keep each provider's documented response shape and add explicit consumer adapters. | Chris accepts Karim's known envelopes, ID names and enum values in Reports. Natalio supplies exact Users/Logs list responses, including pagination. No need to rename every database column or public field. |
| D6. Audit delivery | Use Natalio's internal HTTP ingestion, service credentials, stable event UUIDs and durable caller outboxes. | Chris adapts its existing worker; Karim replaces direct log-table writes and best-effort logging. Natalio supplies complete acknowledgment schemas and confirms action names. |
| D7. Notifications | Call Notifications through an agreed HTTP interface, with durable retry and duplicate protection for generated alerts. | Karim provides a service-authenticated contract. All consumers replace Python imports across service boundaries. Keep existing public endpoint permissions. |
| D8. Dates and permissions | Use timezone-aware UTC timestamps and an explicit endpoint/ownership permission matrix. | Karim fixes new timestamp generation and plans conversion of existing values. Resolve analyst incident listing and auditor threat-search ambiguities with the professor before claiming assignment compliance. |

Flask and FastAPI can remain in their respective services. A framework rewrite
is not needed to agree HTTP request/response contracts. Deployment must still
meet the assignment's independent-service and API communication requirements.

## Database and ownership

- Natalio owns Users, Logging and Playbooks tables/migrations.
- Chris owns Assets, Threats and Chris's audit outbox/migrations.
- Karim owns Incidents, Investigation Notes, Vulnerabilities, Notifications and
  any outboxes he introduces for those services.
- Karim's current all-tables `schema.sql` must not create or replace the other
  members' tables in the integrated environment.
- Apply Users before Assets, then tables referencing either. Order the remaining
  migrations from their actual foreign-key dependencies, after inspecting code.
  Give each owner's migration history a distinct name if using one schema.
- Keep database foreign keys for integrity. Obtain another service's business
  data through its API rather than querying its tables from application code.
- User deletion must preserve historical references. Natalio must demonstrate
  the documented deleted-account behavior and agree its database policy with
  all referencing services.

Preserve existing databases. Do not reset, delete or reseed them as an automatic
part of this agreement. Use a new disposable integration database for initial
testing, or review forward migrations and a backup/data-transfer plan. If moving
existing SQLite data, preserve identifiers and verify generated IDs afterward.

PostgreSQL documents the distinction between primary keys, foreign keys and
deletion behavior in its [constraint documentation](https://www.postgresql.org/docs/17/ddl-constraints.html).
Inspect generated migrations: Alembic describes autogeneration as producing
candidate migrations requiring review in its [autogeneration documentation](https://alembic.sqlalchemy.org/en/latest/autogenerate.html).

## Identity and user lookups

Use Natalio's proposed current-identity endpoint:

`POST {USERS_BASE_URL}/internal/identity/verify`

Here `USERS_BASE_URL` includes Natalio's agreed prefix. Send the original user's
Bearer token plus the caller's `X-Service-Name` and `X-Service-Key`. Each service
uses its own key, separate from the JWT signing/verification configuration.
Keep secrets in local configuration, outside Git and shared screenshots.

After local signature/expiry validation, validate the identity response and
match its user ID to the token subject. Authorize using the returned current
role/status. Do not continue using stale role/status claims from the token.
Users being unreachable must fail protected operations with `503`.

Recommended role values are Natalio's `security_administrator`,
`security_analyst`, `regular_employee`, and `auditor`. Chris and Karim should map
these explicitly to their permission checks and separately enforce ownership.
Do not assume Natalio's JWT contains Chris's currently required `role` and
`account_status` claims; agree the actual claim set first.

Use Natalio's service-authenticated `GET /internal/users/{id}` for user reference
validation. For new ownership/assignment links, reject deleted users and check
status/role as required. Historical audit actors can refer to deleted users.
Karim also needs an agreed Assets lookup over HTTP exposing the asset's actual
`id`, `name`, `criticality` and `owner_id`. Chris owns that implementation.
If ordinary caller permissions cannot authorize a required internal lookup,
agree a narrowly scoped internal endpoint rather than broadening public access.

## Reports: preserve provider formats, map at the boundary

Chris should add explicit adapters for these documented Karim responses:

| Provider response | Reports' internal representation |
| --- | --- |
| `GET /incidents`: `incidents` array within the success envelope | Incident records |
| `incident_id` | `id` |
| Incident `severity` such as `Critical` | `severity` such as `critical` |
| Incident `status` such as `Under Investigation` | `status` such as `under_investigation` |
| `GET /vulnerabilities`: `vulnerabilities` array within the success envelope | Vulnerability records |
| `vulnerability_id` | `id` |
| Vulnerability `severity_level` such as `High` | `severity` such as `high` |
| Vulnerability `status` such as `In Progress` | `status` such as `in_progress` |

Use exact allowed-value mappings, not arbitrary case conversion. Validate the
envelope, complete list, unique positive IDs and consumed fields. Derive report
counts from records; do not trust auxiliary `count_by_*` summaries. Agree whether
`count` means the total or the current page. If pagination exists, traverse it
fully under defined bounds or fail explicitly; never count only the first page.

Natalio still needs to provide actual schemas/examples for `GET /users` and
`GET /logs`: record ID fields, envelopes, timestamps, pagination, access rules
and the exact login-success/login-failure action values. The sample audit action
`incident_assigned` does not define login actions. Chris's current defaults are
not evidence that Natalio uses them.

Karim can keep Title Case lifecycle values in his API and stored data if the
team approves these adapters. Reports can keep its internal snake_case values.
Do not rewrite existing records solely to make every service spell enums alike.

All new cross-service timestamp values should be zoned UTC ISO 8601 ending in
`Z`. Convert existing naive timestamps using their known original timezone;
adding `Z` without conversion can change their meaning.

## Audit: align the transport and acknowledgment

Adopt Natalio's proposed `POST {LOGGING_BASE_URL}/internal/logs`, with:

- `X-Service-Name` and that service's `X-Service-Key`.
- `Idempotency-Key` set to the same UUID for every retry of one logical event.
- Body fields `user_id`, `action`, `description`, `severity`, `related_service`.
- `related_service` equal to the authenticated machine service name, such as
  `assets` or `incidents`; do not send human display labels here.
- Log severities exactly `Information`, `Warning`, `Error`, `Critical`.

Chris must replace the worker's service Bearer authentication and its currently
assumed flat positive-`id` acknowledgment. Its shared outbox requires delivery
using the matching service's credentials for each event. Karim must replace
direct `logs` writes with transactionally persisted events and HTTP delivery.
Every required mutation and denied request must create a durable audit event;
printing and dropping a failed log is insufficient.

Natalio's documented log timestamp is ingestion time. Preserve original event
time locally in the outbox. Chris's extra body `event_id` and `timestamp` fields
must not be sent unless Natalio explicitly adds them to the contract.

Before implementation, Natalio must publish complete JSON acknowledgments for:

1. New event (`201`).
2. Identical retry (`200`).
3. Identical retry after log deletion (`duplicate=true`, `log=null`).
4. UUID reused with a different payload/source (`409`).

Accept a valid persisted receipt even when its log was subsequently deleted.
Handle the documented concurrent-identical `409` by bounded retry of the same
UUID; flag a permanent payload conflict instead of retrying forever. Never
generate a fresh UUID or replay a whole business mutation to recover delivery.

## Notifications: remove the in-process dependency

Karim's `send_notification()` helper is an implementation detail inside his app.
Chris and Natalio need an HTTP contract rather than importing that module.

Karim should propose the exact endpoint, service authentication, request fields,
acknowledgments, allowed caller/type combinations and idempotency behavior.
An internal endpoint is a candidate; it has not been approved or implemented.
Do not forward an analyst token to an administrator-only public creation route
and assume it will succeed.

Retain the documented triggers: incident assignment notifies its analyst;
creation of a High/Critical vulnerability notifies its asset owner. Define any
additional Threat Alert or System Notification trigger and recipient explicitly
before wiring it. Reserving a type name alone does not define a trigger.

Persist generated notification work with the triggering change, then deliver
with bounded retry. A temporary Notifications outage should leave pending work
that can recover without replaying the incident/vulnerability operation or
creating duplicate notifications.

## Implementation responsibilities after team approval

| Owner | Changes in that owner's branch |
| --- | --- |
| Natalio | Confirm database/migration compatibility; publish JWT and list-response schemas, audit acknowledgments and login action values; register service identities; verify deleted-user and retry behavior. |
| Chris | Add current-identity checks and role mapping; agree Assets reference lookup; adapt Reports to provider schemas; adapt audit transport, per-service credentials and receipt handling; connect agreed notification triggers; update tests/Postman. |
| Karim | Port storage/migrations if PostgreSQL is accepted; reference `users.id` / `assets.id`; replace placeholder authentication, cross-owner queries and direct logging; expose Notifications HTTP contract and persistent delivery; fix UTC timestamps; update tests/Postman. |
| All three | Review exact routes, permissions and migrations; approve one canonical contract revision; provide actual code/OpenAPI and service configuration; integrate and test together. |

After agreement, publish one canonical contract in the repository at a path
chosen by the team. Record the approved revision/commit. Each owner then updates
their own branch against that revision. Earlier individual documents should link
to it and identify remaining implementation gaps instead of competing as the
authority. Do not merge branches or alter shared architecture merely by sharing
this draft with another AI.

## Acceptance checks before calling the system integrated

Run against all nine actual services in one configured environment, using
Natalio-issued tokens and a dedicated integration database:

1. Apply owned migrations in dependency order; inspect real PK/FK constraints.
2. Log in once and call each protected service. Exercise every role, ownership
   restriction, invalid/expired token, role change and account suspension.
   Confirm Users outages fail closed. Check historical references after deletion.
3. Create an asset, report an incident against it, assign an analyst and retrieve
   the analyst's generated notification. Advance the full incident lifecycle;
   reject forbidden transitions and invalid user/asset references.
4. Create a High/Critical vulnerability against that asset, verify its owner's
   notification and exercise its lifecycle. Confirm referenced-asset deletion
   is rejected by the agreed constraint/API behavior.
5. Exercise Threats and Playbooks/Response workflows and their required audit
   events. Exercise additional notification triggers only once agreed.
6. Trigger a mutation and a denied request in every service. Verify real Logging
   entries. Stop Logging, verify persistent queued events, restore it and confirm
   delivery without duplicate business changes or duplicate audit events.
   Test identical delivery, receipt-after-deletion and conflicting UUID cases.
7. Interrupt Notifications and verify pending generated alerts recover once
   without duplicate notifications.
8. Run all six reports with the agreed administrator/auditor access. Reconcile
   their results against actual source records and database queries, including
   login action counts and complete paginated lists if applicable.
9. Run the complete Postman/API permission and validation checks against this
   integrated version. Capture actual responses and database screenshots with
   required full-name captions. Record the code/contract revisions being tested.

Individual passing tests do not establish interoperability: Chris's earlier
213 checks and Karim's reported 117 checks exercise different contracts.
Update those checks and add real integration checks. Capture final submission
evidence against the agreed final code; rerun affected checks if a merge changes
it. A merge itself does not prove the system works.

## Approval and missing information

- [ ] Chris approves D1–D8, including the changes to his existing adapters/auth.
- [ ] Natalio approves D1–D8 and provides his database, JWT and response details.
- [ ] Karim approves D1–D8 and provides the Notifications HTTP contract.
- [ ] Team resolves route/name and role-permission assignment ambiguities.
- [ ] Team records the canonical contract revision and integration configuration.
- [ ] Owners implement their changes and all acceptance checks pass.

All boxes remain unchecked. This draft does not authorize database resets,
repository renaming, modification of another member's implementation, or merges.
