# Running the Sprint I services (Chris Gharfine)

Chris's three services implement the 18 prescribed endpoints for Assets, Threat
Intelligence, and Reports. They use FastAPI, SQLAlchemy, PostgreSQL, Alembic,
Pydantic, shared JWT verification, and HTTPX. They do not implement another
student's service or issue authentication tokens. The user approved this baseline;
Chris's boundaries now implement [team-integration-v1.0.0](TEAM_INTEGRATION_V1.md).
The real nine-service release gates remain separate from the owned tests; see
[integration-contracts.md](integration-contracts.md) for current dependencies.

## Files and responsibilities (Chris Gharfine)

| Location | Responsibility |
| --- | --- |
| `services/assets` | Asset schemas, model, repository-backed operations, and six routes |
| `services/threats` | Threat schemas/normalization, model, operations, and six routes |
| `services/reports` | Six HTTP aggregation routes and validated source contracts |
| `services/chris_support` | Chris-owned JWT/error/database/audit adapters and migration runner |
| `tests/chris` | Validation, role matrix, PostgreSQL, concurrency, audit, HTTP, and collection tests |
| `postman/chris-sprint1.postman_collection.json` | 31 request templates: all 18 endpoints, negatives and internal Assets checks; no saved responses/tokens/keys |
| `compose.chris.yaml` | Chris's runtime containers; optional local database and audit worker |

## Configuration and authentication

Use Python 3.12 and install `tests/chris/requirements.txt` for development, or
`requirements-chris.txt` for runtime only. On Windows, with your Python executable:

```powershell
python -m venv .venv-chris
.\.venv-chris\Scripts\python.exe -m pip install -r tests/chris/requirements.txt
```

If `python` is unavailable, use the Python executable configured in Codex or
install your team's approved Python runtime. In this session, the bundled Codex
Python created the virtual environment. The runtime directory and environment
files are ignored; no credentials are stored in tracked configuration.

Set process environment variables using the team's actual connection and issuer
configuration. A secret-free template is in
[configuration.example.env](configuration.example.env). Python reads process
environment; it does not load that template automatically. The following are
prompts/templates, not working credentials:

```powershell
$env:CHRIS_DATABASE_URL = Read-Host 'Approved postgresql+psycopg connection URL'
$env:CHRIS_JWT_VERIFICATION_KEY = Read-Host 'Locally supplied shared JWT secret (at least 32 bytes)'
$env:CHRIS_JWT_ALGORITHM = 'HS256'
$env:CHRIS_JWT_ISSUER = 'security-sprint1-users'
$env:CHRIS_JWT_AUDIENCE = 'security-sprint1-services'
$env:CHRIS_SERVICE_TOKENS = Read-Host 'JSON mapping of required service names to distinct registered keys'
```

Only HS256 is accepted. Required claims: text positive user ID `sub` through
2147483647, numeric `iat`/`exp`, configured `iss`/`aud`, and `type="access"`.
Any `nbf` is validated; unsigned/other-algorithm/refresh tokens are rejected.
JWT `role` and `account_status` are optional and never authorize a request.

After local verification, every protected request calls Users'
`POST /internal/identity/verify` with the original Bearer token and that resource
service's `X-Service-Name`/`X-Service-Key`. The returned ID must match `sub`.
Current roles are `security_administrator`, `security_analyst`,
`regular_employee`, `auditor`. Inactive/deleted/suspended accounts are denied
with `401`; permission failures return `403`; unavailable/malformed Users data
fails closed with `503`. No cross-request identity cache is used.

Service keys are distinct printable ASCII secrets of at least 32 bytes, separate
from the JWT secret. Configure only the keys required by each process: Assets
needs its own key and the accepted `incidents`/`vulnerabilities` inbound keys;
Threats needs `threats`; Reports needs `reports`; a combined audit worker needs
`assets`, `threats`, `reports`. Register matching identities in the real providers.
Never share populated configuration or use the old audit Bearer token setting.

## Database and migration order

All services share the approved PostgreSQL database for actual foreign keys,
while each student owns their tables. Chris's migrations create only `threats`,
`assets`, `chris_audit_outbox`, and `chris_alembic_version`. SQLAlchemy's `users`
metadata reference represents an external table; production code never creates it.
Do not call `Base.metadata.create_all()` against the shared database.

1. Run Natalio's actual Users migrations, with `users.id` an integer primary key.
2. Run Chris's migrations:

```powershell
.\.venv-chris\Scripts\python.exe -m alembic -c services/chris_support/alembic.ini upgrade head
```

3. Karim's Incident/Vulnerability migrations can then reference `assets.id`.

If Users is not ready, `upgrade chris_0001` installs only Threats and the outbox.
`upgrade head` refuses to create Assets without the required real Users table.
Reports need the outbox for durable denied-access logging. Migrations require only
`CHRIS_DATABASE_URL`; they do not require a JWT key. Existing Users rows are not
modified. `chris_alembic_version` avoids collision with another student's runner.
The additive `chris_0003` migration adds `transport_payload` and `failed_at` for
delivery snapshots/permanent failures. It preserves existing row IDs, original
event data and delivered records. Always upgrade existing Chris deployments to
head before starting the updated apps/worker; do not reset the database.

Assets have a restrictive owner foreign key. Incidents and Vulnerabilities must
also use restrictive asset foreign keys. A referenced asset cannot be deleted;
the API returns `409` instead of deleting another student's records. Department
is a validated asset field; the assignment does not mandate a Department table.

## Starting the services

Use separate Codex terminal tabs/processes with the same approved environment:

```powershell
.\.venv-chris\Scripts\python.exe -m uvicorn services.assets.main:app --port 8002
.\.venv-chris\Scripts\python.exe -m uvicorn services.threats.main:app --port 8004
.\.venv-chris\Scripts\python.exe -m uvicorn services.reports.main:app --port 8006
```

For the coordinated private-env commands, see ../team/SETUP.md.

Each command runs in the foreground. Each service provides `/docs`, `/openapi.json`, `/health` liveness and `/ready`
database/schema readiness under `/api/chris-gharfine`.
Reports checks source availability when a report is requested, not during its
readiness probe. Bind explicitly to an appropriate interface for the deployment.

Reports uses configurable source base URLs: `CHRIS_USERS_URL`, `CHRIS_ASSETS_URL`,
`CHRIS_INCIDENTS_URL`, `CHRIS_THREATS_URL`, `CHRIS_AUDIT_URL`, and
`CHRIS_VULNERABILITIES_URL`. For local processes, set Assets to
`http://127.0.0.1:8002/api/chris-gharfine` and Threats to
`http://127.0.0.1:8004/api/chris-gharfine`, plus the actual URLs
of the other students' services. Host-run defaults are the exact v1 ports, with
the destination owner prefix included once in every service URL. Compose uses its
own service DNS names on port 8000 for Chris and host.docker.internal defaults
for teammates running on host ports; override these for the actual team network.

For containers, set the same environment with a database URL reachable inside
Docker, then run:

```powershell
docker compose -f compose.chris.yaml build
docker compose -f compose.chris.yaml run --rm migrate
docker compose -f compose.chris.yaml up -d assets threats reports
```

The optional `database` profile starts a local PostgreSQL instance. Set a nonempty
`CHRIS_POSTGRES_PASSWORD` first, then use
`docker compose -f compose.chris.yaml --profile database up -d postgres`.
Run Natalio's migration before Chris's Assets migration. Inside this Compose
network its host is `postgres:5432`; its optional host port defaults to 5433.
The volume retains data. The Compose file includes only Chris's runtime; join
the team's services to the agreed network or supply reachable service URLs.

## Asset API contract (Chris Gharfine)

| Field | Contract |
| --- | --- |
| `id` | Generated positive 64-bit integer; read only |
| `name` | Required, trimmed, nonempty, up to 200 characters |
| `asset_type` | Required: `server`, `workstation`, `database`, `application`, `network_device`, `cloud_resource` |
| `ip_address` | Required textual IPv4/IPv6; canonicalized; no zone/scope identifier |
| `owner_id` | Required positive integer referencing existing `users.id`; strings/booleans rejected |
| `department` | Required, trimmed, nonempty, up to 200 characters |
| `criticality` | Required: `low`, `medium`, `high`, `critical` |
| `status` | `active` (creation default), `inactive`, `under_maintenance` |
| `operating_system`, `location` | Optional, nullable strings; if present, nonempty and up to 200 characters |

| Method and path | Request/result | Roles |
| --- | --- | --- |
| `POST /assets` | Required fields above; `201` complete asset object | Administrator |
| `PUT /assets/{id}` | Any supplied editable fields; `200` complete updated object | Administrator |
| `DELETE /assets/{id}` | `204` empty body; missing ID `404`, referenced asset `409` | Administrator |
| `GET /assets` | `200` complete array, ordered by ID | Administrator, Auditor |
| `GET /assets/{id}` | `200` complete object; missing ID `404` | Administrator, Analyst, Auditor |
| `GET /assets/search` | `200` filtered array | Administrator, Analyst, Auditor |
| `GET /internal/assets/{id}` | `200` success/data with id, name, criticality, owner_id; missing ID `404` | Incidents/Vulnerabilities service keys only |

Search query parameters: `name`, `asset_type`, `ip_address`, `department`,
`criticality`, and `status`. Combine supplied filters using AND. Name/department
use case-insensitive literal substring matching; `%` and `_` are escaped. Other
fields are exact matches after IP normalization. At least one criterion is
required, so an empty analyst search does not bypass list permissions.
Creation and an actual owner change also call Users' service-authenticated
`GET /internal/users/{id}`. Unknown owner returns `404`; deleted/inactive owner
returns `400`; invalid/unavailable Users data returns `503`. Existing FKs remain
the race-condition guard. Internal Assets lookups do not accept a user JWT as a
replacement for service credentials; invalid keys return `401`, other registered
services return `403`, and denials are durably audited.

## Threat API contract (Chris Gharfine)

| Field | Contract |
| --- | --- |
| `id`, `date_added` | Generated ID and timezone-aware UTC creation time; read only |
| `threat_type` | Required: `ip_address`, `domain`, `file_hash`, `malware_signature`, `other` |
| `threat_value` | Required, trimmed, nonempty, at most 512 characters |
| `description` | Required, trimmed, nonempty, at most 5000 characters |
| `severity` | Required: `low`, `medium`, `high`, `critical` |
| `source` | Required, trimmed, nonempty, at most 200 characters |

IP values are canonicalized and cannot contain zone identifiers. Domains must be
fully qualified, are normalized with IDNA, lowercased, and may have one final
root dot removed. URLs, IPs supplied as domains, invalid labels, and multiple
trailing dots are rejected. File hashes accept hexadecimal MD5/SHA-1/SHA-256/
SHA-512 digest lengths and normalize to lowercase. Signature/other values retain
case after trimming. The 512-character limit also bounds the composite index size
for multibyte text. PostgreSQL enforces unique normalized type/value pairs.

| Method and path | Request/result | Roles |
| --- | --- | --- |
| `POST /threats` | Required fields above; `201` complete object; duplicate `409` | Administrator |
| `PUT /threats/{id}` | Description/severity/source only; `200` complete updated object | Administrator |
| `DELETE /threats/{id}` | `204` empty body | Administrator |
| `GET /threats` | `200` complete array, ordered by ID | Administrator, Analyst, Auditor |
| `GET /threats/{id}` | `200` complete object; missing ID `404` | Administrator, Analyst, Auditor |
| `GET /threats/search` | `200` filtered array | Administrator, Analyst |

Search parameters: `threat_type`, `threat_value`, `severity`, `source`. At least
one is required. Type/severity match exactly; value/source use case-insensitive
literal substring matching. When both type and value are supplied, apply that
type's indicator validation/normalization before matching. Auditor search remains
denied under the narrower Service 4 table until the professor clarifies the
conflicting general role list. Threat type/value are immutable through PUT.

For both services, PUT updates only supplied fields and requires at least one;
required fields cannot become null. Unknown body fields, invalid IDs/enums,
empty strings, and prohibited control characters return `400`. No dynamic SQL is
built from input; ORM filters use bound parameters.

## Reports and error responses (Chris Gharfine)

All six `/reports/*` endpoints require Administrator or Auditor. They return
objects containing the fields in [requirements.md](requirements.md), using the
source contracts in [integration-contracts.md](integration-contracts.md).
Distributions include every supported enum value, including zero counts. Summary
uses exactly `users`, `assets`, `open_incidents`, `critical_threats`; `open` means
the literal `open` incident state. Activity also returns recent activity records.
Recent lists default to ten records, descending timestamp then ID; configure
`CHRIS_RECENT_LIMIT`. Most-performed actions sort by count descending, then name.

Errors contain `status: "error"` and `message`; validation errors additionally
contain `details` with location/message/type, without echoing raw submitted data.
Missing/invalid authentication returns `401` with `WWW-Authenticate: Bearer`;
insufficient role `403`; missing resources `404`; conflicts `409`; input errors
`400`; malformed upstream data `502`; unavailable dependencies/database `503`;
unexpected internal failures `500`. Upstream `401`/`403` is preserved. No source
URL, bearer token, connection string, SQL, or raw upstream body is returned.

## Audit delivery and tests (Chris Gharfine)

Successful asset/threat mutations write an outbox event in the same transaction.
If the event cannot persist, the business mutation rolls back. Authentication
and role denials persist their own events before returning. If that persistence
fails, the request fails closed with `503`. Auth failures have unknown `user_id`.
Events do not contain submitted bodies, query strings, or bearer tokens.

Run the separate delivery worker with the locally registered per-service keys:

```powershell
.\.venv-chris\Scripts\python.exe -m services.chris_support.audit_worker
```

Use `--once` for one batch, or the Compose `audit` profile for a persistent worker.
PostgreSQL row locking with `SKIP LOCKED` permits concurrent workers. Failed
deliveries caused by outages remain pending with bounded exponential backoff.
The worker posts to Audit `/internal/logs` with the matching originating service
identity, stable UUID Idempotency-Key and five canonical fields. Old pending
dotted actions/lower severities are mapped explicitly and snapshotted before
network delivery. Original columns/UUIDs remain unchanged; retries reuse the
frozen payload, including after an acknowledgment transaction fails.

Receipts must match the UUID: `201` new/duplicate=false, `200` retry/duplicate=true.
A retry receipt with log=null after legitimate deletion also succeeds. Invalid
acknowledgments stay pending. Permanent input/credential failures set failed_at;
IDEMPOTENCY_CONFLICT never loops forever. `--once` prints queue counts and exits
nonzero while pending or failed work remains. After correcting credentials/input,
explicitly requeue that service's recoverable failures:

```powershell
.\.venv-chris\Scripts\python.exe -m services.chris_support.audit_worker --retry-failed --service assets --once
```

Use threats/reports for their queues. UUID conflicts/invalid local payloads require
operator review and are not automatically requeued. No whole business operation
is replayed to recover logging. The current live verification scope is recorded
in [verification.md](verification.md).

To run all tests with a disposable PostgreSQL container and automatic cleanup:

```powershell
.\tools\chris\run_tests.ps1
```

Use `-UnitOnly` to run validation/auth/report/collection tests without Docker.
For an existing dedicated test database, set `CHRIS_TEST_DATABASE_URL` with a
database name beginning `chris_test`, then run
`.\.venv-chris\Scripts\python.exe -m pytest tests/chris -q`.
Database tests use random schemas and an explicitly labeled external Users test
double; they never create a production Users implementation. If no test database
is configured, database-dependent tests skip rather than claim to pass. Windows
sandbox restrictions may require Codex approval for asyncio's loopback sockets.

Import the Postman collection and set its real role tokens and internal service
keys locally. Set
`asset_owner_id` to an actual Users ID and use a disposable demonstration dataset.
Creation requests capture the actual returned IDs. Run report evidence requests
before deleting demonstration rows, or create additional real data. Never export
populated token variables. Use the [evidence checklist](evidence-checklist.md) for
the real Postman/database screenshots and common report.

## Technical references

- [FastAPI dependency overrides for tests](https://fastapi.tiangolo.com/advanced/testing-dependencies/)
- [SQLAlchemy foreign keys and uniqueness constraints](https://docs.sqlalchemy.org/en/20/core/constraints.html)
- [PyJWT verification API](https://pyjwt.readthedocs.io/en/latest/api.html)

AI assistance was used to extract requirements, implement Chris's services,
prepare tests/documentation, and diagnose execution issues. Chris must review,
understand, and disclose that use in the common report and resolve compliance
with the course's restrictions before submission.
