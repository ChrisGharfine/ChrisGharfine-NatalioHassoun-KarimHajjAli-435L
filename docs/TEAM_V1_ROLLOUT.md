# Natalio Hassoun — team v1 implementation and rollout

Target: team-integration-v1.0.0 supplied by Chris on 19 October 2026. This update
implements Natalio's owner tasks only. Chris/Karim still own their six services;
this package neither implements them nor proves all-nine-service integration.

## What changed

- JWT encode/decode issuer/audience wiring, strict signed required claims and
  HS256 access-token validation shared by Users, Logs and Playbooks. No role or
  account-status token claims are needed; live identity remains authoritative.
- Strict identity/reference response validation including subject equality;
  malformed dependencies fail closed. Service-key rejection is an identity
  dependency/configuration failure, not an invitation to bypass authentication.
- Audit receipt verification before marking delivery: status, success envelope,
  UUID, boolean duplicate and log ID, including a deleted duplicate with log=null.
- Persistent exponential retry metadata, skipping permanently blocked events,
  and explicit recovery for rejected deliveries. A temporary dependency failure
  stops that batch after scheduling the failed row to bound outage latency. No automatic
  scheduler is installed; use the existing flush command periodically.
- Additive migration 002; nine service-key placeholders; regenerated Postman
  collection and three OpenAPI exports. Public routes/envelopes/roles/enums,
  receipt retention and soft deletion stay compatible with the agreed v1 target.

## Upgrade an existing checkout

Run commands from the Student 1 repository in PowerShell with its virtual
environment. Use your own configured database. Preserve the private .env;
do not overwrite it with the placeholder template.

1. Update code/dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

2. Add/confirm the following in the private .env on every relevant service:

```text
JWT_ENCODE_ISSUER=security-sprint1-users
JWT_DECODE_ISSUER=security-sprint1-users
JWT_ENCODE_AUDIENCE=security-sprint1-services
JWT_DECODE_AUDIENCE=security-sprint1-services
```

Keep the shared JWT secret and distinct service keys private. SERVICE_TOKENS
must contain users/logs/playbooks plus assets/threats/reports/incidents/
vulnerabilities/notifications for full integration. Give each service only its
own caller identity; receivers need the relevant trusted-key registry. Current
development configuration holds the registry in each owned process. Harden
per-process secret distribution before production deployment.

3. Stop your three old service processes and run the non-destructive migration:

```powershell
.\.venv\Scripts\python.exe -m security_backend migrate
```

The command applies 001 then 002; no drop/reset/reseed is needed. Back up an
existing shared database and coordinate migration order: Natalio, Chris, Karim.
No existing development/shared database was migrated merely by running tests.

4. Start in three separate terminals:

```powershell
.\.venv\Scripts\python.exe -m security_backend run users
.\.venv\Scripts\python.exe -m security_backend run logs
.\.venv\Scripts\python.exe -m security_backend run playbooks
```

5. Reimport Student1.postman_collection.json and select your private environment.
   Run Administrator login again. Old tokens without v1 claims will fail.
   The collection creates/deletes its own demo records; use a test/demo database.

6. Flush due audit work after recovery, repeating later if work is scheduled:

```powershell
.\.venv\Scripts\python.exe -m security_backend flush-audit users
.\.venv\Scripts\python.exe -m security_backend flush-audit playbooks
```

After correcting a permanent credential/input rejection, add --retry-blocked.
An IDEMPOTENCY_CONFLICT requires investigation of the original logical event;
do not alter an already accepted event to force it through. All failures retain
pending work and sanitized error codes. Exit 1 includes scheduled/blocked work.

## Teammate handoff

- INTEGRATION.md supplies exact identity/reference/log requests and receipt shapes.
- API.md and openapi-users.json/openapi-logs.json/openapi-playbooks.json describe
  the three owned services. USER/LOG base settings in this implementation are
  origin-only plus API_PREFIX; Chris's full-base settings include the prefix.
- Chris must adapt Reports and audit delivery. Karim must replace temporary auth,
  use PostgreSQL/owned migrations and HTTP reference/audit/notification APIs.
- The internal Users reference returns no display names. Optional name enrichment
  requires an explicitly agreed addition or omitting that enrichment.
- Instructor clarification on teammates' full-name routes/permission ambiguities
  remains separate from this local implementation. No teammate route is changed.
- The signed shared HMAC key is trusted infrastructure: any holder can sign tokens.
  Live identity prevents stale-role use; keep the key restricted to trusted services.

## Verification and evidence

See VERIFICATION_V1.md for executed results. Tests named test_unit_ use explicit
fault doubles; other security/workflow checks run through real owned HTTP services
and isolated PostgreSQL schemas. A client authenticated as a teammate service in
these tests validates Natalio's interfaces, not that a teammate implementation ran.
Old screenshots/report counts describe the earlier version. Capture fresh affected
evidence after the final team deployment; do not present new contract examples as
execution screenshots. This work used AI assistance and requires student review.

Technical references: [Flask JWT options](https://flask-jwt-extended.readthedocs.io/en/stable/options.html)
and [PyJWT validation](https://pyjwt.readthedocs.io/en/stable/api.html).
