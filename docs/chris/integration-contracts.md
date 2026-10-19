# Implemented integration boundaries (Chris Gharfine)

Chris's Assets, Threats and Reports now implement the selected
[team-integration-v1.0.0](TEAM_INTEGRATION_V1.md) boundaries. That version remains
the team's target. This file records Chris's implementation and open dependencies;
it does not establish that all nine services are deployed or compliant.

## Identity and references

HS256 access tokens require sub, iat, exp, iss, aud and type=access. User IDs
follow Natalio's positive signed-32-bit range. Local signature/claim checks
precede a fresh service-authenticated Users identity request. Returned subject
must match; current canonical role/status authorizes each request, without
trusting stale JWT role/status claims. Invalid credentials/inactive accounts
return 401, disallowed access 403, unavailable/malformed identity 503.

Assets checks new/changed owners through Users' internal reference endpoint.
Its own scoped GET /internal/assets/{id} returns a success/data envelope with
id, name, criticality and owner_id. Only valid Incidents/Vulnerabilities service
identities may call it. The original six public Asset routes remain unchanged.

Each configured process receives its required distinct service keys using
CHRIS_SERVICE_TOKENS. Chris's Assets/Threats/Reports each sends its own identity;
a single audit worker dispatches using the originating service's key.

## Reports

| Provider | Complete array location | Boundary normalization |
| --- | --- | --- |
| Users | success envelope, data | validated id |
| Assets | bare array | existing snake_case fields/enums |
| Incidents | success envelope, incidents, exact count | incident_id to id; explicit Title Case severity/status map |
| Threats | bare array | existing fields/enums, UTC timestamps |
| Logs | success envelope, data | Title Case log severity to lower case; UTC timestamp |
| Vulnerabilities | success envelope, vulnerabilities, exact count | vulnerability_id to id; severity_level to severity; explicit enum map |

Reports delegates the actual caller JWT and reports service credentials to
source APIs. All six report response schemas are preserved. Login action names
are login_success and login_failed. Recent/ranked lists are limited to ten.
Complete-list bounds remain 50,000 records and 5,000,000 bytes; pagination,
invalid records/counts/duplicates and malformed timestamps are rejected, not
silently approximated. Source 401/403 propagate, malformed data returns 502,
and unavailable dependencies return 503.

## Durable audit

Data changes and canonical audit events commit atomically. Denials persist
separately. The worker calls Natalio's prefixed /internal/logs with service
name/key, stable UUID Idempotency-Key and exactly user_id, action, description,
severity and related_service. It never substitutes an administrator JWT.

Migration chris_0003 adds a durable transport_payload snapshot and failed_at
without deleting or changing original event data, IDs or delivered records.
Existing pending dotted actions/lower severities are explicitly mapped before
their first v1 network attempt; the frozen body is reused afterward.

New receipts require 201/duplicate=false; retries 200/duplicate=true, matching
event UUID and valid nested log ID, or log=null for a deleted-log retry receipt.
Permanent conflicts/input/credential rejection are visible failed records.
Outages/ambiguous retries remain pending with capped backoff. Recovery never
repeats the business mutation or replaces an event UUID.

After fixing a recoverable credential/input error:

    python -m services.chris_support.audit_worker --retry-failed --service assets --once

Use threats/reports as appropriate. Invalid local payloads and UUID conflicts
need operator investigation. See [service-guide.md](service-guide.md) for
configuration, migration, launch and flush instructions.

## Remaining real-team dependencies

- Natalio must deploy v1 JWT issuer/audience/required-claim configuration,
  register matching service keys and retain the documented identity/log APIs.
- Karim must publish/run actual PostgreSQL Incidents/Vulnerabilities/
  Notifications services with the specified references, responses and HTTP
  delivery. His fetched remote branch currently contains only README.
- Connect actual runtime URLs/database/network and local credentials. Never
  commit populated configuration or real Postman tokens/keys.
- Execute the all-nine-service workflow, outage/recovery, ownership and report
  reconciliation release gates in section 9 of the versioned specification.
- No extra Threat Alert broadcast was invented: v1 reserves its type but
  defines no automatic Chris trigger.
- Preserve prescribed public routes pending professor clarification; the
  auditor Threat-search discrepancy still follows the narrower service list.

Actual executed checks and their fixture/live limits appear in
[verification.md](verification.md). Screenshots and final integrated evidence
remain separate from automated contract tests.
