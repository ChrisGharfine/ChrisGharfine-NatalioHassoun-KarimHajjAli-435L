# Implementation proposal (Chris Gharfine)

Status: proposal awaiting approval. This file does not establish a shared team
contract. No service code, schema, authentication system, or runtime configuration
has been implemented.

## Verified starting point

The attached assignment was read in full from the supplied attachment location,
including the database, validation, authorization, evidence, and submission
sections. It contains no embedded images, tables, or external content chunks.
No assignment copy was placed in the repository.

On inspection, the selected repository and `feature/chris` branch were correct
and the working tree was clean. A fresh fetch found only the initial `README.md`
on the available remote branches. There was no `AGENTS.md`, `PROJECT_CONTRACT.md`,
`CLAUDE.md`, application, dependency manifest, or architecture/API contract.

The request proposes a stack only "if approved" and requires approval before
changing shared architecture. Establishing that architecture in an empty
repository is a consequential decision, so implementation must wait for approval.

## Proposed baseline for approval

1. Use the requested Python, FastAPI, PostgreSQL, SQLAlchemy, Alembic, Pydantic,
   HTTPX, pytest, Docker Compose, and Postman stack. Select and pin compatible
   dependency versions during implementation, after checking official sources.
2. Put Chris's implementation under `services/assets`, `services/threats`, and
   `services/reports`; keep any reusable Chris-owned adapter code in an explicitly
   Chris-owned package. Keep tests, Postman files, and supporting documentation
   scoped to Chris. Do not create the other six services or a team-wide framework.
3. Propose a shared PostgreSQL database with table ownership per service to allow
   the assignment's real cross-entity foreign keys. Chris creates only the Assets,
   Threats, and any approved service-owned support tables. Natalio owns Users and
   Audit; Karim owns Incidents and Vulnerabilities. Reports read business data
   only over HTTP. Users migrations must precede Assets; Assets must precede the
   referencing Incident/Vulnerability migrations. Do not create placeholder Users
   tables or silently remove required foreign keys.
4. Propose positive integer identifiers, snake_case JSON/database fields,
   timezone-aware UTC timestamps, and the prescribed route paths. Final table
   names, ID types, and migration coordination need agreement from the team.
5. Propose explicit serialized enums: severities `low`, `medium`, `high`,
   `critical`; asset statuses `active`, `inactive`, `under_maintenance`; asset types
   `server`, `workstation`, `database`, `application`, `network_device`,
   `cloud_resource`; threat types `ip_address`, `domain`, `file_hash`,
   `malware_signature`, `other`. These spellings and the closed asset-type list
   are proposed implementation choices, not assignment-mandated wire values.
6. Propose entity objects for create/detail/update results, complete JSON arrays
   for list/search results, `201` for creation, `200` for reads/updates, and `204`
   for deletion. Treat PUT as an idempotent update of supplied allowed fields;
   reject empty updates. Register `/search` before parameterized detail routes.
7. Propose JSON errors containing `status` and `message`, with validation details
   when appropriate. Use `401`, `403`, `404`, `409`, and `422` for the corresponding
   authentication, permission, missing resource, conflict, and validation cases.
   Reports should return `503` for an unavailable required source and `502` for a
   malformed successful upstream response, rather than returning false totals.
8. Consume Natalio-issued JWTs only. Verification must require configured trusted
   algorithms, verification material, issuer, audience, expiry, subject, and role.
   Do not supply a development signing secret, bypass, token minting endpoint,
   or independent authentication service. The issuer must define the exact claim
   names, role values, account-status/revocation handling, and key distribution.
9. Propose forwarding the caller's bearer token for authorized report reads from
   `/users`, `/assets`, `/incidents`, `/threats`, `/logs`, and `/vulnerabilities`.
   The initial proposal uses complete arrays; if the team selects pagination,
   define complete traversal and bounds before writing adapters. Never silently
   aggregate a single page or convert upstream authorization errors into zeros.
10. Propose durable delivery of modification and permission-denial audit events
    to Natalio's `POST /logs`, with service credentials issued by the shared Users
    service. The team must agree on the event payload/action names, service-call
    authorization, retry/idempotency protocol, storage ownership, and behavior
    during audit outages. A denied analyst token cannot simply be reused for an
    administrator-only log-write API.
11. Propose restrictive deletion of assets referenced by incidents or
    vulnerabilities, returning `409` rather than cascading into Karim's records.
    Agree on this behavior and the schema before integration.
12. Propose the narrower Service 4 permission table for auditor threat search until
    clarified. Preserve all 18 prescribed routes while the full-name route note is
    clarified. These are recorded interpretations, not resolved professor rulings.

Approval of the proposed stack alone does not establish Natalio's or Karim's
actual contracts. Unconfirmed identity/audit/report integrations must remain
explicit dependencies and be exercised with isolated test doubles until their
real contracts and services are available.

## Contracts needed from the team

| Contract | Required decisions | Coordination owner |
| --- | --- | --- |
| Identity | JWT algorithm/key, issuer/audience, subject/role claims, active-account enforcement, revocation, role spellings | Natalio |
| Database | Topology, table/schema names, ID types, migration order, foreign keys, deletion policy | All three students |
| HTTP data | Base URLs, exact JSON shapes/field names/enums, list pagination, forwarded-token support, errors | Respective service owners |
| Audit writes | Credential model, event body, action names, retries, idempotency, outage behavior | Natalio and all callers |
| Asset references | Exact owner/asset IDs and reference behavior in Incidents and Vulnerabilities | Chris, Natalio, Karim |
| Report semantics | Open status definition, recent ordering/limits, login success/failure actions, complete datasets | Chris and source owners |

The report summary proposal counts `open_incidents` as status `open`, counts
`critical_threats` by severity, and keeps its four illustrated keys. Other reports
provide the specified distributions. A proposed recent limit is ten, sorted by
timestamp descending with ID as a deterministic tie-breaker. Confirm these
choices along with the source contracts rather than hardcoding unagreed behavior.

## Implementation sequence after approval

1. Establish Chris's isolated service layout, approved dependencies, and shared
   contract adapters without modifying another student's files. Continue on
   `feature/chris`; use an isolated worktree if the branch can be safely moved
   without concurrent checkouts or changing the branch's identity.
2. Implement Asset models, schema/migration, ownership constraints, validation,
   RBAC, search, error handling, and audit integration. Test all six routes,
   role combinations, invalid input, unknown owners/IDs, persistence, and safe
   deletion. Verify against PostgreSQL, not only an in-memory substitute.
3. Implement Threat models, schema/migration, type-specific validation,
   normalization, uniqueness, RBAC, search, error handling, and auditing. Test all
   six routes and both application- and database-level duplicate rejection.
4. Implement Reports as HTTP aggregation. Add strict source-response validation,
   complete collection handling, caller authorization, deterministic aggregation,
   and dependency error handling. Contract-test all six routes with isolated HTTP
   doubles, including empty datasets and upstream failures/forbidden responses.
5. Prepare the 18-endpoint Postman collection plus negative examples, service
   documentation, migration/run instructions, and real execution evidence guide.
6. Run available relevant automated tests, migrations, and local service smoke
   checks. Record exactly what ran; identify missing live integrations and
   environment limitations. Do not claim completion of all nine services.
7. Review changes and staged files for ownership and secrets, then make meaningful
   commits with Chris Gharfine's authorized identity and push only `feature/chris`.

## Current verification record

- Executed: repository/remote/branch/status checks; `git fetch origin`; tracked
  tree and instruction/contract discovery; full attachment text/structure review.
- Result: correct repository, branch `feature/chris`, no pre-existing local
  modifications, and no approved implementation stack or contracts in the repo.
- Automated implementation tests: not run; service code does not exist yet.
- Live APIs, PostgreSQL migrations, Docker, and Postman: not executed.
- Remaining gate: approve the proposed baseline or supply the team's approved
  architecture/contract document before service implementation.
