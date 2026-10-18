# Executed verification record (Chris Gharfine)

Execution date: October 18, 2026 (Asia/Beirut). Scope: Chris's three Sprint I
services on `feature/chris`, implementation commit `f405201`. These results record actual commands run in this
workspace; they do not claim that the full nine-service system is integrated.

## Final automated test execution

Command:

```powershell
.\tools\chris\run_tests.ps1
```

Result: **213 passed, 0 failed, 0 skipped, 1 third-party deprecation warning**,
in 36.67 seconds of pytest execution. The runner created a dedicated PostgreSQL
17 container with generated credentials and a random localhost port, ran tests
in randomly named schemas, and stopped that generated container afterward.
The raw local JUnit output is in ignored `.chris-runtime/latest-tests.xml`.

The warning is Starlette's deprecation of HTTPX for its TestClient; the approved
HTTPX-based tests still pass. No replacement HTTP library was introduced. The
earlier Windows sandbox run stalled on asyncio's local socket pair; tests were
then executed with approved access outside that sandbox restriction. No test
result was inferred from the stalled run.

Coverage exercised:

- All 18 prescribed endpoint types against all four roles, including durable
  denied-access events and unchanged business records after forbidden requests.
- Asset persistence, owner foreign keys, nonexistent owners/IDs, IP/type/status/
  criticality validation, searches, literal wildcard/SQL-looking input, updates,
  and restrictive incident/vulnerability reference deletion behavior.
- Threat normalization, all supported indicator types/hash lengths, malformed
  indicators, duplicate rejection, updates, deletion, and concurrent insertion
  with one success and one database-backed conflict.
- Real Alembic upgrades, absence of production Users creation, the missing-Users
  migration gate, idempotent repeated upgrades, constraints, and actual PostgreSQL
  rejection of invalid values outside the API. A final schema consistency check
  compares migrated columns/indexes/foreign keys and check-constraint names with
  ORM metadata; duplicated generated constraint prefixes were corrected.
- JWT signature/key/algorithm, issuer/audience, required claims, expiry, role,
  status, and invalid subject checks; authenticated and anonymous denial auditing.
- Atomic rollback when audit persistence fails; durable delivery attempts,
  invalid acknowledgments, retry idempotency headers, and concurrent workers
  skipping locked events.
- Nonzero/empty report datasets, expected aggregates, deterministic recent
  ordering, source authorization failures, timeouts, invalid JSON/content types,
  invalid fields/timestamps, duplicate IDs, unsupported envelopes, and size bounds.
- A real three-service localhost HTTP test in which Reports reads Assets and
  Threats over HTTP and reflects their subsequent persisted changes.
- Postman JSON coverage of all 18 endpoint types, 25 total requests, positive
  body compatibility, descriptions, and blank exported token variables.

Tests use generated signing keys and explicit external-service doubles. The
database Users fixture is a minimal table confined to each disposable test
schema, not Natalio's implementation or a production migration. Report sources
other than the live Asset/Threat HTTP test are isolated HTTP doubles.

## Packaging and dependency checks

- `python -m pip check`: passed with no broken requirements in `.venv-chris`.
- `docker build --file services/chris_support/Dockerfile --tag chris-sprint1-local:20261018 .`:
  passed, including Linux dependency installation.
- `docker compose -f compose.chris.yaml config --quiet`: passed using temporary
  in-process verification settings; no real user token or private key was saved.
- Built-image import check for all three route modules: passed as UID 10001.
- The image was built locally; it was not published to a registry.

## Checks still required with the team

- Actual Natalio-issued user/service tokens, issuer/key rotation, immediate
  account suspension/revocation, and real audit event delivery/deduplication.
- Natalio's complete Users schema/migration and Karim's actual incident/
  vulnerability foreign keys and HTTP responses.
- Live Users/Incidents/Audit/Vulnerabilities reports and a full summary using
  the real source services, including cross-service role restrictions.
- Real Postman collection execution and database screenshots from the student's
  running integrated system, with Chris Gharfine captions.
- Professor clarification of student-name route paths and auditor threat search.

No Postman screenshots, database screenshots, external-service responses, or
final report totals were fabricated. Use [evidence-checklist.md](evidence-checklist.md)
for the remaining actual execution evidence and
[integration-contracts.md](integration-contracts.md) for the open contracts.
