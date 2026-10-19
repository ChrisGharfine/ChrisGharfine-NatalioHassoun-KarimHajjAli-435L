# Team v1 executed verification — Natalio Hassoun

Executed 19 October 2026 against the updated owned Users, Logs and Playbooks code.
Target: team-integration-v1.0.0. These results supersede the original-version
counts for this update; they do not establish nine-service integration.

| Check | Executed result |
|---|---|
| Complete pytest suite | **85 passed**, 34.70 seconds, zero failures |
| Live HTTP/PostgreSQL and migration/recovery tests | 67 passed (included above) |
| Explicit mocked outbound-dependency fault tests | 17 passed (included above) |
| OpenAPI coverage of registered operations | 1 passed (included above) |
| Updated Postman collection through Newman | **77 requests, 158 assertions, zero failures**, 9.8 seconds |
| Python compilation | Passed |
| pip check | No broken requirements found |
| Git whitespace check | Passed |

The suite uses real threaded HTTP servers for the three owned services, temporary
loopback ports and random disposable schemas in the dedicated PostgreSQL test
database. It also tests upgrading the ORIGINAL version 1 DDL with an existing
outbox record: migration 002 is repeatable and preserves the payload and attempt
count. No existing development/team database was reset or migrated by these tests.

New coverage includes issuer/audience/type and required signed claims, numeric
date validation, HS256 allowlisting, current role/status/deletion, all six teammate
service identities calling Natalio's interfaces, malformed identity responses,
subject mismatch, malformed/wrong-UUID/202/redirect receipts, permanent rejection
and explicit requeue, retry scheduling/cap, and delivery from a newly created
application/worker using persisted queue state. This is not a claim that an OS
process crash was injected. Existing CRUD/history/permissions tests remain passing.

Tests named test_unit_ use explicit response doubles to inject malformed upstream
replies. They are security unit/fault tests, not real teammate integration evidence.
All 77 Newman requests execute against the actual owned HTTP applications and
PostgreSQL. Newman validates v1 token claims and new/duplicate/deleted-log receipts;
no saved fake responses stand in for requests. The script creates temporary test
credentials and removes the populated environment on completion.

Artifacts: verification/pytest-results-v1.xml and
verification/newman-summary-v1.txt. Reproduction commands from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=test-results.local.v1.xml
# Optional: point NEWMAN_JS at an installed Newman bin/newman.js first.
.\.venv\Scripts\python.exe -m scripts.verify_postman
```

TEST_DATABASE_URL must select a dedicated PostgreSQL database ending in _test.
The local verification used the existing workspace virtual environment and
portable PostgreSQL 17 runtime; those private tools are outside the source tree.
The first test attempts encountered stopped/misconfigured local database access;
after starting the existing runtime on its configured port, real checks ran.
A draft contract coverage assertion needed to handle Flask's string converter,
and a request-latency adjustment initially deferred the second event from failed
login. The bounded audit batch was corrected and the complete suite/collection
rerun successfully. Failed attempts are not included in the passed counts above.

Not verified: Chris's/Karim's implementations, their checker, full team workflows,
production deployment, instructor permission/route clarifications or updated GUI
screenshots. Previously captured evidence remains evidence of its original version.
AI assisted this update; student review and accurate disclosure remain necessary.
No assistant-created commits, pushes or changes to Git identity were made.
