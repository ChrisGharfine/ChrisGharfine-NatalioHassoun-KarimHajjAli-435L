# Executed verification (Natalio Hassoun)

Final verification was executed on October 18, 2026, using Python 3.10.5,
PostgreSQL 17.10, Flask 3.1.3, SQLAlchemy 2.0.55, Psycopg 3.3.6 and
Flask-JWT-Extended 4.7.4. These are measured runs against this local implementation,
not invented response examples. Runtime dependencies are pinned in
requirements-lock.txt.

| Check | Actual final result |
|---|---|
| HTTP/PostgreSQL pytest integration suite | **36 passed**, 18.43 seconds |
| Exported Postman collection executed by Newman 6.2.1 | **73 requests, 146 assertions, 0 failures**, 7.4 seconds |
| Dependency consistency (`pip check`) | No broken requirements found |
| Python source compilation | Passed |
| Migration repeatability | Applied twice in isolated test schemas; passed |
| Administrator setup repeatability | Actual CLI executed twice; existing credentials retained |
| Sample-data setup | Actual script executed through live APIs; two playbooks with three actions each verified |
| Git state | Branch natalio/student1; no assistant-created commits or pushes |

The pytest report is retained as `verification/pytest-results.xml`. The Newman
console summary is retained as `verification/newman-summary.txt`; the request
collection and empty environment template are under `postman/`.

The three real servers ran on temporary loopback ports against random disposable
schemas in the dedicated security_incidents_test database. No mock HTTP/API
responses or SQLite replacements were used. Outage tests used genuinely unreachable
local URLs. Each schema was removed on teardown; no existing database was dropped.
The portable PostgreSQL runtime and downloaded test tooling lived under the chat's
work directory, outside the source deliverable, and are not project dependencies.

Coverage includes all four roles, profile ownership, registration/email/username
validation, password hashing, login failure, suspended/inactive/deleted accounts,
invalid/expired tokens, current role checks, deletion history, internal service
authentication, log filters/immutability/deletion/deduplication, ordered actions,
execution snapshots, invalid assignments and completion dates, identity outage,
durable audit queue recovery, CLI setup, and sample-data creation.

The final sample-data verification initially counted similarly named fixtures from
other tests. Its assertion was corrected to filter by its newly created admin's
creator ID, then the complete final suite and collection passed. Earlier attempts
also encountered local sandbox networking restrictions; PostgreSQL was started
outside that restricted network environment for the successful runs.

Not verified or supplied: teammates' six services, a full nine-service deployment,
actual Postman GUI/database screenshots, GitHub student contribution history,
CREATES attendance, or the common final report. Newman execution complements but
does not replace the assignment's required screenshots. The student must review,
understand, and rerun the assisted implementation in their own workflow.

To rerun the exported collection headlessly, install Newman separately and set
NEWMAN_JS to its bin/newman.js and TEST_DATABASE_URL to an isolated *_test database:

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_postman
```

This optional runner creates an environment containing temporary credentials only
inside a temporary directory and removes it afterward. Do not export or commit a
real populated environment file. The normal project startup needs no Node/Newman.
