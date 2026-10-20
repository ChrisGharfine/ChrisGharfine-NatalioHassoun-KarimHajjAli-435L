# Nine-service setup and verification

Use the merged `main` checkout and the [v1.1 addresses](INTEGRATION_V1_1.md).
All commands below run from the repository root. The services are separate
processes even though their source is now in one repository. Separate owner
checkouts can also run together if they use matching configuration and addresses.

## 1. Python and dependencies

Use Python 3.12 and a virtual environment. From a repository root:

```powershell
py -3.12 -m venv .venv-team
.\.venv-team\Scripts\python.exe -m pip install -r requirements.txt
```

For an owner-only environment install `requirements-natalio.txt`,
`requirements-chris.txt`, or `requirements-karim.txt`. Optional Sphinx build
dependencies are separate in `requirements-docs-karim.txt`. Existing Natalio
`requirements-lock.txt` describes his older owner environment; the new
`requirements-team-lock.txt` records the complete tested team environment, including optional documentation tools.

## 2. Private configuration

If `.env.team` already exists, keep it and review its settings locally. Otherwise
create it from the tracked placeholder template without overwriting another file:

```powershell
if (-not (Test-Path -LiteralPath .env.team)) {
    Copy-Item -LiteralPath .env.example -Destination .env.team
}
```

Open the new private file in your local editor and complete these groups:

| Settings | Required agreement |
|---|---|
| `DATABASE_URL`, `CHRIS_DATABASE_URL`, `KARIM_DATABASE_URL` | Same running team database and schema, with actual local connection credentials |
| `TEST_DATABASE_URL`, `CHRIS_TEST_DATABASE_URL`, `KARIM_TEST_DATABASE_URL` | Dedicated pre-existing test databases, separate from team data; use the required names below |
| `JWT_SECRET_KEY`, `CHRIS_JWT_VERIFICATION_KEY`, `KARIM_JWT_VERIFICATION_KEY` | The same private secret, at least 32 bytes |
| `SERVICE_TOKENS`, `CHRIS_SERVICE_TOKENS`, `KARIM_SERVICE_TOKENS` | Matching registry of nine distinct printable ASCII service keys, each at least 32 bytes and separate from the JWT secret; retain each setting's JSON or comma-separated format |
| `KARIM_INCIDENTS_SERVICE_KEY`, `KARIM_VULNERABILITIES_SERVICE_KEY`, `KARIM_NOTIFICATIONS_SERVICE_KEY` | Match the corresponding keys in every registry |
| `ADMIN_*`, `DEMO_PASSWORD` | Real local demonstration values satisfying the Users password policy |
| Prefix, issuer, audience and service URL settings | Keep the v1.1 values in the template; change host/port only when the deployment requires it |

For an existing Natalio installation, `tools/team/init_env.py --source .env
--destination .env.team` is an optional generator. It refuses to overwrite its
destination, but replaces Chris/Karim URL settings with the template values,
**including `CHRIS_TEST_DATABASE_URL` and `KARIM_TEST_DATABASE_URL`**. Do not
assume existing test settings are preserved. Complete and verify the generated
file locally before using any test command. Manual configuration above avoids
depending on that helper behavior.

On separate machines replace loopback addresses with reachable service hosts.
Coordinate matching keys through a private channel, never through Git or screenshots.
`DATABASE_URL`, `CHRIS_DATABASE_URL`, and `KARIM_DATABASE_URL` must identify the
same database and schema. Only Karim uses `postgresql://`; SQLAlchemy uses
`postgresql+psycopg://`. Reuse one JWT secret and the same nine distinct service
keys in all registries. Do not use example placeholders as credentials.

Commands below use the virtual environment's executable directly, so PowerShell
activation is not required. Use that same executable in each new terminal.
The private-env runner loads `.env.team` explicitly and prints no secrets.
Restart a process after changing its configuration; a running process retains
the values it loaded. No Docker is required for this local setup.

## 3. Prepare PostgreSQL and apply owned migrations

PostgreSQL must be running, and the configured application role needs access and
permission to create its owned objects. For an existing installation, back up
the database and review migrations first. Do not drop databases or use a reset
command to make setup pass.

For a fresh installation only, create the configured runtime and test databases
using pgAdmin's query tool or `psql` as a database administrator. The following
SQL is a template: replace `your_existing_role` with your configured existing
role and create only databases that do not already exist. Execute each statement
separately, outside a transaction:

```sql
CREATE DATABASE security_incidents OWNER your_existing_role;
CREATE DATABASE security_incidents_test OWNER your_existing_role;
CREATE DATABASE chris_test_security OWNER your_existing_role;
```

The runtime URLs refer to `security_incidents`. Natalio and Karim can use the
separate `security_incidents_test`; Chris uses `chris_test_security`. Test names
are checked by the suites: Natalio/Karim names end `_test`; Chris starts
`chris_test`. If you choose other names, retain those safeguards and update the
private URLs. These databases do not appear automatically when installing
Python packages.

If a PostgreSQL utility is not found in PowerShell, use its full path from your
actual PostgreSQL installation's `bin` directory or use pgAdmin. A path from
another machine's temporary runtime is not a valid installation instruction.
Check the same host and port that you placed in `.env.team`.

Apply the real owned migrations in order, from the merged repository root:

```powershell
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend migrate
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m alembic -c services/chris_support/alembic.ini upgrade head
.\.venv-team\Scripts\python.exe tools/team/run.py karim migrate.py
.\.venv-team\Scripts\python.exe tools/team/run.py karim migrate.py --status
```

These are additive/repeatable native migrations. Natalio creates Users before
Chris creates Assets; Karim's foreign keys require both. Karim's migration
checksums remain unchanged. Do not use the development stand-in bootstrap for
team integration. Existing SQLite data, if any, requires a separate reviewed
import plan after a backup; this patch does not add an automatic SQLite importer.

## 4. Start nine processes in separate terminals

Open nine terminals at the merged repository root, one command per terminal:

```powershell
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend run users --port 8001
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend run logs --port 8005
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend run playbooks --port 8009
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m uvicorn services.assets.main:app --host 127.0.0.1 --port 8002
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m uvicorn services.threats.main:app --host 127.0.0.1 --port 8004
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m uvicorn services.reports.main:app --host 127.0.0.1 --port 8006
.\.venv-team\Scripts\python.exe tools/team/run.py karim apps/incidents_app.py
.\.venv-team\Scripts\python.exe tools/team/run.py karim apps/vulnerabilities_app.py
.\.venv-team\Scripts\python.exe tools/team/run.py karim apps/notifications_app.py
```

After Users and Logs are available, bootstrap the initial administrator once:
`.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend create-admin`.
This command does not change an existing administrator's password. Use actual
stored credentials in Postman. Health routes are `<complete-base>/health`;
Chris also exposes `<complete-base>/ready` and `<complete-base>/docs`.

## 5. Run delivery workers and check queues

Keep Chris's and Karim's workers running in separate terminals:

```powershell
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m services.chris_support.audit_worker
.\.venv-team\Scripts\python.exe tools/team/run.py karim worker.py
```

Explicit one-pass commands (repeat after backoff or while draining large queues):

```powershell
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend flush-audit users
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m security_backend flush-audit playbooks
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m services.chris_support.audit_worker --once
.\.venv-team\Scripts\python.exe tools/team/run.py karim worker.py --flush
.\.venv-team\Scripts\python.exe tools/team/run.py karim worker.py --status
```

Natalio/Chris exit nonzero while pending/failed work remains. Karim prints queue
counts; its flush exit code alone is not a proof that the queues are empty.
Karim notification delivery queues an audit event, which is sent on the next
worker pass. Wait for both pending and permanent-error counts to be zero before
treating a queue as drained. Check logs/status after an outage. Credential/input
failures need correction; never blindly replay a conflicting idempotency UUID.
Natalio supports `--retry-blocked`; Chris supports `--once --retry-failed
--service assets` (or threats/reports) after correcting the cause. Karim's retryable
credential failures resume with the same UUID after configuration is repaired.
Permanent failures require operator review of the preserved outbox record.

## 6. Postman and live team verification

Import Natalio's `postman/Student1.postman_collection.json` and
`postman/Local.postman_environment.json`; Chris's
`postman/chris-sprint1.postman_collection.json`; Karim's three `Service N ...`
collections and `postman/SIRMS v1 Local.postman_environment.json`.
Use the current templates. `postman/historical/` retains old captures only.
Login through real Users and put tokens/keys in local secret variables.
No old saved response is proof that the changed routes were executed.
Follow [the ordered workflow and API examples](WORKFLOW.md). Health checks alone
do not cover the 54 core operations, validation, role denials or automatic alerts.

Once workers drain and the data is stable, Chris's checker reconciles all six
Reports responses with their actual sources. From the merged root, set a locally
obtained current admin access token in `TEAM_ADMIN_TOKEN` and the Reports
service key in `TEAM_REPORTS_SERVICE_KEY`, then run:

```powershell
.\.venv-team\Scripts\python.exe tools/team/run.py chris tools/chris/check_team_integration.py
```

Defaults use the nine addresses in the contract; override `TEAM_<SERVICE>_URL`
for a different network. This is read-only except required audit events for
denied operations. It does not migrate or seed data.

## 7. Tests and evidence

Dedicated test databases must exist; never point test settings at team data.
Natalio's database ends `_test`; Chris's begins `chris_test`; Karim's ends
`_test`. Each suite creates/removes only its own random schema.

```powershell
# Natalio root, TEST_DATABASE_URL configured in private .env.team
.\.venv-team\Scripts\python.exe tools/team/run.py natalio -m pytest tests/test_integration.py tests/test_team_v1.py -q
# Chris root, CHRIS_TEST_DATABASE_URL configured locally
.\.venv-team\Scripts\python.exe tools/team/run.py chris -m pytest tests/chris -q
# Karim root, KARIM_TEST_DATABASE_URL configured locally
.\.venv-team\Scripts\python.exe tools/team/run.py karim -m unittest tests.test_security_v1_1 -v
.\.venv-team\Scripts\python.exe tools/team/run.py karim tests/test_integration_v1.py
```

Karim's 144-check suite and parts of Chris's suite use explicit upstream doubles;
they do not establish live teammate integration. The separate execution record
in VERIFICATION_V1_1.md describes the real nine-process run. Capture current
Postman responses and disclose AI help accurately in the report. Do not commit
private dotenv files, runtime folders, access tokens, service keys, or raw
unsanitized terminal logs.

## 8. Repeat the full isolated live scenario

`tools/team/verify_live.py` starts all nine real processes on temporary loopback
ports, applies owned migrations twice, creates only disposable demonstration
data, runs source/report reconciliation twice, and exercises real dependency
outages and recovery. No upstream doubles are used. It creates/removes only one
generated schema in a pre-existing local dedicated *_test PostgreSQL database.
It does not touch the running development services or their database schema.

From an assembled repository using the team runtime:

```powershell
.\.venv-team\Scripts\python.exe tools/team/verify_live.py --env-file .env.team
```

From separate checkouts, supply `--natalio-root`, `--chris-root`, `--karim-root`
with their actual absolute paths and an existing private `--env-file`.
Results and local server logs go to a NEW ignored `.runtime/team-live-*` folder.
Only sanitized JSON/checker summaries should be copied into public evidence.
An unsuccessful check exits nonzero. A one-pass outbox command during a simulated
outage may still exit zero for Karim; separate persisted-queue assertions verify
that failed delivery did not lose work.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| A Python command cannot import a package | Use `.\.venv-team\Scripts\python.exe` and install the shared requirements into that environment |
| Database connection refused | PostgreSQL process, configured host/port, existing database and local role credentials |
| A test database URL still contains `CHANGE_ME` | Complete it privately; the optional generator can restore Chris/Karim test template values |
| Administrator login returns 401 | Stored username/email and password, account status, selected Postman environment; `ADMIN_FULL_NAME` is not the login identifier |
| Editing `ADMIN_PASSWORD` did not change login | `create-admin` preserves an existing administrator; use its actual stored credentials |
| A route returns 404 | Correct process/port plus destination owner's prefix exactly once; import current collections |
| Protected calls return 503 | Users is reachable and current identity/service-key configuration matches; check the named downstream service |
| Notifications or audit records do not arrive yet | Workers running, saved outbox status, dependency availability and matching service keys; allow the next worker pass |
| Reconciliation totals differ | Drain queues, avoid concurrent mutations and confirm all reports use the same source dataset |

See [evidence guidance](EVIDENCE.md) before copying execution material into the
common report. Keep current and historical runs distinct.
