# Nine-service setup and verification

Use the v1.1 addresses in INTEGRATION_V1_1.md. The three personal checkouts can
run together without merging: start each owner's processes from their own root.
After the team reviews and combines the branches, the same commands work from
the assembled root. This change does not merge branches or change main.

## 1. Environment and dependencies

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

Copy `.env.example` to a NEW private `.env.team` and fill the placeholders.
Do not overwrite existing private `.env` or `.env.local` files. For an existing
Natalio setup, this optional helper derives a new coordinated file, preserving
its database settings and secrets:

```powershell
python tools/team/init_env.py --source .env --destination .env.team
```

The helper refuses overwrite and missing/placeholder source keys. Review the new
file locally, then securely copy the SAME private file to the other checkouts
on the same machine. Never commit or send this file in screenshots. On separate
machines replace 127.0.0.1 with the appropriate reachable service hosts.
`DATABASE_URL`, `CHRIS_DATABASE_URL`, and `KARIM_DATABASE_URL` must identify the
same database and schema. Only Karim uses `postgresql://`; SQLAlchemy uses
`postgresql+psycopg://`. Reuse one JWT secret and the same nine distinct service
keys in all registries. Do not use example placeholders as credentials.

Commands below use `python` from the activated team virtual environment.
The private-env runner loads `.env.team` explicitly; it prints no secrets.
No Docker is required. PostgreSQL must already be running and the databases
must exist. Back up existing data before upgrading a shared installation.

## 2. Apply owned migrations in this order

Run each command in that owner's repository root:

```powershell
python tools/team/run.py natalio -m security_backend migrate
python tools/team/run.py chris -m alembic -c services/chris_support/alembic.ini upgrade head
python tools/team/run.py karim migrate.py
python tools/team/run.py karim migrate.py --status
```

These are additive/repeatable native migrations. Natalio creates Users before
Chris creates Assets; Karim's foreign keys require both. Karim's migration
checksums remain unchanged. Do not use the development stand-in bootstrap for
team integration. Existing SQLite data, if any, requires a separate reviewed
import plan after a backup; this patch does not add an automatic SQLite importer.

## 3. Start nine processes in separate terminals

Run each command in its owner's checkout, with the same Python environment:

```powershell
python tools/team/run.py natalio -m security_backend run users --port 8001
python tools/team/run.py natalio -m security_backend run logs --port 8005
python tools/team/run.py natalio -m security_backend run playbooks --port 8009
python tools/team/run.py chris -m uvicorn services.assets.main:app --host 127.0.0.1 --port 8002
python tools/team/run.py chris -m uvicorn services.threats.main:app --host 127.0.0.1 --port 8004
python tools/team/run.py chris -m uvicorn services.reports.main:app --host 127.0.0.1 --port 8006
python tools/team/run.py karim apps/incidents_app.py
python tools/team/run.py karim apps/vulnerabilities_app.py
python tools/team/run.py karim apps/notifications_app.py
```

After Users and Logs are available, bootstrap the initial administrator once:
`python tools/team/run.py natalio -m security_backend create-admin`.
This command does not change an existing administrator's password. Use actual
stored credentials in Postman. Health routes are `<complete-base>/health`;
Chris also exposes `<complete-base>/ready` and `<complete-base>/docs`.

## 4. Run delivery workers and check queues

Keep Chris's and Karim's workers running in separate terminals:

```powershell
python tools/team/run.py chris -m services.chris_support.audit_worker
python tools/team/run.py karim worker.py
```

Explicit one-pass commands (repeat after backoff or while draining large queues):

```powershell
python tools/team/run.py natalio -m security_backend flush-audit users
python tools/team/run.py natalio -m security_backend flush-audit playbooks
python tools/team/run.py chris -m services.chris_support.audit_worker --once
python tools/team/run.py karim worker.py --flush
python tools/team/run.py karim worker.py --status
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

## 5. Postman and live team verification

Import Natalio's `postman/Student1.postman_collection.json` and
`postman/Local.postman_environment.json`; Chris's
`postman/chris-sprint1.postman_collection.json`; Karim's three `Service N ...`
collections and `postman/SIRMS v1 Local.postman_environment.json`.
Use the current templates. `postman/historical/` retains old captures only.
Login through real Users and put tokens/keys in local secret variables.
No old saved response is proof that the changed routes were executed.

Once workers drain and the data is stable, Chris's checker reconciles all six
Reports responses with their actual sources. In Chris's root, set a locally
obtained current admin access token in `TEAM_ADMIN_TOKEN` and the Reports
service key in `TEAM_REPORTS_SERVICE_KEY`, then run:

```powershell
python tools/team/run.py chris tools/chris/check_team_integration.py
```

Defaults use the nine addresses in the contract; override `TEAM_<SERVICE>_URL`
for a different network. This is read-only except required audit events for
denied operations. It does not migrate or seed data.

## 6. Tests and evidence

Dedicated test databases must exist; never point test settings at team data.
Natalio's database ends `_test`; Chris's begins `chris_test`; Karim's ends
`_test`. Each suite creates/removes only its own random schema.

```powershell
# Natalio root, TEST_DATABASE_URL configured in private .env.team
python tools/team/run.py natalio -m pytest tests/test_integration.py tests/test_team_v1.py -q
# Chris root, CHRIS_TEST_DATABASE_URL configured locally
python tools/team/run.py chris -m pytest tests/chris -q
# Karim root, KARIM_TEST_DATABASE_URL configured locally
python tools/team/run.py karim -m unittest tests.test_security_v1_1 -v
python tools/team/run.py karim tests/test_integration_v1.py
```

Karim's 144-check suite and parts of Chris's suite use explicit upstream doubles;
they do not establish live teammate integration. The separate execution record
in VERIFICATION_V1_1.md describes the real nine-process run. Capture current
Postman responses and disclose AI help accurately in the report. Do not commit
private dotenv files, runtime folders, access tokens, service keys, or raw
unsanitized terminal logs.

## 7. Repeat the full isolated live scenario

`tools/team/verify_live.py` starts all nine real processes on temporary loopback
ports, applies owned migrations twice, creates only disposable demonstration
data, runs source/report reconciliation twice, and exercises real dependency
outages and recovery. No upstream doubles are used. It creates/removes only one
generated schema in a pre-existing local dedicated *_test PostgreSQL database.
It does not touch the running development services or their database schema.

From an assembled repository using the team runtime:

```powershell
python tools/team/verify_live.py --env-file .env.team
```

From separate checkouts, supply `--natalio-root`, `--chris-root`, `--karim-root`
with their absolute paths. For this workspace, run it from Natalio's root with
`--chris-root ..\chris --karim-root ..\karim --env-file .env`.
Results and local server logs go to a NEW ignored `.runtime/team-live-*` folder.
Only sanitized JSON/checker summaries should be copied into public evidence.
An unsuccessful check exits nonzero. A one-pass outbox command during a simulated
outage may still exit zero for Karim; separate persisted-queue assertions verify
that failed delivery did not lose work.
