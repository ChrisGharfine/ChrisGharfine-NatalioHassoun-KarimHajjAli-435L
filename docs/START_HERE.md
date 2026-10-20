# Student 1 implementation (Natalio Hassoun)

This checkout contains Users, Security Audit Logging, and Playbooks only. The
original repository README is preserved. The other six services remain the
responsibility of teammates. No commits or pushes were created by the assistant.

## Setup

Use Python 3.10 or newer and PostgreSQL 17 or another compatible PostgreSQL
installation. Run commands from the repository root. On Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
Copy-Item .env.example .env
```

Create development and test databases using your PostgreSQL administrator tools:

```sql
CREATE ROLE student1 LOGIN PASSWORD 'replace-with-your-own-password';
CREATE DATABASE security_incidents OWNER student1;
CREATE DATABASE security_incidents_test OWNER student1;
```

Edit `.env` with your database password and random secrets. Generate each secret
separately using `python -c "import secrets; print(secrets.token_hex(32))"`.
`SERVICE_TOKENS` is a JSON mapping with a distinct key for each trusted service.
Set the initial administrator's `ADMIN_*` fields. The password policy is 12–128
characters, including uppercase, lowercase, digit, and symbol. This policy is an
implementation choice because the assignment does not specify exact rules.

```powershell
.\.venv\Scripts\python.exe -m security_backend migrate
.\.venv\Scripts\python.exe -m security_backend create-admin
```

The migration creates only Student 1's tables and immutable-history triggers.
It now applies 001_student1.sql and the additive 002_team_v1.sql retry-metadata
migration in one transaction. Existing outbox events and receipt IDs are retained.
It is repeatable and never drops existing tables or records. It does not reconcile
an incompatible pre-existing schema: coordinate the shared schema before applying
it to an existing team database. Users must exist before teammates add user FKs.

Start each service in a separate terminal, from this same folder:

```powershell
.\.venv\Scripts\python.exe -m security_backend run users
.\.venv\Scripts\python.exe -m security_backend run logs
.\.venv\Scripts\python.exe -m security_backend run playbooks
```

Defaults are ports 8001, 8005 and 8009 on loopback. Use `--port` to change a
listener and update the corresponding URL variables. Add `PLAYBOOKS_URL` if you
change its port for the sample-data script. These are local teaching servers;
they run with debug/reloader disabled. Health routes include Natalio's name.

An initial administrator's audit event can remain pending before Logging starts.
After all servers are running:

```powershell
.\.venv\Scripts\python.exe -m security_backend flush-audit users
.\.venv\Scripts\python.exe -m security_backend flush-audit playbooks
```

`create-admin` does not overwrite existing credentials. After setup, remove the
bootstrap password from your shell/session if it is no longer needed. Do not
share `.env`, real Postman environments, tokens, or database credentials in Git.

For the team v1 upgrade, restart all three services AFTER running migrate, then
log in again: existing tokens without issuer/audience are intentionally rejected.
The four JWT issuer/audience settings and all nine service-key placeholders are
in .env.example. Add distinct random local keys; coordinate matching credentials
privately with each owner. Never put real keys in the JSON environment export.

Audit delivery respects a persisted exponential schedule (maximum five minutes).
Run flush-audit again once pending events are due. After fixing rejected service
credentials or another permanent delivery failure, explicitly requeue blocked work:

```powershell
.\.venv\Scripts\python.exe -m security_backend flush-audit users --retry-blocked
.\.venv\Scripts\python.exe -m security_backend flush-audit playbooks --retry-blocked
```

Exit 1 means some work remains pending/scheduled/blocked. Do not repeat the
successful business operation. See TEAM_V1_ROLLOUT.md for exact upgrade steps.

## Sample data

Set `DEMO_PASSWORD` in your local `.env`, then run:

```powershell
.\.venv\Scripts\python.exe -m scripts.seed_demo
```

This uses HTTP to register a demo analyst, employee and auditor, then creates two
playbooks and six actions. Repeated runs reuse users and add more playbooks.
It prints no passwords or tokens. These are real inserted records, not evidence
screenshots. You must execute and capture the required demonstrations yourself.

## Tests

Set `TEST_DATABASE_URL` to an isolated PostgreSQL database whose name ends in
`_test`. Never point it at your team/development database.

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=test-results.local.xml
```

The suite starts three real HTTP servers on temporary loopback ports and uses a
random schema inside the test database. It removes only that schema at teardown.
It does not drop the database, touch existing schemas, or use SQLite. The original
integration suite uses no mocked APIs. New tests explicitly named test_unit_ use
mocked outbound responses to test malformed dependency replies; those are unit
fault tests, not teammate integration evidence. Outage tests point a URL at an unreachable local
port; they are real connection failures. Tests do not prove integration with
teammates' six services or replace the assignment's Postman screenshots.

See `VERIFICATION.md` for the actual results from the assistant's run, and rerun
the suite in your own environment after any change.

## Postman

Import both files under `postman/`. Select the local environment and fill in:
`admin_username`, `admin_password`, `demo_password`, `playbooks_service_key`.
Keep these values local and clear them before exporting an environment.

Run the collection folders in order. Setup creates fresh accounts, obtains
tokens and captures IDs automatically. Later folders change roles/statuses,
demonstrate permissions, build workflow history and delete the demo employee and
first playbook. It intentionally inserts data into the configured development
database. Use a dedicated demo database if you want to keep real work separate.

Every request includes an expected HTTP-status assertion. The collection contains
no invented saved responses. Capture actual Postman execution as described in
`EVIDENCE_CHECKLIST.md`.

## Your branch and commits

The local working branch is `natalio/student1`; `main` has not been changed.
Review the files and run the tests before committing. Check your Git identity:

```powershell
git branch --show-current
git config user.name
git config user.email
git status
```

If needed, set this repository's name to `Natalio Hassoun` and its email to the
verified email (or GitHub-provided no-reply address) on YOUR GitHub account.
No email has been guessed or configured. You can then stage reviewed files,
create your own meaningful commits, and push explicitly with:

```powershell
git push -u origin natalio/student1
```

That push is for you to run. The assistant did not commit, push, change Git
identity, or add a co-author trailer. Preserve accurate AI-use disclosure.
