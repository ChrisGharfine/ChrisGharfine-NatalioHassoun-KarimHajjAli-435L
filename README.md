# SIRMS — Services 3, 7 and 8

Security Incident Detection and Response Management System
EECE 435L — Software Tools Lab — Sprint I

**Implemented by Karim Hajj Ali**, to `team-integration-v1.0.0`.

| # | Service | Port | Endpoints |
|---|---------|------|-----------|
| 3 | Incident Management | 8003 | 6 public |
| 7 | Vulnerability Management | 8007 | 6 public |
| 8 | Notification and Alert Management | 8008 | 6 public + 1 internal |

Services 1, 2, 4, 5, 6 and 9 belong to Natalio Hassoun and Chris Gharfine.
This repository never creates their tables and never queries them.

---

## Running it

### 1. Dependencies

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. PostgreSQL 17

Any PostgreSQL 17 reachable on a connection string. During development:

```bash
docker run -d --name sirms-pg -e POSTGRES_PASSWORD=CHOOSE_ONE -e POSTGRES_DB=sirms_integration -p 5432:5432 postgres:17
```

### 3. Configuration

Copy `.env.example` to `.env.local` and fill it in. Nothing has a usable
default: the JWT key and the three service keys must be supplied or the
services refuse to start.

```bash
cp .env.example .env.local
# generate secrets
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Load it before any command below:

```bash
set -a; . ./.env.local; set +a     # bash
```

```powershell
Get-Content .env.local | ForEach-Object { if ($_ -match '^([^#=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2]) } }
```

### 4. Migrations

Apply **after** Natalio's and then Chris's, per section 3 — my foreign keys
point at `users(id)` and `assets(id)`, so those tables must already exist.

```bash
python migrate.py            # apply outstanding migrations
python migrate.py --status   # show what is applied, change nothing
```

If `users` or `assets` are missing the migration refuses and says so rather
than creating someone else's tables.

**Developing alone**, with no teammates' services available:

```bash
KARIM_ALLOW_DEV_BOOTSTRAP=yes python devtools/bootstrap_dev_dependencies.py
```

That creates minimal stand-in `users` and `assets` tables. It refuses to
run without the opt-in variable and **must never touch the real
integration database**.

### 5. Start the services

Three processes, one per service:

```bash
python apps/incidents_app.py        # :8003
python apps/vulnerabilities_app.py  # :8007
python apps/notifications_app.py    # :8008
```

Check them:

```bash
curl http://127.0.0.1:8003/health   # {"status":"ok","service":"incidents"}
curl http://127.0.0.1:8007/health
curl http://127.0.0.1:8008/health
```

`/health` and `/ready` return `200` only when that service's own tables can
actually be queried.

### 6. Start the delivery worker

Audit events and notification deliveries are queued transactionally and
sent afterwards. Nothing reaches Natalio's Logs or the Notifications
service until the worker runs.

```bash
python worker.py             # run continuously
python worker.py --flush     # one pass, then exit
python worker.py --status    # queue depths, sends nothing
```

Run `--flush` before taking screenshots or running the team checker, so
nothing is still queued.

### 7. Tests

```bash
python tests/test_integration_v1.py
```

144 checks. Uses its own `sirms_test` database, created on first run; the
integration database is never touched.

---

## Authentication

Natalio's Users service is the only token issuer:

```
POST {USERS_BASE_URL}/users/login
{"identifier": "your.username", "password": "..."}
```

Take `data.access_token` and send it as `Authorization: Bearer <token>`.

On every protected request my services verify the token locally (HS256,
required claims, issuer, audience, expiry) and then ask Users for the
caller's **current** role over HTTP. There is no cache, so a suspension or
role change takes effect on the very next request.

| Situation | Status |
|---|---|
| No token, bad signature, expired, wrong issuer/audience, missing claim | `401` |
| Account inactive, suspended or deleted | `401` |
| Healthy identity, role not permitted here | `403` |
| Users unreachable, slow, or malformed reply | `503` — fails closed |

Internal endpoints use `X-Service-Name` and `X-Service-Key` instead. A user
token is never accepted in their place.

---

## Endpoints

### Service 3 — Incidents (`:8003`)

| Method | Endpoint | Admin | Analyst | Employee | Auditor |
|---|---|:-:|:-:|:-:|:-:|
| POST | `/incidents` | ✓ | | ✓ | |
| GET | `/incidents` | ✓ | | | ✓ |
| GET | `/incidents/{id}` | ✓ | ✓ | own only | ✓ |
| PUT | `/incidents/{id}/assign` | ✓ | | | |
| PUT | `/incidents/{id}/status` | ✓ | ✓ | | |
| POST | `/incidents/{id}/notes` | ✓ | ✓ | | |

### Service 7 — Vulnerabilities (`:8007`)

| Method | Endpoint | Admin | Analyst | Employee | Auditor |
|---|---|:-:|:-:|:-:|:-:|
| POST | `/vulnerabilities` | ✓ | | | |
| GET | `/vulnerabilities` | ✓ | ✓ | | ✓ |
| GET | `/vulnerabilities/{id}` | ✓ | ✓ | | ✓ |
| PUT | `/vulnerabilities/{id}` | ✓ | ✓ | | |
| GET | `/vulnerabilities/search` | ✓ | ✓ | | ✓ |
| DELETE | `/vulnerabilities/{id}` | ✓ | | | |

### Service 8 — Notifications (`:8008`)

| Method | Endpoint | Admin | Analyst | Employee | Auditor |
|---|---|:-:|:-:|:-:|:-:|
| POST | `/notifications` | ✓ | | | |
| GET | `/notifications/user/{id}` | ✓ | own only | own only | ✓ |
| GET | `/notifications/{id}` | ✓ | own only | own only | ✓ |
| PUT | `/notifications/{id}/read` | ✓ | own only | own only | |
| GET | `/notifications/search` | ✓ | own only | | ✓ |
| DELETE | `/notifications/{id}` | ✓ | | | |
| POST | `/internal/notifications` | service credential only | | | |

---

## Lifecycles

Both advance **one step at a time**; skipping is refused with `400` naming
the only status that would have been accepted.

- Incidents: `Open → Under Investigation → Mitigated → Resolved → Closed`
- Vulnerabilities: `Open → Under Investigation → In Progress → Resolved → Closed`

Reaching `Resolved` stamps the resolution date automatically.

---

## Cross-service behaviour

| Trigger | Effect |
|---|---|
| Incident assigned | `Incident Assignment` notification to the analyst |
| High/Critical vulnerability created | `Vulnerability Alert` to the asset's owner |
| Any mutation | Audit event queued, delivered to Natalio's Logs |
| Any denied request | `unauthorized_access` event, in its own transaction |

Both notification triggers go over HTTP to `POST /internal/notifications`
with the trigger's own service key. Nothing imports
`services.notifications_db` from another service, as section 7 requires.

Delivery is durable. A business change commits with its queued work in one
transaction; if Logs or Notifications is down the change still succeeds and
the work waits. Retries use the same UUID, so a repeat is recognised rather
than duplicated, with exponential backoff capped at 300 seconds.

---

## Postman

`postman/` holds three collections and one environment. Import all four,
select **SIRMS v1 Local**, then paste a real token from Natalio's Users
service into `admin_token` / `analyst_token`.

The committed environment has **every secret blank**, per section 9. Never
commit a filled-in copy.

---

## Documentation

```bash
cd docs
make html        # output in docs/build/html/index.html
```

Generated from Sphinx-style docstrings with autodoc, viewcode and napoleon
on the Read the Docs theme.

---

## Design decisions worth explaining in the report

**Transactional outbox for everything owed to another service.** A mutation
and its audit event commit together, or neither does. Delivery happens
later in the worker. This is why a Logs outage cannot lose a security event
and cannot fail a legitimate incident update.

**Fail closed on identity.** If Users cannot be reached the request gets
`503`, never access. An outage is not permission.

**Display names were removed.** Sprint I returned `reporter_name`,
`assigned_analyst_name` and `affected_asset_name` from SQL joins onto
`users` and `assets`. Section 3 forbids querying another owner's tables, so
the joins are gone. Natalio's `GET /internal/users/{id}` exposes no name
field, so they cannot be restored over HTTP either. Reports never consumed
them.

**Roles are canonical snake_case; severities and statuses stay Title Case.**
Section 4.2 fixes the role strings; section 5 requires the enum spellings to
stay as they are and has Chris normalise them inside Reports.

**Timestamps are `TIMESTAMPTZ`, written as aware UTC.** The serializer
refuses a naive datetime rather than guessing its zone.

**Parameterised queries only.** The sole strings formatted into SQL are
column names checked against a fixed whitelist in `update_vulnerability`,
and table names that are literals in this codebase.

---

## What is NOT demonstrated

The 144 checks replace Natalio's and Chris's services with test doubles in
`tests/upstream_double.py`. They prove my services behave correctly against
the v1 contracts. **They do not prove live team integration** — no real
endpoint of theirs has been called. Section 9's assembly gates remain
outstanding and need all nine services running together.

See `INTEGRATION_STATUS.md` for current state and remaining dependencies.
