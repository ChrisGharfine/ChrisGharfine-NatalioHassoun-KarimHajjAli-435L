# team-integration-v1.0.0 — where this stands

Karim Hajj Ali, services 3 / 7 / 8. Updated 19 October 2026.

All seven owner tasks in section 8 are implemented. Everything below marked
**verified** was executed on this machine, not merely written.

**Nothing here demonstrates live team integration.** Natalio's and Chris's
real services were never contacted. Section 8 is explicit that "fixture
responses are never real execution evidence."

---

## Owner task list (section 8)

| # | Task | State |
|---|---|---|
| 1 | SQLite → PostgreSQL, owned migrations only, FKs retargeted, RESTRICT | done, verified |
| 2 | JWT + current identity over HTTP, Users/Assets reference APIs | done, verified |
| 3 | Envelopes + Title Case enums kept, complete lists, zoned UTC | done, verified |
| 4 | Durable audit outbox replacing direct log writes | done, verified |
| 5 | Internal Notifications API, receipts, durable delivery | done, verified |
| 6 | Three independently addressable services | done, verified |
| 7 | Tests, Postman, documentation, run instructions | done, verified |

---

## Verified by execution

| Check | Result |
|---|---|
| PostgreSQL 17.11, migrations `001`–`004` | 0 outstanding |
| FK targets `users(id)` / `assets(id)` | confirmed in `information_schema` |
| `ON DELETE RESTRICT` on both asset references | confirmed |
| `ON DELETE CASCADE` notes → incident | confirmed |
| All timestamp columns `timestamptz` | confirmed |
| Three services on 8003 / 8007 / 8008 | confirmed |
| `/health` and `/ready` query own tables | confirmed |
| **Integration test suite** | **144 passed, 0 failed** |
| Sphinx docs, warnings as errors (`-W`) | build succeeded |
| Postman: 22 requests, 22 real captured responses | confirmed |
| Secret scan of committed Postman files | no tokens, no keys |

### What the 144 checks cover

- **Auth:** no/malformed/expired token, wrong issuer, wrong audience,
  missing `type`, missing `sub`, wrong token type, `alg=none`, wrong
  signing key, suspended account, deleted account, insufficient role,
  Users outage → `503` fail closed, recovery.
- **Incidents:** creation by admin and employee, employee forced as own
  reporter, validation, unknown asset, list envelope and `count`,
  ownership rules, assignment to non-analyst / suspended / unknown,
  full lifecycle, illegal skip, closed-state refusal, notes.
- **Vulnerabilities:** three severities, CVE format, CVSS range, missing
  and unknown asset, role rules, update, five-state lifecycle, six search
  cases, delete permissions.
- **Notifications:** internal endpoint credentials, UUID validation,
  caller/type pairs, unknown and unavailable recipients, first delivery,
  identical retry (`duplicate=true`), changed payload
  (`409 IDEMPOTENCY_CONFLICT`), retry after deletion returning
  `notification: null`, no duplicate creation audit event, all six public
  endpoints and their ownership rules.
- **Audit delivery:** all ten transport action codes received, regex and
  severity conformance, no body-level `timestamp`, outbox drained,
  business change succeeds during a Logs outage, event stays pending,
  recovery delivers exactly once, no UUID delivered twice.

---

## Remaining dependency — this is the blocker

**Natalio has not pushed the section 4.1 JWT wiring.**

Checked on 19 October 2026:

- `origin/natalio/student1` tip is `cb2728c`, dated 18 October 23:56 —
  byte-identical to the commit section 1 records as his *starting* state.
- A search of his entire branch for `issuer`, `audience` or
  `security-sprint1` returns **nothing**.

Section 4.1 requires him to add `JWT_ENCODE_ISSUER`, `JWT_DECODE_ISSUER`,
`JWT_ENCODE_AUDIENCE` and `JWT_DECODE_AUDIENCE`.

**Consequence:** my services require `iss` and `aud` as mandatory claims,
exactly as specified. Tokens from his current Users service lack them, so
every protected request returns `401`. Chris implemented the same
requirement, so his services will behave identically. Nothing assembles
until this lands.

**Chris is ahead.** `origin/feature/chris` tip `2ad8c9a`, two commits past
the `f80e0a0` recorded in section 1, and contains `/internal/assets/{id}`,
identity verification, `CHRIS_JWT_ISSUER`, `login_success`, and
`tools/chris/check_team_integration.py`.

---

## Decisions that need the team's attention

**1. Display names removed from responses.** `reporter_name`,
`assigned_analyst_name` and `affected_asset_name` came from SQL joins onto
`users` and `assets`, which section 3 forbids. Natalio's
`GET /internal/users/{id}` exposes no name field, so they cannot be
restored over HTTP. Section 5 never consumed them.

**2. `assets.owner_id` treated as nullable.** Section 3 says it references
`users.id ON DELETE RESTRICT` but does not say it is mandatory. My
Vulnerability service handles an asset with no owner to notify. If Chris
makes it `NOT NULL`, nothing of mine breaks.

**3. A development bootstrap exists.**
`devtools/bootstrap_dev_dependencies.py` creates minimal `users`/`assets`
stand-ins so the suite can run without the teammates' services. It refuses
to run without `KARIM_ALLOW_DEV_BOOTSTRAP=yes`, is never called by a
migration or at startup, and is not part of the integrated setup.

**4. Sprint I files removed.** `auth.py`, `audit.py`, `database.py`,
`app.py`, `seed.py`, `test_services.py`, `schema.sql` and the SQLite
`database.db` are gone, superseded by `security/`, `outbox/`, `db.py`,
`app_factory.py`, `apps/`, `migrate.py` and `migrations/`.

**5. Analyst access to `GET /incidents`.** The assignment's role section
says an analyst can "view assigned incidents", but the Service 3
authorization list does not grant it. I enforce the per-service list.
Pair this with Chris's auditor threat-search question for the professor.

---

## Commands

```bash
set -a; . ./.env.local; set +a
python migrate.py                       # apply owned migrations
python migrate.py --status              # inspect, change nothing
python apps/incidents_app.py            # :8003
python apps/vulnerabilities_app.py      # :8007
python apps/notifications_app.py        # :8008
python worker.py --flush                # drain both outboxes
python worker.py --status               # queue depths
python tests/test_integration_v1.py     # 144 checks
cd docs && make html                    # documentation
```

Postgres container: `docker start sirms-pg` / `docker stop sirms-pg`.

---

## Git

Branch **`karim`**, remote
`ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L`.

**Nothing has been committed by me.** All v1 work is uncommitted in the
working tree. `.env.local` holds development values and is gitignored —
confirm it is untracked before committing. Committing, branching and
pushing remain yours.
