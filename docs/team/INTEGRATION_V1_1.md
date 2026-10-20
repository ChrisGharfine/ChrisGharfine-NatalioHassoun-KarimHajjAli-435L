# Team integration v1.1 — coordinated amendment

Date: 20 October 2026. Applies to Natalio Hassoun (1/5/9), Chris Gharfine
(2/4/6), and Karim Hajj Ali (3/7/8). Read this amendment with the existing
TEAM_INTEGRATION_V1.md baseline. This file supersedes its route examples and
error-envelope omissions; the assignment takes precedence over both.

## Routes and service addresses

Every public/internal API, health endpoint, and Chris documentation endpoint
includes its owner's full name, as the assignment requires.

| Service | Port | Complete base URL |
|---|---:|---|
| Users | 8001 | http://127.0.0.1:8001/api/natalio-hassoun |
| Assets | 8002 | http://127.0.0.1:8002/api/chris-gharfine |
| Incidents | 8003 | http://127.0.0.1:8003/api/karim-hajj-ali |
| Threats | 8004 | http://127.0.0.1:8004/api/chris-gharfine |
| Logs | 8005 | http://127.0.0.1:8005/api/natalio-hassoun |
| Reports | 8006 | http://127.0.0.1:8006/api/chris-gharfine |
| Vulnerabilities | 8007 | http://127.0.0.1:8007/api/karim-hajj-ali |
| Notifications | 8008 | http://127.0.0.1:8008/api/karim-hajj-ali |
| Playbooks | 8009 | http://127.0.0.1:8009/api/natalio-hassoun |

Append the existing resource path once: for example
`http://127.0.0.1:8002/api/chris-gharfine/internal/assets/12`.
Chris's `CHRIS_*_URL` and Karim's `KARIM_*_URL` values are complete base URLs
including the destination owner's prefix. Natalio's `USERS_URL` and `LOGS_URL`
remain origins only, because his client appends `API_PREFIX` internally.
Unprefixed old Chris/Karim routes are no longer served. Reimport the current
Postman templates and update saved clients. Configurable prefixes must retain
the owner's slug. `CHRIS_API_PREFIX` / `KARIM_API_PREFIX` control local routes.

## Authentication and common errors

Users issues 30-minute HS256 access JWTs with string positive integer `sub`,
numeric `iat`/`exp`, `type=access`, issuer `security-sprint1-users`, audience
`security-sprint1-services`. Other services verify these locally, then call
Users' authenticated `/internal/identity/verify` on every protected request.
The live account status and role override stale JWT role claims. Users validates
locally to avoid recursion. Identity transport/protocol failures return 503.

Only canonical roles cross the identity boundary: `security_administrator`,
`security_analyst`, `regular_employee`, `auditor`. User/asset references use
the authenticated internal HTTP APIs, not another owner's table queries.
All services share one coordinated database/schema; foreign keys still enforce
relationships. Database ownership does not authorize cross-owner writes.

Errors contain `status="error"`, a machine-readable `code`, and a safe
`message`. Extra details may be present; business success envelopes and enum
spellings are unchanged. Invalid request input returns 400 (including Chris's
Pydantic validation, formerly 422). 401/403/404/409/500/503 retain their usual
authentication/permission/missing/conflict/internal/unavailable meanings.
Chris retains 502 for malformed upstream responses. Codes can be more specific
than a generic HTTP label. Do not parse human messages as integration logic.

## Durable events and receipts

Notification mark-read now atomically stores `notification_marked_read` with
the data change, actor ID, `Information`, and `related_service=notifications`.
Repeating an already-read request preserves its read date and creates no extra
mutation event. Role/ownership denials generate `unauthorized_access`; audit
storage failure is surfaced rather than silently losing the event.

Audit and notification receivers persist idempotency receipts. Send one stable
UUID in `Idempotency-Key` for the lifetime of an outbox event. Delivery requires
200/201, success envelope, matching UUID, boolean `duplicate`, and the proper
positive resource ID. New receipts use 201/false; retries use 200/true. An
explicit null resource is valid only on a duplicate receipt after deletion.
Incomplete acknowledgements remain pending. Never replay the business mutation
to repair delivery or silently replace its UUID/payload.

## Shared packaging and ownership

Root `.env.example`, `.gitignore`, README, runtime manifests, `tools/team/*`,
and `docs/team/*` are deliberately identical across the three branches.
Python 3.12 supports all nine services. Root requirements install the complete
team runtime; owner manifests allow smaller installations. Secrets remain in
ignored local dotenv files. Separate native Postman exports are ignored because
they can contain live tokens. No schema is reset by this update. Apply existing
owned migrations in order: Natalio, Chris, Karim. Existing migration files with
stored checksums are not edited.

This contract fixes the identified compatibility issues. It is not an instructor
approval or a claim of exhaustive assignment compliance. Each student must
understand the code, resolve assignment ambiguities with the instructor, and
disclose AI assistance accurately.
