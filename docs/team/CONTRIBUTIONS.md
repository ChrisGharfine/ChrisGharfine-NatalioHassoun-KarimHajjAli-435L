# Contributors and division of work

The project assigns three distinct services to each student. Shared contracts,
configuration and integration evidence support the combined system; they do not
transfer ownership of another student's service.

| Student | Assigned services | Main source and database locations | Personal branch |
|---|---|---|---|
| Natalio Hassoun | 1 Users; 5 Logs; 9 Playbooks | `security_backend/`, `database/`, `scripts/`, `tests/test_integration.py`, `tests/test_team_v1.py` | `natalio/student1` |
| Chris Gharfine | 2 Assets; 4 Threat Intelligence; 6 Reports | `services/assets/`, `services/threats/`, `services/reports/`, `services/chris_support/`, `tests/chris/` | `feature/chris` |
| Karim Hajj Ali | 3 Incidents; 7 Vulnerabilities; 8 Notifications | `apps/`, `services/incidents_*`, `services/vulnerabilities_*`, `services/notifications_*`, `migrations/`, `security/`, `outbox/`, `worker.py` | `karim` |

Natalio owns account authentication/current identity, audit ingestion and ordered
playbook actions. Chris owns the asset inventory, threat indicator validation and
reports that read source APIs. Karim owns investigation workflows, vulnerability
tracking and recipient notifications, including the two automatic alert triggers.

The team coordinated JWT claims, route prefixes, identity/reference endpoints,
service-key registries, table migration order, durable deliveries and verification.
Shared setup lives in `docs/team/` and `tools/team/`; dependency manifests are
split by owner as well as combined for the team.

## Commit evidence

These representative commits are present in the merged history. The links show
actual files and authors. Commit counts do not measure effort, and authorship of
a commit does not establish who independently wrote every line.

| Student | Implementation commit | Integration commit |
|---|---|---|
| Natalio Hassoun | [cb2728c — Users, Logs and Playbooks](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/commit/cb2728c) | [eb434b0 — Integration v1.1](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/commit/eb434b0054270d6702e184d01648c2401071705d) |
| Chris Gharfine | [f405201 — Assets, Threats and Reports](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/commit/f405201) | [519e722 — Integration v1.1](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/commit/519e722aef952df0b776f439e14499077610774a) |
| Karim Hajj Ali | [9edcbec — PostgreSQL, JWT and HTTP integration](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/commit/9edcbec) | [84439d8 — Final commit before merge](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/commit/84439d8f0ea3d443bffe14669a31cfb397210eb1) |

The team merged through pull requests
[1](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/pull/1),
[2](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/pull/2)
and [3](https://github.com/ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L/pull/3).
The main commit inspected for this documentation was
`6ed5e48e5b062404ca52a2d97f36e92e998c4283`.

Inspect the history locally without changing files:

```powershell
git log --all --graph --decorate --oneline
git log --all --format="%h %an %ad %s" --date=short
git show --stat eb434b0
git show --stat 519e722
git show --stat 84439d8
```

For the common report, capture the GitHub history view with repository, branch,
author and meaningful commits visible. Caption it with full names and service
responsibilities. A local history export supports, but does not replace, a
requested GitHub screenshot.

## Review and assistance

The team reported completing CREATES and supplied its feedback sheet. The
[feedback record](CREATES_FEEDBACK.md) maps its criteria to documentation changes.
AI assistance contributed to review, integration implementation, verification and
documentation; the [disclosure](REFERENCES.md#ai-assistance) describes that scope.
Each student must understand and demonstrate their assigned services.
