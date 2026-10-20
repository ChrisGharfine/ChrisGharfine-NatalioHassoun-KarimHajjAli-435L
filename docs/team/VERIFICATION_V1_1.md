# Executed integration verification — 20 October 2026

The v1.1 repair was first tested on three uncommitted personal working trees
based on the commits below. This table identifies the original execution
baseline, not the current personal-branch tips:

| Branch | Baseline commit |
|---|---|
| natalio/student1 | caa2de2831590d07149faedd2b63321e0f570b5f |
| feature/chris | 2ad8c9a2c92e5bc8d30fa9d9945dff112a7894bb |
| karim | 0661c950d626fe634f8d30c23f716bf1e517808c |

At that execution stage, the assistant had not committed, pushed or merged the
changes. The team subsequently committed and merged them. Main commit
`6ed5e48e5b062404ca52a2d97f36e92e998c4283` contains Natalio `eb434b0`, Chris
`519e722` and Karim `84439d8`; its source tree matched the tested combination.
See [current status](../../INTEGRATION_STATUS.md) for the complete hashes.
The dated JSON files retain the original execution provenance and are not
rewritten to imply that those tests started after merging.

## Actual results

| Check | Executed result | Scope |
|---|---|---|
| Public file assembly, without a Git merge | 520 passed, 0 failed; 79 subtests passed | Combined pytest suites and config-helper tests |
| Natalio owner suite | 85 passed | Three real HTTP services/PostgreSQL plus explicitly labeled unit fault injection |
| Chris owner suite | 425 passed; 30 subtests passed | PostgreSQL, actual Chris HTTP and explicit upstream doubles/unit tests |
| Karim owner scenario | 144 passed, 0 failed | Three real Karim HTTP services/PostgreSQL; Users/Assets/Logs are explicit doubles |
| Karim new security regressions | 7 passed | Unit fault injection, strict JWT/receipts, safe JSON and denial behavior |
| Shared private-config helper | 3 passed | Generated temporary fixtures; no real credentials |
| Packaged full live verifier | 128 passed, 0 failed | Nine actual processes; no teammate doubles |
| Reports source reconciliation | All six reports, twice | Live sources and real Reports before/after workflow changes |
| Dependencies | Clean install and pip check passed | Python 3.12.14; shared pinned requirements and optional Sphinx tools |
| Karim Sphinx | Build succeeded with warnings treated as errors | `python -m sphinx -W -b html docs/source docs/build/html` |
| Public file scan | No matching local credentials or literal JWTs found | Literal comparison with local secret values and token-pattern scan; not a comprehensive security audit |
| Common file assembly | No differing overlapping paths | Shared files have identical contents in all three roots |

Counts overlap: 520 includes the owner pytest cases and new unit/helper tests.
Do not add overlapping totals and describe them as unique test coverage.
The only pytest warning was the installed Starlette TestClient deprecation of
httpx; it did not fail any checks. This patch does not replace the HTTP testing
stack solely to suppress that third-party warning.

## Real live scenario

The committed `tools/team/verify_live.py` was executed from Natalio's root with
the other two roots supplied explicitly and one shared Python runtime. It used
generated secrets and dynamic loopback ports, with one generated schema inside
the dedicated local `security_incidents_test` database. That schema was removed
on completion. Development data, existing private configuration, and native
Postman workspaces were preserved.

It applied each owner's migrations twice, bootstrapped a real Users administrator,
created all four roles, and used Users-issued access tokens throughout. It
created an asset, threat, incident, vulnerability, playbook and assigned action
through actual APIs. Both automatic notification triggers delivered exactly as
expected. Workers delivered audit records, and source/report totals reconciled.

It confirmed restrictive asset foreign keys (409), employee/analyst denials,
suspension affecting the same token across owners, and real Logs/Notifications
outages followed by process restart and durable recovery without duplicate UUIDs.
Mark-read queued exactly one mutation audit; a repeat created no duplicate.
Notification ownership denial was audited. It checked common errors, missing
internal actors, malformed JSON input, and removal of old unprefixed routes.

Sanitized execution records: [live results](evidence/live-results.json),
[first reconciliation](evidence/initial-checker.txt),
[final reconciliation](evidence/final-checker.txt), and
[assembly checks](evidence/assembly-results.json).
These files record execution, not fabricated Postman responses. Current changed
Postman collections are templates; historical responses remain clearly labeled.

## What still belongs to the team

Update private service addresses/keys consistently, apply the
owned migrations to the backed-up shared installation, and restart all services
with the v1.1 prefixes. The live tests used disposable data, not a production
upgrade or all possible pre-existing datasets. No automatic SQLite importer was
added. Instructor clarification is still needed where assignment prose and
permission tables disagree. These checks do not establish exhaustive assignment
compliance, instructor approval or a full security assessment.

Each student must understand and demonstrate their code and accurately disclose
AI assistance. Suggested disclosure: “AI assistance was used to review integration
contracts, propose and implement compatibility fixes, and support test/documentation
preparation. We reviewed the resulting code and verified the stated execution
results.” Edit this to reflect the review and work actually performed by you.
