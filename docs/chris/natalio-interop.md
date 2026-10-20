# Optional actual Chris–Natalio interoperability check

This check runs Chris's three services against Natalio's unchanged Users and
Logs source at commit cb2728cdfc52b9fc3bd314deccea0aea02c1f48d. All five use real
localhost HTTP and a newly generated PostgreSQL schema. It uses native Users
login tokens, native Users references and native Logs receipts, with no HTTP
fixtures or direct insertion of user/asset/threat business records.

The tool validates the source file set and contents against the Git commit;
only Windows CRLF/LF differences are normalized. It does not modify Natalio's
source, merge his branch or create a production configuration.

## Prepare an isolated runtime

Run from the repository root, on Chris's branch. The source commit must exist
locally; fetch origin if necessary. Do not overwrite a pre-existing snapshot.

```powershell
New-Item -ItemType Directory -Force .chris-runtime | Out-Null
git archive --format=zip --output=.chris-runtime/natalio-source.zip cb2728cdfc52b9fc3bd314deccea0aea02c1f48d security_backend database requirements-lock.txt
Expand-Archive -LiteralPath .chris-runtime/natalio-source.zip -DestinationPath .chris-runtime/natalio-cb2728c
.\.venv-chris\Scripts\python.exe -m venv .chris-runtime/interop-venv
.\.chris-runtime\interop-venv\Scripts\python.exe -m pip install -r tests/chris/requirements.txt -r .chris-runtime/natalio-cb2728c/requirements-lock.txt
```

This runtime is separate from Chris's application environment. No native Flask
dependencies are added to Chris's production requirements. Source snapshots,
archives and the temporary environment remain ignored by Git.

## Execute

With Docker running:

```powershell
.\tools\chris\run_tests.ps1 -Python .chris-runtime/interop-venv/Scripts/python.exe -NatalioSource .chris-runtime/natalio-cb2728c
```

The runner starts a generated disposable PostgreSQL 17 container/database and
supplies its credentials to the child process only. The Python check restricts
database names to chris_test*, creates one random chris_test_interop_ schema,
migrates Natalio first and Chris second, then starts five temporary HTTP servers.
Generated JWT/service secrets and bootstrap credentials stay in process memory;
raw bodies, tokens and passwords are not printed or saved as evidence.

The check removes only its generated schema, stops its servers, and the runner
stops its generated container. Existing databases and schemas are preserved.
Exit zero means this partial check passed; a failure is not a completed gate.

## Actual execution on 19 October 2026

The command above passed, verifying:

- Native then Chris migrations, all five actual HTTP services, and a genuine
  Users-issued HS256 token carrying the configured issuer/audience/type.
- User-reference validation, asset creation/reassignment and scoped internal
  Assets access; invalid keys and other registered callers were rejected.
- Assets and Threats reports matched the real source records.
- Chris's worker delivered to native Logs, accepted an identical retry,
  received the changed-payload conflict, and accepted a retained receipt after
  legitimate log deletion without recreating the log.
- The same user token changed permissions after real role updates, was rejected
  after suspension, worked after reactivation and was rejected after soft deletion.
  The referenced asset and historical owner ID remained stored.
- The Activity report matched actual Logs records, login_success/login_failed
  counts, action rankings and UTC recent activity ordering.

Native issuer/audience values were supplied through the factory's supported
runtime overrides before JWT initialization. This does not implement Natalio's
remaining required-claim enforcement or outbox receipt changes. His current
source is not declared fully v1-compliant by this run.

Karim's code was unavailable in the fetched branch. Summary, Incidents and
Vulnerabilities reports, Notifications, the complete nine-service workflow and
real-team outage acceptance remain pending. The all-nine-service checker is not
reported as passed. These automated actual HTTP checks do not replace required
Postman/database screenshots.
