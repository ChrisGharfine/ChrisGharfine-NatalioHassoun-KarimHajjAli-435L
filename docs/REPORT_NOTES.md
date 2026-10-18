# Implementation notes for the common report (Natalio Hassoun)

These notes describe the implementation. Review and rewrite them to reflect what
you understand, retain, modify and actually run. Add your real screenshots and
teammates' sections; this is not the full team final report.

## Architecture and responsibilities (Natalio Hassoun)

Student 1 owns Users, Security Audit Logging and Security Playbooks/Response
Automation. They are separate Flask processes, using PostgreSQL and SQLAlchemy.
Common helpers unify authentication, validation, errors and event delivery.
Other services verify current identity through Users and send security events to
Logging using authenticated HTTP requests. Their tables are not implemented here.

## Registration and login (Natalio Hassoun)

Registration validates a bounded set of fields and uses database uniqueness for
normalized usernames and emails. Public users can only register as regular
employees. Administrator authentication is required for privileged accounts.
Passwords use Werkzeug's salted scrypt hashes. Login accepts username or email,
verifies the hash, checks active/non-deleted status and issues a 30-minute JWT
with a string user-ID identity. Failed authentication gets a generic response.

## Authorization (Natalio Hassoun)

Each protected route verifies the token and its allowed roles. Users loads its
current identity locally; Logging/Playbooks check it through an internal Users
API with service credentials. This makes changes in role/status immediately
effective for existing tokens. Employee profile access also checks ownership.
If identity verification is unavailable, access fails closed with 503.

## Audit logging (Natalio Hassoun)

Users and Playbooks persist an audit event in their own database transaction
alongside a mutation. HTTP delivery follows commit. An unavailable Logging
Service produces an explicit pending-delivery response and leaves an event for
manual retry. Stable UUID event IDs and durable receipts prevent duplicate
ingestion and resurrection of legitimately deleted logs. Logging records its own
security events locally, avoiding recursive calls. Logs cannot be updated; only
administrators can delete them through the API.

## Playbooks and response actions (Natalio Hassoun)

Playbooks group response steps by incident category and severity. Distinct positive
step numbers define display order. Actions record assignment, current status and
completion time. Each creation/update stores immutable previous/current snapshots
with actor and UTC time. Deletion hides a playbook without erasing history.
The assignment does not dictate action transition ordering, so the supported
statuses can move in either direction with history preserved.

## Database and errors (Natalio Hassoun)

Integer keys and foreign keys connect users, logs, playbooks, actions and history.
Soft user deletion preserves historical references. Database constraints enforce
unique accounts, unique action steps and enum/field consistency. Log/history
immutability is reinforced by PostgreSQL triggers. Errors share a status/code/
message envelope and do not reveal internal SQL or credentials. Full details and
known policy interpretations are in API.md, DATABASE.md and DECISIONS.md.

## Validation and verification (Natalio Hassoun)

See VERIFICATION.md for actual automated results. Tests use three live HTTP
servers and a disposable schema in an isolated PostgreSQL test database. They
cover successful and unsuccessful operations, ownership, all four roles, token
revocation, immutable records, audit deduplication and service outages. Actual
Postman/database screenshots and full team integration remain separate evidence.

## AI-assistance disclosure — review for accuracy

AI assistance was used to draft and implement Student 1 service code, shared
helpers, schema scripts, automated tests, Postman requests and documentation, and
to execute local verification. Natalio Hassoun must review and understand the
implementation, document any changes and tests personally performed, and confirm
the course's allowed scope of AI use before submission. This package does not
claim that the assisted code was independently authored or demonstrated by the
student.

## Submission reminders

The common report needs title page, contents with responsible members,
introduction, architecture, implementation, database, error/validation, API docs,
authentication/authorization, GitHub evidence and references. Provide complete
team source/database scripts, Postman collection JSON, embedded real screenshots,
repository link and contribution history. Each student uploads the common team
submission separately. CREATES attendance/feedback is a separate graded obligation.
