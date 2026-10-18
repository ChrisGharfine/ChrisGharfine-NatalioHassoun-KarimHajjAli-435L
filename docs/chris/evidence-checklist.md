# Execution evidence checklist (Chris Gharfine)

This checklist is preparation for real execution after implementation. No items
below are claimed as executed or passed. Capture screenshots from your own
running system and compare responses with its actual persisted records. Test
doubles, invented responses, and screenshots of code are not execution evidence.

Use captions of the form: **Chris Gharfine - API title - behavior demonstrated**.
Hide passwords, bearer tokens, signing keys, and other credentials in screenshots.
Record the execution date, branch/commit, request inputs, response/status, and
corresponding database state. Keep evidence out of the repository unless its
contents have been reviewed for secrets and personal data.

## Assets (Chris Gharfine)

- [ ] `POST /assets`: create multiple assets with differing types/criticalities;
      capture request/response and actual rows, including owner foreign keys.
- [ ] `PUT /assets/{id}`: capture before/after state and persisted updates.
- [ ] `DELETE /assets/{id}`: demonstrate administrator success and another role's
      denial; verify database state and the audit event. Test a referenced asset.
- [ ] `GET /assets`: show several rows and their criticality/status; demonstrate
      that analysts and regular users cannot list all assets.
- [ ] `GET /assets/{id}`: show an existing record, nonexistent ID, invalid ID,
      and role enforcement.
- [ ] `GET /assets/search`: show name, type, IP, department, and criticality
      searches, combined filters, and no results.
- [ ] Demonstrate required-field, invalid-IP, invalid-type, invalid-criticality,
      invalid-status, and nonexistent-owner rejection without unwanted inserts.
- [ ] Show primary/foreign keys and prevention of orphaned references.

## Threats (Chris Gharfine)

- [ ] `POST /threats`: create several indicator types/severities and show rows.
- [ ] Demonstrate duplicate type/value rejection and its database constraint.
- [ ] Reject invalid IP/domain/hash values and invalid types/severities.
- [ ] `GET /threats`: show records with source, severity, and date added.
- [ ] `GET /threats/{id}`: demonstrate existing, absent, and invalid IDs.
- [ ] `GET /threats/search`: show type/value/severity/source filters and no results.
- [ ] `PUT /threats/{id}`: show before/after description, severity, and source,
      including persisted values and invalid update rejection.
- [ ] `DELETE /threats/{id}`: show authorized deletion and unauthorized prevention.
- [ ] Show the final clarified auditor search policy and actual audit records for
      mutations and denied operations.

## Reports (Chris Gharfine)

- [ ] Populate the real source services using their implemented APIs. Coordinate
      Users/Audit data with Natalio and Incidents/Vulnerabilities data with Karim.
- [ ] `GET /reports/summary`: reconcile every count with source data.
- [ ] `GET /reports/incidents`: reconcile total, severity, and status groups.
- [ ] `GET /reports/assets`: reconcile total, critical assets, and type groups.
- [ ] `GET /reports/threats`: reconcile total, severity/type groups, and recent
      additions and their ordering.
- [ ] `GET /reports/vulnerabilities`: reconcile total, severity/status groups,
      and critical count with Karim's actual records.
- [ ] `GET /reports/activity`: reconcile total activities, login attempts,
      failed logins, and most performed actions with Natalio's actual logs.
- [ ] Demonstrate administrator and auditor success, analyst/regular-user denial,
      and missing/invalid/expired authentication rejection.
- [ ] Demonstrate valid empty datasets and an unavailable source. Ensure an outage
      does not appear as a successful report with zero totals.
- [ ] Demonstrate invalid upstream-data handling using clearly labeled automated
      contract tests; do not present synthetic upstream data as live team evidence.

## Submission preparation (Chris Gharfine)

- [ ] Export the final Postman collection with all 18 endpoint descriptions,
      request bodies/parameters, successful requests, and negative scenarios.
- [ ] Use configured local Postman variables for credentials; do not export secrets.
- [ ] Capture actual database schema/constraints and representative stored rows.
- [ ] Include responsibilities, architecture and database diagrams, API details,
      relationships, validation, errors, authorization, and testing instructions
      in the common team report, marking Chris's contributions with his full name.
- [ ] Capture actual GitHub commits and contributions for `feature/chris`.
- [ ] Disclose where and why AI assistance was used and check compliance with the
      assignment's restriction on submitting complete AI-generated solutions.
- [ ] Practice explaining the implementation and its test results independently.
- [ ] Resolve the full-name route requirement, auditor threat-search discrepancy,
      and submission naming discrepancy with the professor/team.
- [ ] Identify live integration checks still pending. Do not claim the other six
      services, the full project, or unexecuted tests are complete.
