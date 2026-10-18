# Sprint I service requirements (Chris Gharfine)

This is a focused implementation checklist for Chris Gharfine's Asset Management,
Threat Intelligence, and Security Reports services. It summarizes the attached
professor-provided Sprint I specification; it is not a copy of the assignment.
The attachment remains the requirements authority. The user approved the baseline
in [implementation-plan.md](implementation-plan.md), and Chris's services have
been implemented. External team contracts remain pending as recorded in
[integration-contracts.md](integration-contracts.md).

## Repository and ownership

- Repository: `ChrisGharfine/ChrisGharfine-NatalioHassoun-KarimHajjAli-435L`.
- Development branch: `feature/chris` only.
- Chris owns Services 2, 4, and 6 and their models, migrations, tests,
  documentation, and Postman requests.
- Natalio owns Users, Audit Logging, and Playbooks. Karim owns Incidents,
  Vulnerabilities, and Notifications.
- Preserve other students' implementations. Do not merge into or push to
  `main` or `integration/sprint1`.

## Access control (Chris Gharfine)

Every protected request must authenticate its caller and check the operation's
permissions. Permission violations and data modifications must generate audit
events. Inactive and suspended accounts must not be allowed to authenticate.
Use the team's shared identity system; these services must not issue their own
user tokens or provide an independent login system.

| Service operation | Security Administrator | Security Analyst | Regular Employee/User | Auditor |
| --- | --- | --- | --- | --- |
| Create, update, delete assets | Allow | Deny | Deny | Deny |
| List all assets | Allow | Deny | Deny | Allow |
| Retrieve a specific asset, search assets | Allow | Allow | Deny | Allow |
| Create, update, delete threats | Allow | Deny | Deny | Deny |
| List threats, retrieve a specific threat | Allow | Allow | Deny | Allow |
| Search threats | Allow | Allow | Deny | Unresolved: conflicting assignment lists |
| Generate any of the six reports | Allow | Deny | Deny | Allow |

The general role description mentions analysts viewing related assets, but the
service-specific endpoint permissions do not define a relationship-scoping
algorithm. Record this integration question instead of inventing incident
ownership behavior. Analysts have no report access unless explicitly authorized;
no such exception has been approved here.

## Asset Management requirements (Chris Gharfine)

Each persisted asset needs an identifier, name, type, IP address, operating system
when applicable, department, owner, location, criticality, and status. Creation
explicitly requires name, type, IP address, department, owner, and criticality.
Clarify defaults or optionality for the remaining fields in the API contract.

- Criticality labels: Low, Medium, High, Critical.
- Status labels: Active, Inactive, Under Maintenance.
- The assignment gives servers, workstations, databases, applications, network
  devices, and cloud resources as examples; it does not prescribe a closed type
  enumeration or its wire spelling.
- Validate required and nonempty input, asset types, IP formats, criticality,
  and status. Reject unknown or unsafe input consistently.
- Each asset has one owner; one user can own multiple assets. The proposed
  database design explicitly requires an owner foreign key to Users.
- Maintain department information and relationships to incidents and
  vulnerabilities. One asset can have many of each. Do not implement or duplicate
  Karim's incident or vulnerability storage.

| Method | Prescribed path | Required behavior |
| --- | --- | --- |
| POST | `/assets` | Create an authorized, validated asset and persist it. |
| PUT | `/assets/{id}` | Update name, owner, department, criticality, and status. |
| DELETE | `/assets/{id}` | Remove an asset only for an authorized administrator. |
| GET | `/assets` | Return all assets with details, criticality, and current status. |
| GET | `/assets/{id}` | Return an existing asset; handle invalid and absent identifiers. |
| GET | `/assets/search` | Search by name, type, IP, department, and criticality. |

Required verification includes several created assets, database persistence,
before/after updates, permitted and forbidden deletion, list and detail results,
invalid IDs, and multiple search combinations. Define safe deletion behavior for
referenced assets with Karim; do not silently cascade into other services' data.

## Threat Intelligence requirements (Chris Gharfine)

Each persisted threat needs an identifier, type, value, description, severity,
source, and date added. Creation requires type, value, description, severity, and
source. The creation timestamp is system-generated.

- Supported type labels: IP Address, Domain, File Hash, Malware Signature, and
  Other indicators. Agree on serialized values with the team.
- Severity labels: Low, Medium, High, Critical.
- Validate IP indicators as IPs, domain indicators as domains, and file hash
  indicators against the approved supported hash formats.
- Prevent duplicate `(threat type, threat value)` pairs, including simultaneous
  requests, using a database uniqueness constraint. Document normalization.
- Validate required fields, type, and severity on creation and updates.

| Method | Prescribed path | Required behavior |
| --- | --- | --- |
| POST | `/threats` | Create a validated, nonduplicate threat indicator. |
| GET | `/threats` | List records including severity, source, and date added. |
| GET | `/threats/{id}` | Retrieve a threat; handle missing and invalid identifiers. |
| GET | `/threats/search` | Search by type, value, severity, and source. |
| PUT | `/threats/{id}` | Update description, severity, and source. |
| DELETE | `/threats/{id}` | Delete only for an authorized administrator. |

Required verification includes multiple indicator types and severities, persisted
records, duplicate rejection, invalid formats, list/detail/missing results,
different searches, before/after updates, and authorized/unauthorized deletion.

## Security Reports requirements (Chris Gharfine)

Reports must aggregate actual service data over HTTP using approved contracts.
They must not contain hardcoded final counts or a copy of another service's
business database. The assignment names Users, Assets, Incidents, Threats, and
Audit as report sources and additionally prescribes a Vulnerabilities report.
Vulnerabilities therefore also needs an integration contract.

| Method | Prescribed path | Required content |
| --- | --- | --- |
| GET | `/reports/summary` | Current overview. The example contains `users`, `assets`, `open_incidents`, and `critical_threats`. Derive all values from source data. |
| GET | `/reports/incidents` | Total incidents; distributions by severity and status. |
| GET | `/reports/assets` | Total assets, critical assets, and counts by asset type. |
| GET | `/reports/threats` | Total threats; counts by severity and type; recently added threats. |
| GET | `/reports/vulnerabilities` | Total vulnerabilities; counts by severity and status; critical vulnerabilities. |
| GET | `/reports/activity` | Total user activities, login attempts, failed login attempts, and most performed actions. |

The broader report description also mentions total users/assets/incidents/threats,
incident severity distributions, and recent security activities. Confirm the
placement of recent activity details and the meaning of "recent" in the contract.

Define open-incident semantics, recent-result limits/order, audit login action
names, response envelopes, and pagination before integration. Test nonzero and
empty datasets, invalid upstream data, access restrictions, and unavailable
services. Isolated HTTP test doubles are permitted for automated contract tests;
their output does not count as execution evidence from the integrated system.

## Cross-cutting acceptance criteria (Chris Gharfine)

- Use object-oriented service/repository boundaries and REST APIs.
- Persist assets and threats with primary keys, required foreign keys, and
  appropriate constraints. Supply migrations and explain relationships.
- Validate and sanitize input; use parameterized database operations.
- Reject missing credentials, invalid tokens, forbidden operations, missing
  resources, invalid input, and uniqueness conflicts with meaningful errors.
- Keep errors consistent across services. The assignment illustrates a JSON
  object containing `status: "error"` and a human-readable `message`.
- Document parameters, request/response shapes, status codes, validation,
  authorization, database behavior, and inter-service interactions.
- Export a Postman collection covering all 18 prescribed endpoints and include
  negative requests and descriptions.
- Execute tests before claiming they pass. Record actual commands/results and
  clearly distinguish test doubles from live integration.
- Capture real Postman and database evidence, with captions containing
  "Chris Gharfine", the API title, and what the call demonstrates.
- Explain contributions in the common report and retain meaningful Git history.
- The assignment requires disclosure of AI assistance and students' ability to
  explain their implementation. It also disallows submission of complete
  AI-generated solutions; the student must resolve how their use of assistance
  fits the course rules before submission.

## Assignment ambiguities and conflicts

1. A general note requires every API route to include the full implementing
   student's name, while every prescribed endpoint omits it. Chris's instruction
   explicitly says to preserve the prescribed paths pending clarification.
2. The general Auditor permission list allows threat search, whereas Service 4's
   Auditor list includes only list and detail. Obtain clarification; the proposed
   initial policy follows the narrower service-specific list.
3. Independent services communicating over HTTP are required alongside explicit
   database foreign keys between their entities. The team must approve the
   database topology and migration ownership; a separate database per service
   cannot enforce those foreign keys directly.
4. The submission naming example ends in `430L`, whereas the supplied repository
   ends in `435L`. Do not rename the repository without clarification.
