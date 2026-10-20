# Verification and report evidence

Use evidence to show what actually happened and which requirement it supports.
A request template, code excerpt or diagram documents a design; it is not proof
that a request ran successfully.

## Recorded software checks

The [verification record](VERIFICATION_V1_1.md) explains the 20 October run and
links its original sanitized records:

| Artifact | What it supports | Limit |
|---|---|---|
| [Live results](evidence/live-results.json) | 128 checks with nine real HTTP services, owned migrations, reports, role changes, notifications and outage recovery | Disposable generated schema and credentials; not every existing dataset |
| [Initial source reconciliation](evidence/initial-checker.txt) and [final reconciliation](evidence/final-checker.txt) | All six Reports outputs compared with actual sources before/after the scenario | Requires a stable dataset; not proof of every mutation or permission rule |
| [Assembly results](evidence/assembly-results.json) | Common files matched when the pre-merge personal working trees were assembled | Records that stage; it does not say the later team merge did not happen |
| [Merged main verification](evidence/final-main-verification.json) | The three published personal tips were contained in merged main and its tree matched the tested combination | Identifies a specific checked main commit, not all future commits |

The combined pytest run reported 520 passes and 79 subtests. Owner counts overlap
that run; do not sum them. Karim's separate 144-check owner scenario used explicit
Users/Assets/Logs doubles. It checks Karim's behavior with controlled peers but
does not establish live teammate integration. Use the separate nine-service run
for that claim. These records are dated execution results, not a continuous
integration badge or a claim that new changes were automatically tested.

## Postman screenshots

Capture the selected request title, method, owner-prefixed URL, required input,
actual response JSON, HTTP status and relevant passing assertions. For ownership
denials show a token variable such as `{{employee_token}}`, without revealing its
value. Use actual demonstration records, not fixed IDs copied from another run.

Caption every figure with the student's full name, API call title and a sentence
explaining what it demonstrates. For example:

> Karim Hajj Ali — Assign Incident — PUT assigns the demonstrated incident to
> an active analyst and returns 200; the corresponding inbox figure demonstrates
> the later automatic assignment notification.

| Evidence group | Required distinction |
|---|---|
| Users, Logs, Playbooks — Natalio Hassoun | Six core operations per service, profile ownership, valid/invalid login, validation, role denials, ordered actions, completion/history and deletion retention |
| Assets, Threats, Reports — Chris Gharfine | Six operations per service, indicator and owner validation, permissions, report totals reconciled with source records |
| Incidents, Vulnerabilities, Notifications — Karim Hajj Ali | Six operations per service, valid/invalid IDs and input, workflow transitions, role/recipient restrictions, read state, search and deletion |
| Automatic integration | Incident assignment alert; High/Critical vulnerability owner alert; durable audit delivery and duplicate-safe receipts |
| Database | Table structure, primary/foreign keys and actual persisted rows after the demonstrated changes |
| Collaboration | Repository and GitHub history with meaningful commits/authors, service responsibilities and applied CREATES feedback |

One clear screenshot may support several related assertions, but four health/login
images cannot substitute for CRUD, validation and authorization evidence. Include
before/after states where the assignment requires them. For an expected 400, 401,
403 or 409 response, a passing negative assertion demonstrates correct rejection;
the red HTTP status alone does not mean the test failed.

## Current versus historical material

The current collections are templates under `postman/`. Saved material under
`postman/historical/pre-v1.1/` predates the prefixed route correction. Label it
historical and retake any image whose URL, behavior or fields changed. A screenshot
from a separate run may use different IDs and totals; do not combine it into a
single claimed transaction sequence without explaining that difference.

Retain original screenshots outside Git while selecting report figures. Do not
fabricate or alter returned results. Hide private values before capture and omit
images that expose passwords, JWTs or service keys from public report material.
The report can use diagrams for architecture and schema explanation, with real
request and database captures as separate execution evidence.

## Common report completion

Use the assignment's eleven sections: title page, contents with responsible
members, introduction, architecture, implementation, database design, error
handling/validation, API documentation, authentication, GitHub collaboration,
and references. Include each contributor's full name beside their section titles
and in figure captions. Embed the three owners' actual evidence and disclose AI
assistance accurately; [references](REFERENCES.md) gives the assistance scope.

Report completeness is separate from the software checks. Add missing teammates'
screenshots and GitHub proof before describing the common report as ready for
submission. The team reported attending CREATES; explain the concrete changes
listed in [the feedback record](CREATES_FEEDBACK.md) without inventing a session
date, score or approval.
