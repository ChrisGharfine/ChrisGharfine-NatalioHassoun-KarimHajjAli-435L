# Real evidence checklist (Natalio Hassoun)

These are capture instructions, not claims that screenshots already exist.
Use your own running implementation/database and Postman. Show request method,
route, input, HTTP status and response. Mask bearer tokens, passwords and service
keys. Add a caption to every image:

`Natalio Hassoun — [API call title] — [what this actual execution demonstrates].`

## Users

- Registration request/response and inserted database row. Show the stored hash
  with appropriate masking, not the submitted password. Explain username uniqueness.
- Duplicate username rejected; invalid email; weak password; missing fields.
- Successful login and incorrect credentials; explain hash verification/JWT.
- Inactive and suspended accounts rejected.
- Profile update with before/after database values.
- Employee own-profile success versus another profile forbidden.
- Administrator deletion success versus employee deletion denied. Explain soft deletion.
- List users and explain the returned array/fields.
- Existing/nonexistent username and explanation of the responses.
- Role change and account suspension applied to an already-issued token.
- Attempted public administrator registration and role-field injection rejected.

## Logs

- Generate several actual events: login success/failure, user creation/deletion,
  role change, profile/playbook modification, unauthorized access.
- Show log database records and explain which event generated each.
- List logs, retrieve an existing ID, retrieve an invalid ID.
- Search separately by user, UTC date, action, severity and related service.
- Retrieve logs for two different users and a user/no-match with no logs.
- Administrator deletion versus analyst deletion denied.
- Attempted PUT receives 405; explain the database immutable-update trigger.
- Internal ingestion with service credentials and an identical retry producing
  one log. Do not expose the credentials in the screenshot.
- Temporarily stop Logging: business response shows pending audit; show its
  persisted outbox row, restart Logging, run flush-audit and show exactly one log.

## Playbooks

- Create multiple playbooks with different categories/severities; show DB rows
  and explain organization by category/severity.
- List playbooks; retrieve an existing ID and invalid ID.
- Add multiple actions out of numeric order; retrieve them sorted by step_number.
- Invalid/duplicate steps rejected; show stored actions and their playbook FKs.
- Analyst adds/updates actions; auditor/employee mutation denied.
- Assign an active user; reject invalid/deleted/inactive user references.
- Pending → In Progress → Completed, with completion_date.
- Reopen and explain retained historical snapshots/cleared current completion_date.
- Retrieve full playbook showing action history.
- Administrator deletion versus analyst deletion denied; explain retained history.

## Architecture/database/security/Git

- Architecture diagram: three services plus teammate API connections, shared
  schema ownership, identity lookup and audit delivery.
- Schema diagram, table structures, primary/foreign keys, enums and sample data.
- Same protected operation allowed for one role and forbidden for another.
- Missing/invalid/expired token and identity-service outage fail closed.
- GitHub repository link and YOUR actual commit/contribution history after you
  review, commit and push. No contribution screenshots are generated here.

Embed the real screenshots into the common report. Add your full name in
parentheses beside each owned section/title. Include Postman JSON files. Code
screenshots alone do not prove functionality. Automated test output complements
these requirements; it does not replace the required Postman execution evidence.
