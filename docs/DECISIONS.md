# Assignment interpretation and design decisions (Natalio Hassoun)

The complete uploaded `Final Project Fall 2026-2027-Sprint 1 (1).docx` was read
before implementation. No repository lab instructions were present; only the
initial README existed at commit `c8ed5dabca7b9366f1abbf8b9711f881ef8af000`.

1. **Course identifier:** the repository is named `...-435L`; the assignment's
   example says `...-430L`. Repository naming is preserved. Confirm the final
   submission name with the instructor.
2. **AI use:** the document prohibits copying complete AI-generated solutions and
   requires disclosure of AI assistance. This implementation is an assisted
   working draft for Natalio to understand, inspect, adapt and test. It does not
   itself establish authorship, permitted use, or submission compliance.
3. **Role/status APIs:** user role management is required in the general role
   description but lacks explicit routes. `PUT /users/{id}/role` and
   `PUT /users/{id}/status` are supporting additions. Setting role to
   `regular_employee` removes a privileged assignment; users have one role.
4. **Public registration:** the Role field is required as in the document, but
   public/employee registration accepts only `regular_employee`. Administrators
   can register any defined role. Auditors/analysts with a supplied token cannot
   register accounts. This prevents self-assigned administrator privileges.
5. **Analyst log search:** the Service 5 permission table explicitly allows it,
   while the endpoint prose names only administrators/auditors. The table wins.
6. **Analyst response actions:** the Service 9 permission table explicitly permits
   adding actions, while endpoint prose mentions administrators. The table wins.
7. **User deletion:** DELETE hides the account and sets it inactive, retaining
   the row and identity fields for historical foreign keys. Deleted accounts
   cannot log in or use existing tokens. Usernames/emails remain reserved.
   This is soft deletion, not physical erasure; clarify if the instructor expects
   physical deletion. No cross-service records are cascaded away.
8. **Playbook deletion:** similarly hides the playbook and blocks later action
   updates, retaining actions and their history. Audit log DELETE physically
   removes the selected log, as permitted for administrators; a separate
   idempotency receipt prevents retries from recreating it.
9. **Action workflow:** the assignment gives three statuses but no transition
   sequence. All transitions among Pending, In Progress and Completed are
   allowed. Completion defaults to server UTC time; an explicit zoned timestamp
   cannot be in the future. Reopening clears completion_date and retains previous
   snapshots. Ordered steps use distinct positive integers; gaps are allowed and
   execution is not forced to be sequential. These are documented choices.
10. **User assignment:** response actions may reference any active, non-deleted
    user, since the assignment does not restrict assignment to analysts. Only
    administrators/analysts can perform the relevant API operations.
11. **Audit availability:** Users/Playbooks commit business changes together with
    a local outbox event. Delivery then happens over HTTP. Responses explicitly
    include `audit_delivery` as delivered or pending. The mutation can succeed
    while delivery is pending; do not blindly repeat a successful mutation.
    `flush-audit` retries durable events. IDs are stable across delivery retries.
    There is no background scheduler: run retries explicitly after an outage.
12. **Event timing:** logs use the Logging Service's UTC creation timestamp.
    Outbox rows retain the earlier occurrence/queue time; delayed delivery can
    therefore produce a later log timestamp. This is documented rather than
    presented as synchronous delivery.
13. **Manual versus automatic logs:** manual POST /logs uses the authenticated
    administrator's actor ID. Trusted internal clients can supply known actors
    or null for unidentified attempts. This trust is bounded by individual service
    keys. Callers must not include credentials in descriptions; a pattern check
    catches obvious mistakes but cannot detect every possible secret.
14. **Database:** PostgreSQL with one coordinated schema and separate table
    ownership is a project choice. Shared FKs enforce integrity; application
    service boundaries use HTTP. A shared database owner can bypass API roles,
    so production isolation would require additional database grants.
15. **Internal routes:** service-authenticated identity and reference APIs and
    ingestion support integration; they do not grant analysts public user access.
16. **Bootstrap and self-management:** the setup command creates the initial
    administrator. An administrator cannot delete, demote or disable their own
    account; use another administrator for those changes. This prevents accidental
    lockout and is an additional policy, not an explicit assignment rule.

Unfinished team work: six teammate services, team architecture/schema integration,
common report assembly, CREATES attendance/feedback, real Postman/database
screenshots, GitHub contribution history, and three individual Moodle uploads.

The DOCX contains no exact final date. The announcement supplied in this chat
extends Sprint I to October 20, 11:59 PM, with no further extension. CREATES is
required at least three days before the final deadline; the announcement does
not clarify whether its timing was changed.
