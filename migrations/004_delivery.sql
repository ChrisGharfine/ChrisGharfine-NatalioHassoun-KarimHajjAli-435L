-- Karim Hajj Ali -- owned migration 004
-- Durable delivery: audit outbox, notification outbox, notification receipts.
--
-- Sections 6 and 7 require that a business mutation and the work it owes to
-- another service commit in the same transaction, survive a restart, and
-- never be delivered twice under the same UUID.

-- Outbound audit events, destined for POST {LOGS}/internal/logs.
CREATE TABLE IF NOT EXISTS karim_audit_outbox (
    event_id        UUID        PRIMARY KEY,
    source_service  TEXT        NOT NULL,
    user_id         INTEGER         NULL,
    action          TEXT        NOT NULL
        CONSTRAINT karim_audit_outbox_action_format
        CHECK (action ~ '^[a-z][a-z0-9_]*$' AND char_length(action) <= 100),
    description     TEXT        NOT NULL
        CONSTRAINT karim_audit_outbox_description_length
        CHECK (char_length(description) BETWEEN 1 AND 2000),
    severity        TEXT        NOT NULL
        CONSTRAINT karim_audit_outbox_severity
        CHECK (severity IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts        INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ     NULL,
    permanent_error BOOLEAN     NOT NULL DEFAULT FALSE,
    last_error      TEXT            NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_pending
    ON karim_audit_outbox (next_attempt_at)
    WHERE delivered_at IS NULL AND permanent_error = FALSE;

-- Outbound notification work, destined for
-- POST {NOTIFICATIONS}/internal/notifications. Used by Incidents and
-- Vulnerabilities so they never import the Notifications code directly.
CREATE TABLE IF NOT EXISTS karim_notification_outbox (
    event_id          UUID        PRIMARY KEY,
    source_service    TEXT        NOT NULL,
    recipient_user_id INTEGER     NOT NULL,
    actor_user_id     INTEGER         NULL,
    title             TEXT        NOT NULL,
    message           TEXT        NOT NULL,
    notification_type TEXT        NOT NULL,
    severity_level    TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts          INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at      TIMESTAMPTZ     NULL,
    permanent_error   BOOLEAN     NOT NULL DEFAULT FALSE,
    last_error        TEXT            NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_outbox_pending
    ON karim_notification_outbox (next_attempt_at)
    WHERE delivered_at IS NULL AND permanent_error = FALSE;

-- Inbound idempotency receipts for POST /internal/notifications.
-- The receipt outlives the notification: deleting a notification must not
-- let an identical retry recreate it.
CREATE TABLE IF NOT EXISTS karim_notification_receipts (
    event_id        UUID        PRIMARY KEY,
    source_service  TEXT        NOT NULL,
    payload_digest  TEXT        NOT NULL,
    notification_id BIGINT          NULL
        REFERENCES notifications(notification_id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_receipts_notification
    ON karim_notification_receipts (notification_id);
