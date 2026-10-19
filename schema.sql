-- Security Incident Detection and Response Management System
-- Database schema (all 10 tables)
--
-- The full schema lives in one file so that foreign keys resolve no matter
-- which services are running. Tables are created in dependency order:
-- users and assets first, then everything that points at them.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- Service 1
CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name       TEXT NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    department      TEXT,
    role            TEXT NOT NULL,
    account_status  TEXT NOT NULL DEFAULT 'Active',
    created_date    TEXT NOT NULL,
    last_login_date TEXT
);

-- ---------------------------------------------------------------- Service 2
CREATE TABLE IF NOT EXISTS assets (
    asset_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name        TEXT NOT NULL,
    asset_type        TEXT NOT NULL,
    ip_address        TEXT,
    operating_system  TEXT,
    owner_id          INTEGER REFERENCES users(user_id),
    department        TEXT,
    location          TEXT,
    criticality_level TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'Active'
);

-- ------------------------------------------------- Service 3 (Karim Hajj Ali)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL,
    reporter_id         INTEGER NOT NULL REFERENCES users(user_id),
    asset_id            INTEGER REFERENCES assets(asset_id),
    assigned_analyst_id INTEGER REFERENCES users(user_id),
    status              TEXT NOT NULL DEFAULT 'Open',
    creation_date       TEXT NOT NULL,
    resolution_date     TEXT
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    analyst_id         INTEGER NOT NULL REFERENCES users(user_id),
    note_content       TEXT NOT NULL,
    creation_timestamp TEXT NOT NULL
);

-- ---------------------------------------------------------------- Service 4
CREATE TABLE IF NOT EXISTS threats (
    threat_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type    TEXT NOT NULL,
    threat_value   TEXT NOT NULL,
    description    TEXT,
    severity_level TEXT NOT NULL,
    source         TEXT,
    date_added     TEXT NOT NULL,
    UNIQUE (threat_type, threat_value)
);

-- ---------------------------------------------------------------- Service 5
CREATE TABLE IF NOT EXISTS logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(user_id),
    action_performed TEXT NOT NULL,
    description     TEXT,
    timestamp       TEXT NOT NULL,
    severity_level  TEXT NOT NULL,
    related_service TEXT NOT NULL
);

-- ------------------------------------------------- Service 7 (Karim Hajj Ali)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    cve_identifier   TEXT,
    cvss_score       REAL,
    severity_level   TEXT NOT NULL,
    asset_id         INTEGER NOT NULL REFERENCES assets(asset_id),
    discovery_source TEXT,
    status           TEXT NOT NULL DEFAULT 'Open',
    creation_date    TEXT NOT NULL,
    resolution_date  TEXT
);

-- ------------------------------------------------- Service 8 (Karim Hajj Ali)
CREATE TABLE IF NOT EXISTS notifications (
    notification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(user_id),
    title             TEXT NOT NULL,
    message           TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    severity_level    TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'Unread',
    creation_date     TEXT NOT NULL,
    read_date         TEXT
);

-- ---------------------------------------------------------------- Service 9
CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_name    TEXT NOT NULL,
    description      TEXT,
    incident_category TEXT NOT NULL,
    severity_level   TEXT NOT NULL,
    created_by       INTEGER REFERENCES users(user_id),
    creation_date    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id        INTEGER NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    action_description TEXT NOT NULL,
    step_number        INTEGER NOT NULL,
    status             TEXT NOT NULL DEFAULT 'Pending',
    assigned_user_id   INTEGER REFERENCES users(user_id),
    completion_date    TEXT
);

-- Indexes on the columns my three services filter by most often.
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_analyst  ON incidents(assigned_analyst_id);
CREATE INDEX IF NOT EXISTS idx_notes_incident     ON investigation_notes(incident_id);
CREATE INDEX IF NOT EXISTS idx_vuln_asset         ON vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vuln_status        ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_notif_user         ON notifications(user_id);
