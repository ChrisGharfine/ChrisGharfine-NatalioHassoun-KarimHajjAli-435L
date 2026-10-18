-- Student 1 only (Natalio Hassoun). Non-destructive initial schema.
-- Run after backing up/coordinating an existing team schema.


CREATE TABLE IF NOT EXISTS playbooks_audit_outbox (
	id VARCHAR(36) NOT NULL, 
	payload JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	delivered_at TIMESTAMP WITH TIME ZONE, 
	attempts INTEGER NOT NULL, 
	last_error VARCHAR(120), 
	PRIMARY KEY (id)
)

;

CREATE TABLE IF NOT EXISTS users (
	id SERIAL NOT NULL, 
	full_name VARCHAR(255) NOT NULL, 
	username VARCHAR(64) NOT NULL, 
	email VARCHAR(254) NOT NULL, 
	password_hash TEXT NOT NULL, 
	department VARCHAR(255) NOT NULL, 
	role VARCHAR(40) NOT NULL, 
	account_status VARCHAR(16) NOT NULL, 
	created_date TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_login_date TIMESTAMP WITH TIME ZONE, 
	deleted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CHECK (role IN ('security_administrator','security_analyst','regular_employee','auditor')), 
	CHECK (account_status IN ('active','inactive','suspended')), 
	UNIQUE (username), 
	UNIQUE (email)
)

;

CREATE TABLE IF NOT EXISTS users_audit_outbox (
	id VARCHAR(36) NOT NULL, 
	payload JSON NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	delivered_at TIMESTAMP WITH TIME ZONE, 
	attempts INTEGER NOT NULL, 
	last_error VARCHAR(120), 
	PRIMARY KEY (id)
)

;

CREATE TABLE IF NOT EXISTS logs (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	action VARCHAR(100) NOT NULL, 
	description TEXT NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	related_service VARCHAR(64) NOT NULL, 
	event_id VARCHAR(36) NOT NULL, 
	source_service VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id), 
	CHECK (severity IN ('Information','Warning','Error','Critical')), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE RESTRICT, 
	UNIQUE (event_id)
)

;
CREATE INDEX IF NOT EXISTS ix_logs_action ON logs (action);
CREATE INDEX IF NOT EXISTS ix_logs_related_service ON logs (related_service);
CREATE INDEX IF NOT EXISTS ix_logs_severity ON logs (severity);
CREATE INDEX IF NOT EXISTS ix_logs_timestamp ON logs (timestamp);
CREATE INDEX IF NOT EXISTS ix_logs_user_id ON logs (user_id);

CREATE TABLE IF NOT EXISTS playbooks (
	id SERIAL NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	incident_category VARCHAR(100) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	created_by INTEGER NOT NULL, 
	creation_date TIMESTAMP WITH TIME ZONE NOT NULL, 
	deleted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CHECK (severity IN ('Low','Medium','High','Critical')), 
	FOREIGN KEY(created_by) REFERENCES users (id) ON DELETE RESTRICT
)

;

CREATE TABLE IF NOT EXISTS log_receipts (
	event_id VARCHAR(36) NOT NULL, 
	source_service VARCHAR(64) NOT NULL, 
	payload_hash VARCHAR(64) NOT NULL, 
	log_id INTEGER, 
	PRIMARY KEY (event_id), 
	FOREIGN KEY(log_id) REFERENCES logs (id) ON DELETE SET NULL
)

;

CREATE TABLE IF NOT EXISTS response_actions (
	id SERIAL NOT NULL, 
	playbook_id INTEGER NOT NULL, 
	description TEXT NOT NULL, 
	step_number INTEGER NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	assigned_user_id INTEGER, 
	completion_date TIMESTAMP WITH TIME ZONE, 
	version INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (playbook_id, step_number), 
	CHECK (step_number > 0), 
	CHECK (status IN ('Pending','In Progress','Completed')), 
	CHECK ((status = 'Completed' AND completion_date IS NOT NULL) OR (status <> 'Completed' AND completion_date IS NULL)), 
	FOREIGN KEY(playbook_id) REFERENCES playbooks (id) ON DELETE RESTRICT, 
	FOREIGN KEY(assigned_user_id) REFERENCES users (id) ON DELETE RESTRICT
)

;
CREATE INDEX IF NOT EXISTS ix_response_actions_playbook_id ON response_actions (playbook_id);

CREATE TABLE IF NOT EXISTS response_action_history (
	id SERIAL NOT NULL, 
	action_id INTEGER NOT NULL, 
	changed_by INTEGER NOT NULL, 
	previous JSON, 
	current JSON NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(action_id) REFERENCES response_actions (id) ON DELETE RESTRICT, 
	FOREIGN KEY(changed_by) REFERENCES users (id) ON DELETE RESTRICT
)

;
CREATE INDEX IF NOT EXISTS ix_response_action_history_action_id ON response_action_history (action_id);

CREATE OR REPLACE FUNCTION student1_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'This historical record is immutable';
END;
$$ LANGUAGE plpgsql;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'student1_logs_no_update' AND tgrelid = 'logs'::regclass) THEN
    CREATE TRIGGER student1_logs_no_update BEFORE UPDATE ON logs
      FOR EACH ROW EXECUTE FUNCTION student1_reject_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'student1_history_immutable' AND tgrelid = 'response_action_history'::regclass) THEN
    CREATE TRIGGER student1_history_immutable BEFORE UPDATE OR DELETE ON response_action_history
      FOR EACH ROW EXECUTE FUNCTION student1_reject_mutation();
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS student1_schema_versions (
  version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO student1_schema_versions(version) VALUES (1) ON CONFLICT DO NOTHING;
