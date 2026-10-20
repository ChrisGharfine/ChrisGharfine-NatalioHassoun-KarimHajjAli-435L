-- Additive team v1 retry metadata. Preserve IDs, payloads and existing receipts.
ALTER TABLE users_audit_outbox
  ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS delivery_blocked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE playbooks_audit_outbox
  ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS delivery_blocked BOOLEAN NOT NULL DEFAULT FALSE;
INSERT INTO student1_schema_versions(version) VALUES (2) ON CONFLICT DO NOTHING;
