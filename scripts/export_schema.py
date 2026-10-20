"""Regenerate the initial PostgreSQL SQL from models, plus immutable-record triggers."""

from pathlib import Path

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from security_backend.models import Base


def main():
    statements = ["-- Student 1 only (Natalio Hassoun). Non-destructive initial schema.\n"
                  "-- Run after backing up/coordinating an existing team schema.\n"]
    for table in Base.metadata.sorted_tables:
        statements.append(str(CreateTable(table, if_not_exists=True).compile(dialect=postgresql.dialect())) + ";")
        for index in sorted(table.indexes, key=lambda index: index.name):
            statements.append(str(CreateIndex(index, if_not_exists=True).compile(dialect=postgresql.dialect())) + ";")
    statements.append("""
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
""")
    destination = Path("database/001_student1.sql")
    destination.parent.mkdir(exist_ok=True)
    destination.write_text("\n".join(statements), encoding="utf-8")


if __name__ == "__main__":
    main()
