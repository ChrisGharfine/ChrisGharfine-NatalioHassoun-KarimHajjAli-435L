"""Explicit setup commands; no schema changes occur during server startup."""

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import select, text
from werkzeug.security import generate_password_hash

from .app import create_app
from .models import User
from .shared import validation as v
from .shared.audit import drain_outbox, record_event
from .shared.constants import ADMIN


def migrate(app):
    sql = (Path(__file__).resolve().parent.parent / "database" / "001_student1.sql").read_text(encoding="utf-8")
    with app.extensions["engine"].begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(4351001)"))
        connection.exec_driver_sql(sql)
    print("Student 1 migration applied (repeatable; existing records retained).")


def create_admin(app):
    required = ("ADMIN_FULL_NAME", "ADMIN_USERNAME", "ADMIN_EMAIL", "ADMIN_PASSWORD", "ADMIN_DEPARTMENT")
    if any(not os.getenv(key) or "CHANGE_ME" in os.environ[key] for key in required):
        raise ValueError("Set all ADMIN_* environment variables with real setup values.")
    name, username, email, password, department = (os.environ[key] for key in required)
    with app.extensions["session_factory"]() as session:
        existing = session.scalar(select(User).where(User.username == v.username(username)))
        if existing:
            if existing.role != ADMIN or existing.deleted_at or existing.account_status != "active":
                raise ValueError("The setup username exists but is not an active administrator; no changes made.")
            print("Administrator already exists; credentials were not overwritten.")
            return
        user = User(full_name=v.text(name, "full_name"), username=v.username(username), email=v.email(email),
                    password_hash=generate_password_hash(v.password(password), method="scrypt"),
                    department=v.text(department, "department"), role=ADMIN, account_status="active")
        session.add(user)
        session.flush()
        record_event(session, "user_created", f"Bootstrap created administrator {user.id}.", user.id)
        session.commit()
        print(f"Created administrator ID {user.id}. Password not displayed.")
    print(f"Pending audit events: {drain_outbox()}")


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("run")
    serve.add_argument("service", choices=("users", "logs", "playbooks"))
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int)
    commands.add_parser("migrate")
    commands.add_parser("create-admin")
    flush = commands.add_parser("flush-audit")
    flush.add_argument("service", choices=("users", "playbooks"))
    args = parser.parse_args()
    service = getattr(args, "service", "users")
    app = create_app(service)
    with app.app_context():
        if args.command == "migrate":
            migrate(app)
        elif args.command == "create-admin":
            create_admin(app)
        elif args.command == "flush-audit":
            pending = drain_outbox()
            print(f"Pending audit events: {pending}")
            if pending:
                raise SystemExit(1)
        else:
            app.run(host=args.host, port=args.port or {"users": 8001, "logs": 8005, "playbooks": 8009}[service],
                    debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
