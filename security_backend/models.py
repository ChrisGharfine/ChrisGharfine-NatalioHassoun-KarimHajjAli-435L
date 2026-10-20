"""Student 1 tables only; services write only their own tables.

Users are retained as tombstones when deleted so historical foreign keys remain valid.
Audit outboxes belong to their originating service, not to the Logging Service.
"""

from sqlalchemy import (Boolean, CheckConstraint, DateTime, ForeignKey, Integer,
                        JSON, String, Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .shared.validation import iso, utcnow


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    department: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(40), default="regular_employee")
    account_status: Mapped[str] = mapped_column(String(16), default="active")
    created_date: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_date: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("role IN ('security_administrator','security_analyst','regular_employee','auditor')"),
        CheckConstraint("account_status IN ('active','inactive','suspended')"),
    )

    def public(self):
        return {"id": self.id, "full_name": self.full_name, "username": self.username,
                "email": self.email, "department": self.department, "role": self.role,
                "account_status": self.account_status, "created_date": iso(self.created_date),
                "last_login_date": iso(self.last_login_date)}


class Log(Base):
    __tablename__ = "logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    description: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    related_service: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True)
    source_service: Mapped[str] = mapped_column(String(64))
    __table_args__ = (CheckConstraint("severity IN ('Information','Warning','Error','Critical')"),)

    def public(self):
        return {"id": self.id, "user_id": self.user_id, "action": self.action,
                "description": self.description, "timestamp": iso(self.timestamp),
                "severity": self.severity, "related_service": self.related_service,
                "event_id": self.event_id, "source_service": self.source_service}


class LogReceipt(Base):
    """Idempotency survives deletion of a log, preventing retry resurrection."""
    __tablename__ = "log_receipts"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_service: Mapped[str] = mapped_column(String(64))
    payload_hash: Mapped[str] = mapped_column(String(64))
    log_id: Mapped[int | None] = mapped_column(ForeignKey("logs.id", ondelete="SET NULL"))


class Playbook(Base):
    __tablename__ = "playbooks"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    incident_category: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    creation_date: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)
    deleted_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (CheckConstraint("severity IN ('Low','Medium','High','Critical')"),)

    def public(self):
        return {"id": self.id, "name": self.name, "description": self.description,
                "incident_category": self.incident_category, "severity": self.severity,
                "created_by": self.created_by, "creation_date": iso(self.creation_date)}


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id", ondelete="RESTRICT"), index=True)
    description: Mapped[str] = mapped_column(Text)
    step_number: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="Pending")
    assigned_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    completion_date: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1)
    __mapper_args__ = {"version_id_col": version}
    __table_args__ = (
        UniqueConstraint("playbook_id", "step_number"), CheckConstraint("step_number > 0"),
        CheckConstraint("status IN ('Pending','In Progress','Completed')"),
        CheckConstraint("(status = 'Completed' AND completion_date IS NOT NULL) OR (status <> 'Completed' AND completion_date IS NULL)"),
    )

    def public(self):
        return {"id": self.id, "playbook_id": self.playbook_id, "description": self.description,
                "step_number": self.step_number, "status": self.status,
                "assigned_user_id": self.assigned_user_id, "completion_date": iso(self.completion_date)}


class ActionHistory(Base):
    __tablename__ = "response_action_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    action_id: Mapped[int] = mapped_column(ForeignKey("response_actions.id", ondelete="RESTRICT"), index=True)
    changed_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    previous: Mapped[dict | None] = mapped_column(JSON)
    current: Mapped[dict] = mapped_column(JSON)
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)

    def public(self):
        return {"id": self.id, "action_id": self.action_id, "changed_by": self.changed_by,
                "previous": self.previous, "current": self.current, "timestamp": iso(self.timestamp)}


class OutboxMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(120))
    next_attempt_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    delivery_blocked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


class UsersOutbox(OutboxMixin, Base):
    __tablename__ = "users_audit_outbox"


class PlaybooksOutbox(OutboxMixin, Base):
    __tablename__ = "playbooks_audit_outbox"
