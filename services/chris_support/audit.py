from datetime import datetime
import re
from uuid import uuid4

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column

from .database import Base, utcnow


class AuditOutbox(Base):
    __tablename__ = "chris_audit_outbox"
    __table_args__ = (
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        Index("ix_chris_outbox_pending", "delivered_at", "next_attempt_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    related_service: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(100))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Frozen before the first network attempt. Existing fields and UUIDs survive.
    transport_payload: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)


LEGACY_ACTIONS = {
    "assets.created": "asset_created", "assets.updated": "asset_updated",
    "assets.deleted": "asset_deleted", "threats.created": "threat_created",
    "threats.updated": "threat_updated", "threats.deleted": "threat_deleted",
    "authentication.denied": "unauthorized_access", "authorization.denied": "unauthorized_access",
}
SEVERITIES = {value.lower(): value for value in ("Information", "Warning", "Error", "Critical")}
OWNED_SERVICES = frozenset({"assets", "threats", "reports"})


def wire_payload(*, user_id, action, description, severity, service) -> dict:
    """Normalize only explicitly supported old values, then validate v1."""
    action = LEGACY_ACTIONS.get(action, action)
    severity = SEVERITIES.get(severity, severity)
    payload = {
        "user_id": user_id, "action": action, "description": description,
        "severity": severity, "related_service": service,
    }
    validate_payload(payload)
    return payload


def validate_payload(payload: dict) -> None:
    if not isinstance(payload, dict) or set(payload) != {
        "user_id", "action", "description", "severity", "related_service",
    }:
        raise ValueError("Invalid audit payload fields")
    actor = payload["user_id"]
    if actor is not None and (type(actor) is not int or not 1 <= actor <= 2_147_483_647):
        raise ValueError("Invalid audit actor")
    action = payload["action"]
    if not isinstance(action, str) or len(action) > 100 or not re.fullmatch(r"[a-z][a-z0-9_]*", action):
        raise ValueError("Invalid audit action")
    description = payload["description"]
    if not isinstance(description, str) or not description.strip() or len(description) > 2000:
        raise ValueError("Invalid audit description")
    if payload["severity"] not in SEVERITIES.values():
        raise ValueError("Invalid audit severity")
    if payload["related_service"] not in OWNED_SERVICES:
        raise ValueError("Invalid audit service")


def enqueue(session: Session, *, user_id: int | None, action: str,
            service: str, description: str, severity: str = "information") -> None:
    payload = wire_payload(user_id=user_id, action=action, description=description,
                           severity=severity, service=service)
    session.add(AuditOutbox(
        user_id=user_id, action=payload["action"], related_service=service,
        description=description, severity=payload["severity"], transport_payload=payload,
    ))
