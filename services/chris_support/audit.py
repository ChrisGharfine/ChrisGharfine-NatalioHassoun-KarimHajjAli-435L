from datetime import datetime
from uuid import uuid4

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, String, Text
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


def enqueue(session: Session, *, user_id: int | None, action: str,
            service: str, description: str, severity: str = "information") -> None:
    session.add(AuditOutbox(
        user_id=user_id, action=action, related_service=service,
        description=description, severity=severity,
    ))
