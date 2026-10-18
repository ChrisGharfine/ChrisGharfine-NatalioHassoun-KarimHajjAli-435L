from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Identity, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from services.chris_support.database import Base, utcnow


class Threat(Base):
    __tablename__ = "threats"
    __table_args__ = (
        UniqueConstraint("threat_type", "threat_value", name="uq_threats_type_value"),
        CheckConstraint("threat_type IN ('ip_address','domain','file_hash',"
                        "'malware_signature','other')", name="valid_type"),
        CheckConstraint("severity IN ('low','medium','high','critical')", name="valid_severity"),
        CheckConstraint("length(trim(threat_value)) > 0", name="value_not_blank"),
        CheckConstraint("length(trim(description)) > 0", name="description_not_blank"),
        CheckConstraint("length(trim(source)) > 0", name="source_not_blank"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    threat_type: Mapped[str] = mapped_column(String(30), index=True)
    threat_value: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(String(5000))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    source: Mapped[str] = mapped_column(String(200), index=True)
    date_added: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
